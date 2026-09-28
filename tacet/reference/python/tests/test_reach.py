"""The reach record (PNX.md §4a): building it from a log, verifying it with and without the policy."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tacet.egress import EgressWitness, verify_pnx, verify_sheet
from tacet.keys import SigningKey
from tacet.reach import (
    DOMAIN_REACH,
    Policy,
    ReachLog,
    host_hash,
    rule_matches,
    summarize,
    verify_reach,
)
from tacet.hashing import sha256

SALT = bytes.fromhex("47dfe6cc13a8b4cbef0863bb1891a0a5")
POLICY = Policy.from_json({"version": "crovia.pnx.policy.v1",
                           "allow": ["api.github.com:443", "*.githubusercontent.com:443", "github.com"]})
T = "2026-09-28T05:1{}:00Z"


def attempts() -> list[tuple]:
    # (host, port, at, ip, bytes_out, bytes_in)
    return [
        ("api.github.com", 443, T.format(7), "140.82.112.5", 4000, 90000),
        ("API.github.com", 443, T.format(8), "140.82.112.6", 200, 100),
        ("objects.githubusercontent.com", 443, T.format(8), "185.199.108.133", 300, 700000),
        ("github.com", 22, T.format(9), "140.82.121.4", 1200, 8000),
        ("pastebin.com", 443, T.format(8), None, 500, 0),
        ("githubusercontent.com", 443, T.format(9), None, 10, 0),
        ("api.github.com", 443, T.format(9), "140.82.112.5", 100, 100),
    ]


def enforced() -> ReachLog:
    log = ReachLog(capture="proxy-connect", policy=POLICY, mode="enforce")
    for host, port, at, ip, out, inn in attempts():
        log.attempt(host, port, at, bytes_out=out, bytes_in=inn, ip=ip)
    return log


class TestPolicy:
    def test_rules(self) -> None:
        assert rule_matches("api.github.com:443", "API.GITHUB.COM", 443)
        assert not rule_matches("api.github.com:443", "api.github.com", 80)
        assert rule_matches("github.com", "github.com", 22)
        assert rule_matches("*.githubusercontent.com:443", "objects.githubusercontent.com", 443)
        assert rule_matches("*.githubusercontent.com:443", "a.b.githubusercontent.com", 443)
        assert not rule_matches("*.githubusercontent.com:443", "githubusercontent.com", 443)  # never the apex
        assert not rule_matches("*.githubusercontent.com:443", "evilgithubusercontent.com", 443)
        assert POLICY.has_wildcards()

    def test_hash_is_csc1_of_the_document(self) -> None:
        from tacet.canonical import canonicalize
        doc = {"allow": list(POLICY.allow), "version": "crovia.pnx.policy.v1"}
        assert POLICY.hash == "sha256:" + sha256(canonicalize(doc)).hex()
        assert POLICY.hash == Policy.from_json(json.loads(json.dumps(POLICY.to_json()))).hash

    def test_bad_documents(self) -> None:
        with pytest.raises(ValueError):
            Policy.from_json({"version": "x", "allow": []})
        with pytest.raises(ValueError):
            Policy.from_json({"version": "crovia.pnx.policy.v1", "allow": ["", "a"]})


class TestRecord:
    def test_enforced_record(self) -> None:
        rec = enforced().record(SALT)
        assert rec["version"] == "crovia.pnx.reach.v1"
        assert rec["policy"] == {"kind": "allowlist", "mode": "enforce", "hash": POLICY.hash, "rules": 3}
        hosts = [(d["host"], d["port"], d["outcome"]) for d in rec["destinations"]]
        assert hosts == [("api.github.com", 443, "allowed"), ("github.com", 22, "allowed"),
                         ("githubusercontent.com", 443, "blocked"), ("objects.githubusercontent.com", 443, "allowed"),
                         ("pastebin.com", 443, "blocked")]
        api = rec["destinations"][0]
        assert api["connections"] == 3 and api["bytes_out"] == 4300 and api["bytes_in"] == 90200
        assert api["ips"] == ["140.82.112.5", "140.82.112.6"]
        assert api["first_at"] == T.format(7) and api["last_at"] == T.format(9)
        blocked = rec["destinations"][4]
        assert blocked["bytes_out"] == 0 and blocked["bytes_in"] == 0 and blocked["ips"] == []
        assert rec["summary"] == {"destinations": 5, "connections": 7, "allowed": 3, "blocked": 2, "failed": 0}

    def test_observe_and_none(self) -> None:
        obs = ReachLog(policy=POLICY, mode="observe")
        for host, port, at, ip, out, inn in attempts():
            assert obs.attempt(host, port, at, ip=ip) == "allowed"
        rec = obs.record(SALT)
        assert rec["policy"]["mode"] == "observe" and rec["summary"]["blocked"] == 0
        none = ReachLog()
        assert none.mode == "observe"
        none.attempt("x.example", 443, T.format(0))
        rec = none.record(SALT)
        assert rec["policy"] == {"kind": "none", "mode": "observe", "hash": None, "rules": 0}
        with pytest.raises(ValueError):
            none.attempt("x.example", 443, T.format(0), "blocked")

    def test_explicit_outcomes_merge(self) -> None:
        log = ReachLog(policy=POLICY)
        log.attempt("api.github.com", 443, T.format(1), "failed")
        log.attempt("api.github.com", 443, T.format(2), "allowed", bytes_out=5)
        assert log.record(SALT)["destinations"][0]["outcome"] == "allowed"
        log.attempt("api.github.com", 443, T.format(3), "blocked")
        assert log.record(SALT)["destinations"][0]["outcome"] == "blocked"

    def test_salted(self) -> None:
        rec = enforced().record(SALT, "salted")
        assert all("host" not in d and len(d["host_hash"]) == 64 for d in rec["destinations"])
        assert [d["host_hash"] for d in rec["destinations"]] == sorted(d["host_hash"] for d in rec["destinations"])
        assert host_hash(SALT, "API.GITHUB.COM") == sha256(DOMAIN_REACH + SALT + b"api.github.com").hex()
        assert host_hash(SALT, "api.github.com") in {d["host_hash"] for d in rec["destinations"]}


class TestVerify:
    def test_with_policy(self) -> None:
        r = verify_reach(enforced().record(SALT), SALT, POLICY)
        assert r.ok and r.verdict == "within-policy" and r.outside == [] and not r.warnings

    def test_without_policy(self) -> None:
        r = verify_reach(enforced().record(SALT), SALT)
        assert r.ok and r.verdict == "within-policy" and any("rest on the witness" in w for w in r.warnings)
        obs = ReachLog(policy=POLICY, mode="observe")
        for host, port, at, *_ in attempts():
            obs.attempt(host, port, at)
        r = verify_reach(obs.record(SALT), SALT)
        assert r.ok and r.verdict == "unchecked"
        r = verify_reach(obs.record(SALT), SALT, POLICY)
        assert r.ok and r.verdict == "outside-policy"
        assert r.outside == ["githubusercontent.com:443", "pastebin.com:443"]

    def test_unpoliced(self) -> None:
        none = ReachLog()
        none.attempt("x.example", 443, T.format(0))
        r = verify_reach(none.record(SALT), SALT)
        assert r.ok and r.verdict == "unpoliced"
        r = verify_reach(none.record(SALT), SALT, POLICY)
        assert r.ok and r.verdict == "unpoliced" and r.warnings

    def test_salted_with_names(self) -> None:
        rec = enforced().record(SALT, "salted")
        r = verify_reach(rec, SALT, POLICY, names=["api.github.com", "evil.example"])
        assert r.ok and r.verdict == "within-policy"
        assert r.reached == {"api.github.com": True, "evil.example": False}
        assert any("wildcard" in w for w in r.warnings)

    def test_wrong_policy_document(self) -> None:
        other = Policy.from_json({"version": "crovia.pnx.policy.v1", "allow": ["api.github.com:443"]})
        r = verify_reach(enforced().record(SALT), SALT, other)
        assert not r.ok and "does not match" in r.errors[0]

    @pytest.mark.parametrize("mutate,reason", [
        (lambda r: r["destinations"].reverse(), "not sorted"),
        (lambda r: r["destinations"].append(copy.deepcopy(r["destinations"][-1])), "duplicate"),
        (lambda r: r["summary"].__setitem__("allowed", 9), "summary"),
        (lambda r: r.__setitem__("capture", "telepathy"), "unknown capture"),
        (lambda r: r["destinations"][0].__setitem__("outcome", "maybe"), "unknown outcome"),
        (lambda r: r["destinations"][0].__setitem__("host_hash", "00"), "not allowed under clear"),
        (lambda r: r["destinations"][0].__setitem__("host", "API.github.com"), "lower-cased"),
        (lambda r: r["destinations"][0].__setitem__("connections", 0), "at least 1"),
        (lambda r: r["destinations"][4].__setitem__("bytes_out", 1), "relayed on a blocked"),
        (lambda r: r["destinations"][0].__setitem__("ips", ["b", "a"]), "sorted list"),
        (lambda r: r["destinations"][0].__setitem__("first_at", "2027-01-01T00:00:00Z"), "ordered"),
        (lambda r: r["policy"].__setitem__("kind", "denylist"), "unknown policy kind"),
        (lambda r: r.__setitem__("version", "crovia.pnx.reach.v0"), "unknown reach version"),
    ])
    def test_invalid_records(self, mutate, reason) -> None:
        rec = enforced().record(SALT)
        mutate(rec)
        r = verify_reach(rec, SALT, POLICY)
        assert not r.ok and any(reason in e for e in r.errors), r.errors

    def test_blocked_but_allowed_is_inconsistent(self) -> None:
        rec = enforced().record(SALT)
        rec["destinations"][0]["outcome"] = "blocked"
        rec["destinations"][0]["bytes_out"] = rec["destinations"][0]["bytes_in"] = 0
        rec["summary"] = summarize(rec["destinations"])
        r = verify_reach(rec, SALT, POLICY)
        assert not r.ok and "inconsistent witness" in r.errors[0]
        assert verify_reach(rec, SALT).ok  # without the document nobody can tell

    def test_blocked_under_none_or_observe(self) -> None:
        rec = enforced().record(SALT)
        rec["policy"] = {"kind": "none", "mode": "observe", "hash": None, "rules": 0}
        r = verify_reach(rec, SALT)
        assert not r.ok and any("blocked without a policy" in e for e in r.errors)
        rec = enforced().record(SALT)
        rec["policy"]["mode"] = "observe"
        r = verify_reach(rec, SALT)
        assert not r.ok and any("observe mode" in e for e in r.errors)


class TestSheet:
    def test_sheet_carries_and_signs_the_record(self) -> None:
        key = SigningKey.generate("urn:crovia:pnx-witness:test")
        w = EgressWitness(run_id="r", salt=SALT, reach=enforced().record(SALT))
        w.ingest(b"x" * 100, T.format(0))
        sheet = w.sheet(key, T.format(9))
        assert sheet["reach"]["summary"]["blocked"] == 2
        assert verify_sheet(sheet) == []
        tampered = copy.deepcopy(sheet)
        tampered["reach"]["destinations"][4]["outcome"] = "allowed"
        tampered["reach"]["summary"] = summarize(tampered["reach"]["destinations"])
        assert "witness signature invalid" in verify_sheet(tampered)
        # structural faults are sheet faults
        broken = copy.deepcopy(sheet)
        broken["reach"]["summary"]["allowed"] = 0
        assert any(e.startswith("reach:") for e in verify_sheet(broken))
        # the proof carries the verdicts through
        proof = w.prove(sheet, [("a", b"y" * 60)])
        res = verify_pnx(proof, {"a": b"y" * 60}, policy=POLICY)
        assert res.ok and res.verdict == "absent" and res.reach is not None and res.reach.verdict == "within-policy"
        res = verify_pnx(proof, {"a": b"y" * 60})
        assert res.ok and res.reach.verdict == "within-policy" and any("rest on the witness" in x for x in res.warnings)
        # a sheet without the record: a policy is a warning, nothing more
        w2 = EgressWitness(run_id="r2", salt=SALT)
        w2.ingest(b"x" * 100, T.format(0))
        res = verify_pnx(w2.prove(w2.sheet(key, T.format(9)), [("a", b"y" * 60)]), {"a": b"y" * 60}, policy=POLICY)
        assert res.ok and res.reach is None and any("no reach record" in x for x in res.warnings)


class TestCli:
    def test_witness_and_verify(self, tmp_path: Path) -> None:
        env = {"PYTHONPATH": str(Path(__file__).resolve().parents[1])}
        pol = tmp_path / "policy.json"
        pol.write_text(json.dumps(POLICY.to_json()))
        log = tmp_path / "reach.jsonl"
        log.write_text("# reach log\n" + "\n".join(json.dumps({"at": at, "host": h, "port": p, "ip": ip, "bytes_out": o, "bytes_in": i})
                                                    for h, p, at, ip, o, i in attempts()) + "\n")
        body = tmp_path / "body.txt"
        body.write_text("hello " * 20)
        asset = tmp_path / "asset.txt"
        asset.write_text("s3cr3t " * 20)
        key, sheet, state, proof = (tmp_path / n for n in ("k.json", "sheet.json", "state.json", "proof.json"))

        def run(*args: str, ok: int = 0) -> subprocess.CompletedProcess:
            r = subprocess.run([sys.executable, "-m", "tacet.pnx_cli", *args], capture_output=True, text=True, env=env)
            assert r.returncode == ok, r.stdout + r.stderr
            return r

        run("keygen", "--id", "urn:test:w", "--out", str(key))
        r = run("witness", str(body), "--run-id", "run-1", "--key", str(key), "--sheet", str(sheet), "--state", str(state),
                "--reach", str(log), "--policy", str(pol), "--closed-at", T.format(9))
        assert "reach  5 destinations, 7 connections: 3 allowed, 2 blocked, 0 failed · policy allowlist enforce" in r.stderr
        s = json.loads(sheet.read_text())
        assert s["reach"]["policy"]["hash"] == POLICY.hash
        run("prove", "--state", str(state), "--sheet", str(sheet), "--asset", f"a={asset}", "--out", str(proof))
        r = run("verify", str(proof), "--asset", f"a={asset}", "--policy", str(pol), "--json")
        rep = json.loads(r.stdout)
        assert rep["ok"] and rep["verdict"] == "absent" and rep["reach"] == {"verdict": "within-policy", "outside": [], "reached": {}}
        r = run("verify", str(proof), "--asset", f"a={asset}")
        assert "reach  within-policy" in r.stdout and "rest on the witness" in r.stdout
        # observe mode: the same log, everything relayed; the verifier with the document sees the two outside
        sheet2, state2, proof2 = (tmp_path / n for n in ("sheet2.json", "state2.json", "proof2.json"))
        run("witness", str(body), "--run-id", "run-2", "--key", str(key), "--sheet", str(sheet2), "--state", str(state2),
            "--reach", str(log), "--policy", str(pol), "--reach-mode", "observe", "--reach-salted")
        run("prove", "--state", str(state2), "--sheet", str(sheet2), "--asset", f"a={asset}", "--out", str(proof2))
        r = run("verify", str(proof2), "--asset", f"a={asset}", "--policy", str(pol), "--name", "pastebin.com", "--name", "x.example")
        assert "reached  pastebin.com" in r.stdout and "absent   x.example" in r.stdout
        # clear + observe + document: outside-policy exits 1
        sheet3, state3, proof3 = (tmp_path / n for n in ("sheet3.json", "state3.json", "proof3.json"))
        run("witness", str(body), "--run-id", "run-3", "--key", str(key), "--sheet", str(sheet3), "--state", str(state3),
            "--reach", str(log), "--policy", str(pol), "--reach-mode", "observe")
        run("prove", "--state", str(state3), "--sheet", str(sheet3), "--asset", f"a={asset}", "--out", str(proof3))
        r = run("verify", str(proof3), "--asset", f"a={asset}", "--policy", str(pol), ok=1)
        assert "reach  outside-policy" in r.stdout and "outside  pastebin.com:443" in r.stdout
        # a wrong flag combination is refused
        run("witness", str(body), "--run-id", "run-4", "--key", str(key), "--sheet", str(sheet3), "--state", str(state3),
            "--policy", str(pol), ok=1)
