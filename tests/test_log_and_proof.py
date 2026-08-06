"""End-to-end tests: witness log lifecycle, proofs, tamper detection."""

import hashlib
import json

import pytest

from countersign.log import LogError, WitnessLog
from countersign.proof import ProofError, build_proof, verify_proof


def d(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@pytest.fixture()
def log(tmp_path):
    return WitnessLog.init(tmp_path / "log")


def test_init_creates_genesis_sth(log):
    sth = log.latest_sth()
    assert sth["tree_size"] == 0
    report = log.audit()
    assert report["ok"], report["problems"]


def test_init_refuses_to_reinit(log, tmp_path):
    with pytest.raises(LogError):
        WitnessLog.init(tmp_path / "log")


def test_witness_and_audit(log):
    for i in range(10):
        r = log.witness(d(f"evidence-{i}"), note=f"e{i}")
        assert r.index == i
        assert r.sth["tree_size"] == i + 1
    report = log.audit()
    assert report["ok"], report["problems"]
    assert report["tree_size"] == 10


def test_witness_rejects_bad_digest(log):
    with pytest.raises(LogError):
        log.witness("not-a-digest")
    with pytest.raises(LogError):
        log.witness("A" * 64)  # uppercase


def test_proof_roundtrip(log):
    for i in range(7):
        log.witness(d(f"evidence-{i}"))
    bundle = build_proof(log, d("evidence-3"))
    report = verify_proof(bundle)
    assert report["ok"], report["problems"]
    assert report["digest"] == d("evidence-3")


def test_proof_roundtrip_via_json_serialization(log):
    log.witness(d("only-one"))
    bundle = json.loads(json.dumps(build_proof(log, d("only-one"))))
    assert verify_proof(bundle)["ok"]


def test_proof_with_pinned_key(log):
    log.witness(d("x"))
    bundle = build_proof(log, d("x"))
    pub = log.key().public_hex
    assert verify_proof(bundle, expected_public_key=pub)["ok"]
    wrong = "0" * 64
    assert not verify_proof(bundle, expected_public_key=wrong)["ok"]


def test_proof_for_unknown_digest_fails(log):
    log.witness(d("known"))
    with pytest.raises(ProofError):
        build_proof(log, d("unknown"))


def test_duplicate_digest_uses_latest_unless_index_given(log):
    log.witness(d("dup"), note="first")
    log.witness(d("other"))
    log.witness(d("dup"), note="second")
    bundle = build_proof(log, d("dup"))
    assert bundle["entry"]["note"] == "second"
    bundle0 = build_proof(log, d("dup"), index=0)
    assert bundle0["entry"]["note"] == "first"
    assert verify_proof(bundle0)["ok"]


def test_tampered_entry_detected_by_audit(log):
    for i in range(5):
        log.witness(d(f"e{i}"))
    lines = log.entries_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["digest"] = d("swapped-in-later")
    lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    log.entries_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = log.audit()
    assert not report["ok"]
    assert any("root_hash" in p or "prefix" in p for p in report["problems"])


def test_tampered_proof_bundle_fails(log):
    for i in range(4):
        log.witness(d(f"e{i}"))
    bundle = build_proof(log, d("e2"))

    forged = json.loads(json.dumps(bundle))
    forged["entry"]["digest"] = d("something-else")
    assert not verify_proof(forged)["ok"]

    forged2 = json.loads(json.dumps(bundle))
    forged2["sth"]["timestamp"] = "1999-01-01T00:00:00Z"  # backdating attempt
    assert not verify_proof(forged2)["ok"]

    forged3 = json.loads(json.dumps(bundle))
    forged3["sth"]["tree_size"] = 3
    assert not verify_proof(forged3)["ok"]


def test_history_shrink_detected(log):
    log.witness(d("a"))
    log.witness(d("b"))
    # Simulate a rollback: truncate entries to 1 and re-seal.
    lines = log.entries_path.read_text(encoding="utf-8").splitlines()
    log.entries_path.write_text(lines[0] + "\n", encoding="utf-8")
    log._seal()
    report = log.audit()
    assert not report["ok"]
    assert any("shrank" in p or "prefix" in p for p in report["problems"])
