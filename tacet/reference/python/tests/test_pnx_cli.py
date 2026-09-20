import json
import os

import pytest

from tacet import pnx, pnx_cli
from tacet.egress import THRESHOLD

SECRET = b"sk-live-" + bytes(range(48, 48 + THRESHOLD))  # long enough for the guarantee
SHORT = b"short-token-abc"  # < K_GRAM: undetectable by construction


def _run(*argv):
    return pnx_cli.main([str(x) for x in argv])


@pytest.fixture
def ws(tmp_path):
    (tmp_path / "egress").mkdir()
    (tmp_path / "egress" / "req1.json").write_bytes(b'{"messages":[{"role":"user","content":"summarise the repo"}]}')
    (tmp_path / "egress" / "req2.txt").write_bytes(b"nothing to see here " * 20)
    log = tmp_path / "egress" / "gateway.jsonl"
    log.write_text(json.dumps({"at": "2026-09-20T10:00:00Z", "body": "hello world " * 10}) + "\n"
                   + json.dumps({"body_b64": "aGVsbG8gYWdhaW4="}) + "\n")
    (tmp_path / "protected").mkdir()
    (tmp_path / "protected" / "customers.csv").write_bytes(b"id,name,email\n" + b"".join(f"{i},user{i},user{i}@example.com\n".encode() for i in range(50)))
    (tmp_path / "secret.txt").write_bytes(SECRET)
    (tmp_path / "short.txt").write_bytes(SHORT)
    assert _run("keygen", "--id", "urn:test:witness", "--out", tmp_path / "w.key.json") == 0
    return tmp_path


def test_keygen_is_private_and_reloadable(ws):
    p = ws / "w.key.json"
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    key = pnx.load_key(p)
    assert key.id == "urn:test:witness" and len(key.public_hex) == 64


def test_witness_prove_verify_roundtrip_absent(ws, capsys):
    assert _run("witness", ws / "egress", "--run-id", "r1", "--key", ws / "w.key.json",
                "--sheet", ws / "r1.sheet.json", "--state", ws / "r1.state.json") == 0
    sheet = json.loads((ws / "r1.sheet.json").read_text())
    assert sheet["egress"]["bodies"] == 4 and sheet["profile"] == "crovia.pnx.v1"
    assert oct((ws / "r1.state.json").stat().st_mode & 0o777) == "0o600"

    assert _run("prove", "--state", ws / "r1.state.json", "--sheet", ws / "r1.sheet.json",
                "--asset", f"api_key={ws / 'secret.txt'}", "--assets-dir", ws / "protected",
                "--out", ws / "r1.proof.json", "--fail-on-present") == 0
    proof = json.loads((ws / "r1.proof.json").read_text())
    assert proof["verdict"] == "absent"
    assert {a["label"] for a in proof["assets"]} == {"api_key", "customers.csv"}

    # verifier recomputes fingerprints from the real assets
    assert _run("verify", ws / "r1.proof.json", "--asset", f"api_key={ws / 'secret.txt'}", "--assets-dir", ws / "protected", "--json") == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["ok"] and rep["verdict"] == "absent" and rep["warnings"] == []

    # without assets: still valid, but a warning, so --strict fails
    assert _run("verify", ws / "r1.proof.json") == 0
    assert _run("verify", ws / "r1.proof.json", "--strict") == 1


def test_present_is_detected_and_exit_codes(ws):
    (ws / "egress" / "leak.txt").write_bytes(b"prefix " + SECRET + b" suffix")
    assert _run("witness", ws / "egress", "--run-id", "r2", "--key", ws / "w.key.json",
                "--sheet", ws / "r2.sheet.json", "--state", ws / "r2.state.json") == 0
    assert _run("prove", "--state", ws / "r2.state.json", "--sheet", ws / "r2.sheet.json",
                "--asset", f"api_key={ws / 'secret.txt'}", "--out", ws / "r2.proof.json", "--fail-on-present") == 1
    proof = json.loads((ws / "r2.proof.json").read_text())
    assert proof["verdict"] == "present"
    assert _run("verify", ws / "r2.proof.json", "--asset", f"api_key={ws / 'secret.txt'}") == 1


def test_undetectable_short_asset_never_counts_as_clean(ws):
    assert _run("witness", ws / "egress", "--run-id", "r3", "--key", ws / "w.key.json",
                "--sheet", ws / "r3.sheet.json", "--state", ws / "r3.state.json") == 0
    assert _run("prove", "--state", ws / "r3.state.json", "--sheet", ws / "r3.sheet.json",
                "--asset", f"short={ws / 'short.txt'}", "--asset", f"api_key={ws / 'secret.txt'}",
                "--out", ws / "r3.proof.json") == 0
    proof = json.loads((ws / "r3.proof.json").read_text())
    assert proof["verdict"] == "mixed"
    assert _run("verify", ws / "r3.proof.json", "--asset", f"short={ws / 'short.txt'}", "--asset", f"api_key={ws / 'secret.txt'}") == 1


def test_tampered_proof_is_invalid(ws):
    assert _run("witness", ws / "egress", "--run-id", "r4", "--key", ws / "w.key.json",
                "--sheet", ws / "r4.sheet.json", "--state", ws / "r4.state.json") == 0
    (ws / "egress" / "leak.txt").write_bytes(SECRET)
    assert _run("witness", ws / "egress" / "leak.txt", "--run-id", "r4", "--key", ws / "w.key.json", "--append",
                "--sheet", ws / "r4.sheet.json", "--state", ws / "r4.state.json") == 0
    assert _run("prove", "--state", ws / "r4.state.json", "--sheet", ws / "r4.sheet.json",
                "--asset", f"api_key={ws / 'secret.txt'}", "--out", ws / "r4.proof.json") == 0
    proof = json.loads((ws / "r4.proof.json").read_text())
    assert proof["verdict"] == "present"
    # a prover that flips the verdict is caught by the paths
    proof["verdict"] = "absent"
    for a in proof["assets"]:
        a["verdict"] = "absent"
        for f in a["fingerprints"]:
            f["present"] = False
    (ws / "r4.bad.json").write_text(json.dumps(proof))
    assert _run("verify", ws / "r4.bad.json", "--asset", f"api_key={ws / 'secret.txt'}") == 2


def test_env_assets_and_env_key(ws, monkeypatch):
    seed = os.urandom(32).hex()
    monkeypatch.setenv("PNX_WITNESS_SEED", seed)
    monkeypatch.setenv("OPENAI_API_KEY", SECRET.decode("latin-1"))
    assert _run("witness", ws / "egress", "--run-id", "r5", "--key-env", "PNX_WITNESS_SEED", "--key-id", "urn:test:ci",
                "--sheet", ws / "r5.sheet.json", "--state", ws / "r5.state.json") == 0
    assert json.loads((ws / "r5.sheet.json").read_text())["witness"]["id"] == "urn:test:ci"
    assert _run("prove", "--state", ws / "r5.state.json", "--sheet", ws / "r5.sheet.json",
                "--asset-env", "OPENAI_API_KEY", "--out", ws / "r5.proof.json") == 0
    proof = json.loads((ws / "r5.proof.json").read_text())
    assert proof["assets"][0]["label"] == "env:OPENAI_API_KEY" and proof["verdict"] == "absent"
    assert SECRET.decode("latin-1") not in (ws / "r5.proof.json").read_text()


def test_sealed_delivery_roundtrip(ws):
    pytest.importorskip("crovia_seal")
    assert _run("keygen", "--id", "urn:test:issuer", "--out", ws / "i.key.json") == 0
    assert _run("witness", ws / "egress", "--run-id", "r6", "--key", ws / "w.key.json",
                "--sheet", ws / "r6.sheet.json", "--state", ws / "r6.state.json") == 0
    assert _run("prove", "--state", ws / "r6.state.json", "--sheet", ws / "r6.sheet.json",
                "--asset", f"api_key={ws / 'secret.txt'}", "--seal-key", ws / "i.key.json", "--out", ws / "r6.sealed.json") == 0
    bundle = json.loads((ws / "r6.sealed.json").read_text())
    assert set(bundle) == {"seal", "query", "proof"} and bundle["seal"]["seal_version"] == "crovia.seal.v1"
    assert bundle["seal"]["checks"]["pnx"]["verdict"] == "absent"
    assert _run("verify", ws / "r6.sealed.json", "--asset", f"api_key={ws / 'secret.txt'}") == 0
    # tamper with the inner proof: the Seal no longer binds it
    bundle["proof"]["sheet"]["egress"]["bodies"] = 0
    (ws / "r6.bad.json").write_text(json.dumps(bundle))
    assert _run("verify", ws / "r6.bad.json", "--asset", f"api_key={ws / 'secret.txt'}") == 2
