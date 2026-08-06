"""CLI integration tests (in-process, no subprocess needed)."""

import hashlib
import json

import pytest

from countersign.cli import main


def d(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@pytest.fixture()
def logdir(tmp_path):
    path = tmp_path / "log"
    assert main(["init", "--log", str(path)]) == 0
    return path


def run_json(capsys, argv):
    code = main(argv)
    out = capsys.readouterr().out
    return code, json.loads(out)


def test_init_prints_public_key(tmp_path, capsys):
    code, out = run_json(capsys, ["init", "--log", str(tmp_path / "l")])
    assert code == 0
    assert len(out["public_key"]) == 64
    assert len(out["key_id"]) == 16


def test_witness_digest_and_prove_and_verify(logdir, tmp_path, capsys):
    digest = d("hello-evidence")
    code, out = run_json(capsys, ["witness", "--log", str(logdir), "--digest", digest])
    assert code == 0 and out["count"] == 1

    bundle_path = tmp_path / "proof.json"
    code, _ = run_json(
        capsys,
        ["prove", "--log", str(logdir), "--digest", digest, "--out", str(bundle_path)],
    )
    assert code == 0 and bundle_path.exists()

    code, report = run_json(capsys, ["verify", str(bundle_path)])
    assert code == 0 and report["ok"]


def test_witness_file(logdir, tmp_path, capsys):
    f = tmp_path / "audit_packet.json"
    f.write_text('{"anything": "at all"}', encoding="utf-8")
    code, out = run_json(capsys, ["witness", "--log", str(logdir), str(f)])
    assert code == 0
    expected = hashlib.sha256(f.read_bytes()).hexdigest()
    assert out["witnessed"][0]["digest"] == expected


def test_witness_jsonl_per_line(logdir, tmp_path, capsys):
    f = tmp_path / "receipts.jsonl"
    f.write_text('{"r":1}\n{"r":2}\n\n{"r":3}\n', encoding="utf-8")
    code, out = run_json(capsys, ["witness", "--log", str(logdir), "--jsonl", str(f)])
    assert code == 0 and out["count"] == 3
    assert out["sth"]["tree_size"] == 3


def test_audit_and_list(logdir, capsys):
    main(["witness", "--log", str(logdir), "--digest", d("x")])
    capsys.readouterr()
    code, report = run_json(capsys, ["audit", "--log", str(logdir)])
    assert code == 0 and report["ok"]
    code, out = run_json(capsys, ["list", "--log", str(logdir)])
    assert code == 0 and out["count"] == 1


def test_verify_tampered_bundle_exits_nonzero(logdir, tmp_path, capsys):
    digest = d("evidence")
    main(["witness", "--log", str(logdir), "--digest", digest])
    bundle_path = tmp_path / "proof.json"
    main(["prove", "--log", str(logdir), "--digest", digest, "--out", str(bundle_path)])
    capsys.readouterr()

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["entry"]["witnessed_at"] = "2020-01-01T00:00:00Z"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    code, report = run_json(capsys, ["verify", str(bundle_path)])
    assert code == 1 and not report["ok"]


def test_verify_with_pinned_pubkey(logdir, tmp_path, capsys):
    digest = d("evidence")
    main(["witness", "--log", str(logdir), "--digest", digest])
    bundle_path = tmp_path / "proof.json"
    main(["prove", "--log", str(logdir), "--digest", digest, "--out", str(bundle_path)])
    pub = (logdir / "witness.pub").read_text().strip()
    capsys.readouterr()

    code, report = run_json(capsys, ["verify", str(bundle_path), "--pubkey", pub])
    assert code == 0 and report["ok"]

    code, report = run_json(capsys, ["verify", str(bundle_path), "--pubkey", "0" * 64])
    assert code == 1 and not report["ok"]
