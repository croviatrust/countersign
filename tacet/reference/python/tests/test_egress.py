import json
import os
import random

import pytest

from tacet import egress
from tacet.keys import SigningKey


def _witness_with(bodies, salt=b"\x01" * 16):
    w = egress.EgressWitness(run_id="run-test", salt=salt)
    for i, b in enumerate(bodies):
        w.ingest(b, f"2026-09-19T22:00:{i:02d}Z")
    return w


def _key():
    return SigningKey.from_seed("witness-test", b"\x07" * 32)


def test_winnowing_guarantee_at_every_offset():
    rng = random.Random(7)
    secret = bytes(rng.getrandbits(8) for _ in range(egress.THRESHOLD))
    for _ in range(40):
        noise = bytes(rng.getrandbits(8) for _ in range(600))
        off = rng.randrange(0, len(noise) - len(secret))
        body = noise[:off] + secret + noise[off:]
        w = _witness_with([body])
        _, fps = egress.asset_fingerprints(secret, w.salt)
        assert any(fp in w._map for fp in fps), "a shared substring of THRESHOLD bytes must always hit"


def test_absent_and_present_roundtrip():
    rng = random.Random(1)
    leaked = b"sk-live-" + bytes(rng.getrandbits(8) for _ in range(60))
    safe = b"AKIA" + bytes(rng.getrandbits(8) for _ in range(60))
    traffic = [b"POST /v1/chat " + bytes(rng.getrandbits(8) for _ in range(300)) + leaked + b" tail",
               b"GET /health", bytes(rng.getrandbits(8) for _ in range(1000))]
    w = _witness_with(traffic)
    sheet = w.sheet(_key(), "2026-09-19T22:01:00Z")
    proof = w.prove(sheet, [("openai_key", leaked), ("aws_key", safe)])
    assert proof["verdict"] == egress.VERDICT_PRESENT
    by = {a["label"]: a["verdict"] for a in proof["assets"]}
    assert by == {"openai_key": egress.VERDICT_PRESENT, "aws_key": egress.VERDICT_ABSENT}

    res = egress.verify_pnx(proof, {"openai_key": leaked, "aws_key": safe})
    assert res.ok and res.verdict == egress.VERDICT_PRESENT and not res.warnings

    clean = w.prove(sheet, [("aws_key", safe)])
    res = egress.verify_pnx(clean, {"aws_key": safe})
    assert res.ok and res.verdict == egress.VERDICT_ABSENT

    # the proof survives a JSON round trip byte for byte
    again = json.loads(json.dumps(clean))
    assert egress.verify_pnx(again, {"aws_key": safe}).ok


def test_short_assets_are_reported_not_hidden():
    w = _witness_with([os.urandom(500)])
    sheet = w.sheet(_key(), "2026-09-19T22:01:00Z")
    proof = w.prove(sheet, [("pin", b"1234"), ("mid", b"x" * 40), ("long", b"y" * 100)])
    by = {a["label"]: a["verdict"] for a in proof["assets"]}
    assert by["pin"] == egress.VERDICT_UNDETECTABLE
    assert by["mid"] == egress.VERDICT_ABSENT_PARTIAL
    assert by["long"] == egress.VERDICT_ABSENT
    assert proof["verdict"] == "mixed"
    res = egress.verify_pnx(proof, {"pin": b"1234", "mid": b"x" * 40, "long": b"y" * 100})
    assert res.ok
    assert any("cannot be fingerprinted" in m for m in res.warnings)
    assert any("guarantee" in m for m in res.warnings)


def test_tampering_is_detected():
    secret = os.urandom(80)
    w = _witness_with([os.urandom(400)])
    sheet = w.sheet(_key(), "2026-09-19T22:01:00Z")
    proof = w.prove(sheet, [("s", secret)])
    assert egress.verify_pnx(proof, {"s": secret}).ok

    # wrong asset bytes
    assert not egress.verify_pnx(proof, {"s": os.urandom(80)}).ok
    # forged verdict
    bad = json.loads(json.dumps(proof))
    bad["assets"][0]["verdict"] = egress.VERDICT_PRESENT
    assert not egress.verify_pnx(bad, {"s": secret}).ok
    # tampered sheet (root changed after signing)
    bad = json.loads(json.dumps(proof))
    bad["sheet"]["egress"]["bodies"] = 0
    r = egress.verify_pnx(bad, {"s": secret})
    assert not r.ok and "signature" in " ".join(r.errors)
    # a path against another root
    other = _witness_with([os.urandom(400)], salt=w.salt)
    other_sheet = other.sheet(_key(), "2026-09-19T22:01:00Z")
    bad = json.loads(json.dumps(proof))
    bad["sheet"] = other_sheet
    assert not egress.verify_pnx(bad, {"s": secret}).ok


def test_hash_only_mode_warns():
    secret = os.urandom(80)
    w = _witness_with([os.urandom(400)])
    proof = w.prove(w.sheet(_key(), "2026-09-19T22:01:00Z"), [("s", secret)])
    res = egress.verify_pnx(proof)
    assert res.ok and res.verdict == egress.VERDICT_ABSENT
    assert any("not recomputed" in m for m in res.warnings)


def test_sheet_root_must_match_map():
    w = _witness_with([b"a" * 100])
    sheet = w.sheet(_key(), "2026-09-19T22:01:00Z")
    w.ingest(b"b" * 100, "2026-09-19T22:02:00Z")
    with pytest.raises(ValueError):
        w.prove(sheet, [("x", b"z" * 64)])


def test_epoch_leaf_key_is_namespaced():
    assert egress.epoch_leaf_key("run-1") != egress.epoch_leaf_key("run-2")
    assert len(egress.epoch_leaf_key("run-1")) == 32
