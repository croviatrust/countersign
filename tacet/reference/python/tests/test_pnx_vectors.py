"""The committed PNX conformance vectors (conformance/vectors/v1/pnx_00*.json) against the reference.

The runner in conformance/run_conformance.py is the normative check; these tests keep
the vectors, the fixture scenario and the library from drifting apart under pytest.
"""
import json
from pathlib import Path

import pytest

from tacet import egress
from tacet import fixtures as fx

VECTORS = Path(__file__).resolve().parents[3] / "conformance" / "vectors" / "v1"


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def test_fixture_stream_is_sha256_counter_mode():
    import hashlib
    v = load("pnx_001_fingerprints.json")["stream"]["example"]
    manual = b"".join(hashlib.sha256(f"tacet-pnx-fixture:{v['label']}:{i}".encode()).digest() for i in range(2))[:v["n"]]
    assert fx.pnx_stream(v["label"], v["n"]) == manual and manual.hex() == v["hex"]


def test_fingerprint_primitives_are_pinned():
    v = load("pnx_001_fingerprints.json")
    salt = bytes.fromhex(v["salt_hex"])
    assert salt == fx.PNX_SALT
    assert egress.PRESENT.hex() == v["present_leaf_value"]
    assert [h.hex() for h in egress.kgram_hashes(bytes.fromhex(v["kgram_hashes"]["data_hex"]), salt)] == v["kgram_hashes"]["hashes"]
    assert sorted(f.hex() for f in egress.fingerprints(bytes.fromhex(v["winnowing"]["data_hex"]), salt)) == v["winnowing"]["fingerprints"]
    for c in v["detection_classes"]:
        klass, fps = egress.asset_fingerprints(bytes.fromhex(c["asset_hex"]), salt)
        assert (klass, sorted(f.hex() for f in fps)) == (c["detection"], c["fingerprints"])
    js = v["json_strings"]
    assert [b.hex() for b in egress.json_strings(bytes.fromhex(js["body_hex"]))] == js["derived_hex"]


def test_winnowing_guarantee_vector_holds_at_every_offset():
    g = load("pnx_001_fingerprints.json")["guarantee"]
    salt = fx.PNX_SALT
    secret, noise = bytes.fromhex(g["secret_hex"]), bytes.fromhex(g["noise_hex"])
    assert len(secret) == egress.THRESHOLD
    sfp = set(egress.asset_fingerprints(secret, salt)[1])
    assert all(sfp & egress.fingerprints(noise[:o] + secret + noise[o:], salt) for o in g["offsets"])


def test_scenario_regenerates_the_committed_run_and_proofs():
    v = load("pnx_002_proofs.json")
    sc = fx.build_pnx_scenario()
    assert sc.sheet == v["sheet"]
    assert sc.clean == v["proofs"]["clean"]["proof"]
    assert sc.exposure == v["proofs"]["exposure"]["proof"]
    assert [b["body"].hex() for b in fx.PNX_BODIES] == [b["body_hex"] for b in v["run"]["bodies"]]


def test_config_file_is_found_only_through_json_strings_layer():
    """PNX §3: the quoted file shares no k-gram with the raw JSON body; json-strings-v1 restores detection."""
    raw_only = egress.EgressWitness(run_id=fx.PNX_RUN_ID, salt=fx.PNX_SALT, normalization=())
    for b in fx.PNX_BODIES:
        raw_only.ingest(b["body"], b["at"])
    _, fps = egress.asset_fingerprints(fx.PNX_LEAKED_FILE, fx.PNX_SALT)
    assert not any(fp in raw_only._map for fp in fps)
    sc = fx.build_pnx_scenario()
    assert {a["label"]: a["verdict"] for a in sc.exposure["assets"]}["config.yaml"] == egress.VERDICT_PRESENT


@pytest.mark.parametrize("name", ["clean", "exposure"])
def test_committed_proofs_verify_with_and_without_assets(name):
    v = load("pnx_002_proofs.json")
    vec = v["proofs"][name]
    r = egress.verify_pnx(vec["proof"], {k: bytes.fromhex(x) for k, x in vec["assets_hex"].items()})
    assert r.ok and r.verdict == vec["expect"]["verdict"] and r.assets == vec["expect"]["assets"]
    r = egress.verify_pnx(vec["proof"])
    assert r.ok and any(v["hash_only"]["expect"]["warning_contains"] in m for m in r.warnings)


def test_every_invalid_vector_is_rejected_for_the_stated_reason():
    for name, vec in load("pnx_003_invalid.json").items():
        r = egress.verify_pnx(vec["proof"], {k: bytes.fromhex(x) for k, x in vec["assets_hex"].items()})
        assert not r.ok, name
        assert any(vec["expect_error_contains"] in e for e in r.errors), (name, r.errors)
        assert egress.verify_pnx(vec["proof"]).ok is vec["hash_only_ok"], name


def test_sealed_vectors_round_trip_through_verify_any():
    pytest.importorskip("crovia_seal")
    from tacet.pnx import verify_any
    v = load("pnx_004_sealed.json")
    for name, vec in ({"clean": v["clean"], "exposure": v["exposure"]} | v["invalid"]).items():
        r, outer = verify_any({"seal": vec["seal"], "query": vec["query"], "proof": vec["proof"]},
                              {k: bytes.fromhex(x) for k, x in vec["assets_hex"].items()})
        assert outer["sealed"] and r.ok is vec["expect"]["ok"], (name, r.errors)
        if not vec["expect"]["ok"]:
            assert outer["seal_signature_ok"] is vec["expect"]["seal_signature_ok"], name
            assert any(vec["expect_error_contains"] in e for e in r.errors), (name, r.errors)


def test_seal_pnx_is_deterministic_with_fixed_timestamp_and_nonce():
    pytest.importorskip("crovia_seal")
    from tacet.pnx import seal_pnx
    from tacet.wrap import TACET_VERSION
    sc = fx.build_pnx_scenario()
    kw = dict(tacet_version=TACET_VERSION, emitted_at="2026-09-20T12:00:00.000Z", nonce="PNXCONFORMANCEVECTORAAAAAA", seal_id="cs_2026_PNXCONFORMANCEVECTORAAAAAA")
    assert seal_pnx(sc.clean, sc.issuer, **kw) == seal_pnx(sc.clean, sc.issuer, **kw) == {
        k: load("pnx_004_sealed.json")["clean"][k] for k in ("seal", "query", "proof")}
