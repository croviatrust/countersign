import copy
import hashlib

import pytest

from tacet import (STRENGTH_MAP, STRENGTH_SURFACE, STRENGTH_WITNESSED, EMPTY, CompactPath,
                   SparseMerkleMap, build_query, build_silence_proof, canonicalize, object_hash, target_key,
                   verify_inclusion, verify_non_inclusion, verify_silence_proof, verify_wrapped, wrap_in_seal)
from tacet.epoch import SheetError, validate_chain, validate_sheet
from tacet.fixtures import DISCLOSED_TARGET, DISCLOSURE_EPOCH, MAP_ID, TARGET, build_scenario, witness_set
from tacet.silence import SilenceProofError, decode_paths, encode_deltas
from tacet import merkle


@pytest.fixture(scope="module")
def sc():
    return build_scenario()


@pytest.fixture(scope="module")
def proof3(sc):
    return build_silence_proof(map_id=MAP_ID, target_id=TARGET, sheets=sc.sheets, paths=sc.paths,
                               epoch_snapshot_hashes=sc.snapshot_hashes, negative_snapshots=sc.negative_snapshots,
                               witnesses=sc.witness_sigs, witness_set=witness_set(sc), strength=STRENGTH_WITNESSED)


# --- canonicalization -------------------------------------------------------

def test_csc1_matches_seal_reference():
    pytest.importorskip("crovia_seal")
    from crovia_seal.canonical import canonicalize as ref
    samples = [{"b": 1, "a": [1, "x", None, True], "é": {"z": "\u0001\n\"\\"}}, {"😀": 1, "Z": 2, "a": 3}, [], {}]
    for s in samples:
        assert canonicalize(s) == ref(s)


def test_csc1_rejects_floats():
    from tacet.canonical import CanonicalizationError
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": 1.5})


# --- sparse Merkle map ------------------------------------------------------

def test_empty_root_and_non_inclusion():
    m = SparseMerkleMap()
    assert m.root() == EMPTY[256]
    k = target_key(TARGET)
    p = m.prove(k)
    assert p.bitmap == 0 and p.siblings == ()
    assert verify_non_inclusion(m.root(), k, p)


def test_inclusion_and_non_inclusion_are_exclusive():
    m = SparseMerkleMap()
    for i in range(50):
        m.set(target_key(f"o{i}/m{i}"), object_hash({"i": i}))
    k_in, k_out = target_key("o7/m7"), target_key("absent/model")
    r = m.root()
    assert verify_inclusion(r, k_in, object_hash({"i": 7}), m.prove(k_in))
    assert not verify_non_inclusion(r, k_in, m.prove(k_in))
    assert verify_non_inclusion(r, k_out, m.prove(k_out))
    assert not verify_inclusion(r, k_out, object_hash({"i": 0}), m.prove(k_out))


def test_compact_path_roundtrip():
    m = SparseMerkleMap()
    for i in range(20):
        m.set(target_key(f"o{i}/m{i}"), object_hash({"i": i}))
    p = m.prove(target_key("x/y"))
    assert CompactPath.from_json(p.to_json()) == p
    assert len(p.siblings) < 12


def test_root_is_order_independent():
    a, b = SparseMerkleMap(), SparseMerkleMap()
    items = [(target_key(f"o{i}/m{i}"), object_hash({"i": i})) for i in range(15)]
    for k, v in items:
        a.set(k, v)
    for k, v in reversed(items):
        b.set(k, v)
    assert a.root() == b.root()


# --- RFC 6962 tree ------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13])
def test_merkle_inclusion(n):
    leaves = [hashlib.sha256(bytes([i])).digest() for i in range(n)]
    root = merkle.merkle_root(leaves)
    for i in range(n):
        assert merkle.verify_inclusion(root, leaves[i], i, n, merkle.inclusion_path(leaves, i))
    assert not merkle.verify_inclusion(root, b"\x00" * 32, 0, n, merkle.inclusion_path(leaves, 0))


# --- epoch sheets -------------------------------------------------------------

def test_sheets_validate_and_chain(sc):
    validate_chain(sc.sheets)


def test_sheet_tamper_detected(sc):
    s = copy.deepcopy(sc.sheets[3])
    s["size"] += 1
    with pytest.raises(SheetError, match="signature invalid"):
        validate_sheet(s)


def test_chain_gap_detected(sc):
    with pytest.raises(SheetError, match="epoch gap"):
        validate_chain(sc.sheets[:4] + sc.sheets[5:])


def test_closed_outside_signed_region(sc):
    pending = copy.deepcopy(sc.sheets[11])
    assert pending["closed"]["status"] == "pending"
    validate_sheet(pending)


# --- delta encoding -----------------------------------------------------------

def test_delta_roundtrip(sc):
    epochs = [s["epoch"] for s in sc.sheets]
    paths = [sc.paths[e] for e in epochs]
    enc = encode_deltas(paths, epochs)
    assert sum(len(d["changed"]) for d in enc["deltas"]) <= 6
    dec = decode_paths(enc, epochs)
    assert dec == [p.to_full() for p in paths]


# --- silence proofs -----------------------------------------------------------

def test_level3_verifies(proof3):
    r = verify_silence_proof(proof3)
    assert r.ok and r.strength_verified == STRENGTH_WITNESSED
    assert r.anchored_epochs == 11


def test_monotonicity_rule(proof3):
    s = proof3["silence"]
    assert s["map_epochs"] == 12
    assert s["observed_epochs"] == 8          # epochs 7-9 unobserved, 11 unanchored
    assert s["silence_seconds"] == 8 * 3600   # not 12 * 3600
    assert s["silence_days"] == "0.33"
    assert s["observed_to"] == "2026-09-19T11:00:00Z"


def test_overstated_silence_rejected(proof3):
    bad = copy.deepcopy(proof3)
    bad["silence"]["silence_seconds"] = 12 * 3600
    bad["silence"]["silence_days"] = "0.50"
    r = verify_silence_proof(bad)
    assert not r.ok and any("monotonicity" in e for e in r.errors)


def test_missing_sheet_rejected(proof3):
    bad = copy.deepcopy(proof3)
    del bad["sheets"][5]
    r = verify_silence_proof(bad)
    assert not r.ok and any("gap" in e for e in r.errors)


def test_snapshot_from_other_epoch_rejected(proof3):
    bad = copy.deepcopy(proof3)
    bad["snapshots"][3]["snapshot"]["epoch"] = 4
    r = verify_silence_proof(bad)
    assert not r.ok and any("signature invalid" in e for e in r.errors)


def test_level1_proof_reports_no_observation(sc):
    p1 = build_silence_proof(map_id=MAP_ID, target_id=TARGET, sheets=sc.sheets, paths=sc.paths, strength=STRENGTH_MAP)
    assert p1["silence"]["observed_epochs"] == 0 and p1["silence"]["silence_seconds"] == 0
    assert verify_silence_proof(p1).ok


def test_disclosed_target_cannot_be_proven_silent(sc):
    with pytest.raises(SilenceProofError, match=f"epoch {DISCLOSURE_EPOCH}"):
        build_silence_proof(map_id=MAP_ID, target_id=DISCLOSED_TARGET, sheets=sc.sheets, paths=sc.disclosed_paths)
    before = sc.sheets[:DISCLOSURE_EPOCH]
    p = build_silence_proof(map_id=MAP_ID, target_id=DISCLOSED_TARGET, sheets=before,
                            paths={e: sc.disclosed_paths[e] for e in range(DISCLOSURE_EPOCH)})
    assert verify_silence_proof(p).ok


def test_witness_threshold(sc):
    ws = witness_set(sc, k=3)
    p = build_silence_proof(map_id=MAP_ID, target_id=TARGET, sheets=sc.sheets, paths=sc.paths,
                            epoch_snapshot_hashes=sc.snapshot_hashes, negative_snapshots=sc.negative_snapshots,
                            witnesses=sc.witness_sigs, witness_set=ws, strength=STRENGTH_WITNESSED)
    r = verify_silence_proof(p)
    assert not r.ok and r.strength_verified == STRENGTH_SURFACE
    assert any("need 3" in e for e in r.errors)


def test_operator_key_pinning(proof3, sc):
    assert verify_silence_proof(proof3, expected_operator_pubkey_hex=sc.operator.public_hex).ok
    assert not verify_silence_proof(proof3, expected_operator_pubkey_hex="00" * 32).ok


def test_external_checks_are_consulted(proof3):
    r = verify_silence_proof(proof3, beacon_check=lambda o, s: True, ots_check=lambda c, h: True)
    assert r.ok and r.warnings == []
    r = verify_silence_proof(proof3, ots_check=lambda c, h: False)
    assert not r.ok and r.anchored_epochs == 0


# --- Seal wrapper -------------------------------------------------------------

def test_wrapped_proof_is_a_valid_seal(proof3, sc):
    pytest.importorskip("crovia_seal")
    q = build_query(map_id=MAP_ID, target_id=TARGET, from_epoch=0, to_epoch=11, min_strength=2)
    bundle = wrap_in_seal(issuer=sc.issuer, query=q, proof=proof3,
                          emitted_at="2026-09-19T12:00:00.000Z", nonce="A" * 26, seal_id="cs_2026_" + "A" * 26)
    from crovia_seal import verify_seal
    assert verify_seal(bundle["seal"]).ok
    res = verify_wrapped(bundle)
    assert res["ok"] and res["strength_verified"] == 3
    tampered = copy.deepcopy(bundle)
    tampered["proof"]["silence"]["silence_days"] = "99.00"
    assert not verify_wrapped(tampered)["ok"]
    weak = copy.deepcopy(bundle)
    weak["query"]["min_strength"] = 3
    assert verify_wrapped(weak)["errors"] == ["seal.subject.input_hash does not bind the query"]


@pytest.mark.parametrize("seconds,expected", [
    (0, "0.00"), (3600, "0.04"), (10800, "0.12"), (86400, "1.00"), (86399, "0.99"), (7_513_344, "86.96"), (129_600, "1.50"),
])
def test_silence_days_is_truncated_two_decimals(seconds, expected):
    from tacet.silence import format_silence_days
    assert format_silence_days(seconds) == expected
