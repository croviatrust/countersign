#!/usr/bin/env python3
"""Run the TACET v1 conformance suite against the committed vectors.

    python3 tacet/conformance/run_conformance.py

Exit code 0 iff every case passes. Implementations in other languages should
port this runner: every case is a pure function of the vector files.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "reference" / "python"))

from tacet import (EMPTY, CompactPath, SparseMerkleMap, target_key, verify_inclusion, verify_non_inclusion,  # noqa: E402
                   verify_silence_proof, verify_wrapped)
from tacet.epoch import validate_chain  # noqa: E402
from tacet.hashing import unprefixed  # noqa: E402
from tacet.smt import root_from_path  # noqa: E402

V = HERE / "vectors" / "v1"
passed = failed = 0


def case(name: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    passed += ok
    failed += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail and not ok else ''}")


def load(name: str):
    return json.loads((V / name).read_text(encoding="utf-8"))


def main() -> int:
    print("TACET v1 conformance")
    print(f"Vectors: {V}\n")

    v = load("map_001_primitives.json")
    case("empty root", EMPTY[256].hex() == v["empty_root"])
    case("empty leaf", EMPTY[0].hex() == v["empty_leaf"])
    m = SparseMerkleMap({bytes.fromhex(k): bytes.fromhex(h) for k, h in v["entries"].items()})
    case("map root", m.root().hex() == v["root"])
    ni = v["non_inclusion"]
    case("non-inclusion proof verifies",
         verify_non_inclusion(bytes.fromhex(v["root"]), bytes.fromhex(ni["key"]), CompactPath.from_json(ni["path"])) is ni["expect"])
    case("non-inclusion key derivation", target_key(ni["target_id"]).hex() == ni["key"])
    inc = v["inclusion"]
    case("inclusion proof verifies",
         verify_inclusion(bytes.fromhex(v["root"]), bytes.fromhex(inc["key"]), bytes.fromhex(inc["value_hash"]),
                          CompactPath.from_json(inc["path"])) is inc["expect"])
    case("inclusion path is not a non-inclusion proof",
         not verify_non_inclusion(bytes.fromhex(v["root"]), bytes.fromhex(inc["key"]), CompactPath.from_json(inc["path"])))
    case("proof regenerated from map is identical", m.prove(bytes.fromhex(ni["key"])).to_json() == ni["path"])

    sheets = load("sheets_001_chain.json")["sheets"]
    try:
        validate_chain(sheets)
        case("sheet chain validates", True)
    except Exception as e:  # noqa: BLE001
        case("sheet chain validates", False, str(e))

    for name in ("silence_001_level1.json", "silence_002_level2.json", "silence_003_level3.json"):
        vec = load(name)
        r = verify_silence_proof(vec["proof"])
        exp = vec["expect"]
        case(f"{name}: ok", r.ok is exp["ok"], "; ".join(r.errors))
        case(f"{name}: strength", r.strength_verified == exp["strength_verified"])
        case(f"{name}: silence_seconds", r.silence.get("silence_seconds") == exp["silence_seconds"])

    try:
        import crovia_seal  # noqa: F401
        w = load("wrapped_001_level3.json")
        res = verify_wrapped({"seal": w["seal"], "query": w["query"], "proof": w["proof"]})
        case("wrapped bundle verifies (Seal + TACET)", res["ok"] is w["expect"]["ok"], "; ".join(res["errors"]))
        case("wrapped bundle: outer Seal verifies with crovia_seal", res["seal_ok"])
    except ImportError:
        print("  [SKIP] wrapped bundle (crovia_seal reference not installed)")

    try:
        import crovia_seal  # noqa: F401
        for name, vec in load("wrapped_002_invalid.json").items():
            res = verify_wrapped({"seal": vec["seal"], "query": vec["query"], "proof": vec["proof"]})
            case(f"wrapped invalid/{name}: Seal valid, bundle rejected",
                 res["seal_ok"] and not res["ok"] and any(vec["expect_error_contains"] in e for e in res["errors"]),
                 "; ".join(res["errors"]) or "accepted")
    except ImportError:
        print("  [SKIP] wrapped invalid bundles (crovia_seal reference not installed)")

    inv = load("invalid_001.json")
    for name, vec in inv.items():
        r = verify_silence_proof(vec["proof"])
        case(f"invalid/{name} rejected", not r.ok and any(vec["expect_error_contains"] in e for e in r.errors),
             "; ".join(r.errors) or "accepted")

    vb = load("silence_004_before_disclosure.json")
    r = verify_silence_proof(vb["proof"])
    case("silence before disclosure epoch verifies", r.ok is vb["expect"]["ok"], "; ".join(r.errors))
    key = bytes.fromhex(vb["proof"]["key"])
    after_ok = all(
        root_from_path(key, EMPTY[0], CompactPath.from_json(p).to_full()) == unprefixed(sheets[int(e)]["root"])
        for e, p in vb["paths_after_disclosure"].items())
    case("non-inclusion fails from the disclosure epoch onward", after_ok is vb["expect"]["non_inclusion_after_disclosure"])

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
