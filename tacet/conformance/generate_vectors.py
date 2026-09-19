#!/usr/bin/env python3
"""Generate the TACET v1 conformance vectors deterministically into vectors/v1/.

Run from the repository root:  python3 tacet/conformance/generate_vectors.py
Re-running must produce byte-identical files (CI checks `git diff --quiet`).
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "reference" / "python"))

from tacet import (EMPTY, STRENGTH_MAP, STRENGTH_SURFACE, STRENGTH_WITNESSED, SparseMerkleMap,  # noqa: E402
                   build_query, build_silence_proof, object_hash, target_key, wrap_in_seal)
from tacet.fixtures import (DISCLOSED_TARGET, DISCLOSURE_EPOCH, MAP_ID, TARGET, build_scenario,  # noqa: E402
                            witness_set)

OUT = HERE / "vectors" / "v1"


def dump(name: str, obj) -> str:
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (OUT / name).write_text(data, encoding="utf-8")
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def main() -> None:
    sc = build_scenario()
    index = {"vectors_version": "crovia.tacet.vectors.v1", "files": {}}

    # 1. Map primitives.
    m = SparseMerkleMap()
    for i in range(20):
        m.set(target_key(f"o{i}/m{i}"), object_hash({"i": i}))
    k_out = target_key("absent/model")
    k_in = target_key("o7/m7")
    index["files"]["map_001_primitives.json"] = dump("map_001_primitives.json", {
        "empty_root": EMPTY[256].hex(),
        "empty_leaf": EMPTY[0].hex(),
        "entries": {target_key(f"o{i}/m{i}").hex(): object_hash({"i": i}).hex() for i in range(20)},
        "root": m.root().hex(),
        "non_inclusion": {"target_id": "absent/model", "key": k_out.hex(), "path": m.prove(k_out).to_json(), "expect": True},
        "inclusion": {"target_id": "o7/m7", "key": k_in.hex(), "value_hash": object_hash({"i": 7}).hex(),
                      "path": m.prove(k_in).to_json(), "expect": True},
    })

    # 2. Epoch sheets (full chain) and negative snapshots.
    index["files"]["sheets_001_chain.json"] = dump("sheets_001_chain.json", {"sheets": sc.sheets})
    index["files"]["snapshots_001_negative.json"] = dump("snapshots_001_negative.json", {
        "negative_snapshots": sc.negative_snapshots,
        "epoch_snapshot_hashes": {str(e): [h.hex() for h in hs] for e, hs in sc.snapshot_hashes.items()},
    })

    # 3. Valid silence proofs at the three strengths.
    p1 = build_silence_proof(map_id=MAP_ID, target_id=TARGET, sheets=sc.sheets, paths=sc.paths, strength=STRENGTH_MAP)
    p2 = build_silence_proof(map_id=MAP_ID, target_id=TARGET, sheets=sc.sheets, paths=sc.paths,
                             epoch_snapshot_hashes=sc.snapshot_hashes, negative_snapshots=sc.negative_snapshots,
                             strength=STRENGTH_SURFACE)
    p3 = build_silence_proof(map_id=MAP_ID, target_id=TARGET, sheets=sc.sheets, paths=sc.paths,
                             epoch_snapshot_hashes=sc.snapshot_hashes, negative_snapshots=sc.negative_snapshots,
                             witnesses=sc.witness_sigs, witness_set=witness_set(sc), strength=STRENGTH_WITNESSED)
    for name, p in (("silence_001_level1.json", p1), ("silence_002_level2.json", p2), ("silence_003_level3.json", p3)):
        index["files"][name] = dump(name, {"proof": p, "expect": {"ok": True, "strength_verified": p["strength"],
                                                                "silence_seconds": p["silence"]["silence_seconds"]}})

    # 4. Seal-wrapped bundle.
    q = build_query(map_id=MAP_ID, target_id=TARGET, from_epoch=0, to_epoch=11, min_strength=2)
    bundle = wrap_in_seal(issuer=sc.issuer, query=q, proof=p3, emitted_at="2026-09-19T12:00:00.000Z",
                          nonce="TACETCONFORMANCEVECTORAAAA", seal_id="cs_2026_TACETCONFORMANCEVECTORAAAA")
    index["files"]["wrapped_001_level3.json"] = dump("wrapped_001_level3.json", {**bundle, "expect": {"ok": True}})

    # 5. Invalid proofs (fail-closed).
    invalid = {}
    bad = copy.deepcopy(p2)
    bad["silence"]["silence_seconds"] = 12 * 3600
    bad["silence"]["silence_days"] = "0.50"
    invalid["overstated_silence"] = {"proof": bad, "expect_error_contains": "monotonicity"}
    bad = copy.deepcopy(p3)
    del bad["sheets"][5]
    invalid["missing_sheet"] = {"proof": bad, "expect_error_contains": "gap"}
    bad = copy.deepcopy(p3)
    bad["sheets"][2]["root"] = "sha256:" + "00" * 32
    invalid["tampered_root"] = {"proof": bad, "expect_error_contains": "signature invalid"}
    bad = copy.deepcopy(p3)
    bad["paths"]["deltas"][1]["changed"] = []
    invalid["tampered_delta"] = {"proof": bad, "expect_error_contains": "non-inclusion fails"}
    bad = copy.deepcopy(p3)
    bad["witness_set"]["k"] = 3
    invalid["insufficient_witnesses"] = {"proof": bad, "expect_error_contains": "need 3"}
    bad = copy.deepcopy(p2)
    bad["target_id"] = DISCLOSED_TARGET
    invalid["key_target_mismatch"] = {"proof": bad, "expect_error_contains": "key does not match"}
    index["files"]["invalid_001.json"] = dump("invalid_001.json", invalid)

    # 6. Disclosed target: silence provable only before the disclosure epoch.
    pb = build_silence_proof(map_id=MAP_ID, target_id=DISCLOSED_TARGET, sheets=sc.sheets[:DISCLOSURE_EPOCH],
                             paths={e: sc.disclosed_paths[e] for e in range(DISCLOSURE_EPOCH)})
    index["files"]["silence_004_before_disclosure.json"] = dump("silence_004_before_disclosure.json", {
        "proof": pb, "disclosure_epoch": DISCLOSURE_EPOCH,
        "paths_after_disclosure": {str(e): sc.disclosed_paths[e].to_json() for e in range(DISCLOSURE_EPOCH, 12)},
        "expect": {"ok": True, "non_inclusion_after_disclosure": False},
    })

    dump("index.json", index)
    print(f"wrote {len(index['files']) + 1} files to {OUT}")


if __name__ == "__main__":
    main()
