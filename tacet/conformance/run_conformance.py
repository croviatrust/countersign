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


def hashlib_sha256(b: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(b).digest()


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

    # §8.6: real OpenTimestamps proofs of live sheets, checked offline against the recorded block header.
    from tacet import ots as ots_mod
    ov = load("ots_001_live_anchors.json")
    by_name = {c["name"]: c for c in ov["cases"]}
    for c in ov["cases"]:
        data = bytes.fromhex(c["ots_hex"])
        sh = bytes.fromhex(c["sheet_hash"].split(":")[1])
        p = ots_mod.parse(data)
        case(f"ots/{c['name']}: file digest is SHA-256(sheet_hash bytes)",
             p.file_digest.hex() == c["file_digest"].split(":")[1] and p.file_digest == hashlib_sha256(sh))
        roots = ots_mod.expected_merkle_roots(data)
        case(f"ots/{c['name']}: Bitcoin attestation at block {c['block_height']} names the recorded merkle root",
             c["merkle_root"] in roots.get(c["block_height"], []), str(roots))
        verdict, detail = ots_mod.verify_sheet_anchor(data, sh, c["block_height"], lambda h, c=c: c["merkle_root"] if h == c["block_height"] else None)
        case(f"ots/{c['name']}: anchor verifies against the block header", verdict is True, detail)
    for n in ov["negative"]:
        c = by_name[n["case"]]
        data = bytes.fromhex(c["ots_hex"])
        if "truncate_bytes" in n:
            data = data[:-n["truncate_bytes"]]
        sh = bytes.fromhex(n.get("sheet_hash", c["sheet_hash"]).split(":")[1])
        src = None if ("header_source" in n and n["header_source"] is None) else (lambda h, c=c: c["merkle_root"] if h == c["block_height"] else None)
        verdict, detail = ots_mod.verify_sheet_anchor(data, sh, n.get("block_height", c["block_height"]), src)
        case(f"ots/negative/{n['name']}: verdict {n['expect']}", verdict is n["expect"], detail)

    pnx_cases()

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def pnx_cases() -> None:
    """PNX profile (PNX.md §9): the fingerprint function, proofs against a witnessed run, faults, sealed delivery."""
    from tacet import egress
    from tacet.canonical import canonicalize
    from tacet.keys import verify_signature

    unhex = bytes.fromhex
    hx = lambda bs: sorted(b.hex() for b in bs)  # noqa: E731

    v = load("pnx_001_fingerprints.json")
    salt = unhex(v["salt_hex"])
    p = v["params"]
    case("pnx/001: parameters of crovia.pnx.v1", (p["k_gram"], p["window"], p["threshold"]) == (egress.K_GRAM, egress.WINDOW, egress.THRESHOLD)
         and p["threshold"] == p["k_gram"] + p["window"] - 1)
    case("pnx/001: present leaf value is SHA-256 of the domain string", egress.PRESENT.hex() == v["present_leaf_value"])
    ex = v["stream"]["example"]
    case("pnx/001: fixture byte stream reproduces", fixtures_stream(ex["label"], ex["n"]).hex() == ex["hex"])
    case("pnx/001: salted k-gram hashes", [h.hex() for h in egress.kgram_hashes(unhex(v["kgram_hashes"]["data_hex"]), salt)] == v["kgram_hashes"]["hashes"])
    case("pnx/001: winnowed fingerprints", hx(egress.fingerprints(unhex(v["winnowing"]["data_hex"]), salt)) == v["winnowing"]["fingerprints"])
    case("pnx/001: body shorter than one window selects the single minimum",
         hx(egress.fingerprints(unhex(v["winnowing_short"]["data_hex"]), salt)) == v["winnowing_short"]["fingerprints"])
    for c in v["detection_classes"]:
        klass, fps = egress.asset_fingerprints(unhex(c["asset_hex"]), salt)
        case(f"pnx/001: {c['asset_len']}-byte asset is {c['detection']}", klass == c["detection"] and hx(fps) == c["fingerprints"])
    g = v["guarantee"]
    secret, noise = unhex(g["secret_hex"]), unhex(g["noise_hex"])
    sfp = set(egress.asset_fingerprints(secret, salt)[1])
    case("pnx/001: secret fingerprints", hx(sfp) == g["secret_fingerprints"])
    hit = [bool(sfp & egress.fingerprints(noise[:o] + secret + noise[o:], salt)) for o in g["offsets"]]
    case(f"pnx/001: winnowing guarantee holds at all {len(hit)} offsets", all(hit), f"missed at offsets {[o for o, h in zip(g['offsets'], hit) if not h]}")
    js = v["json_strings"]
    case("pnx/001: json-strings-v1 derived bodies", [b.hex() for b in egress.json_strings(unhex(js["body_hex"]))] == js["derived_hex"])
    case("pnx/001: non-JSON body yields no derived bodies", egress.json_strings(unhex(js["non_json_body_hex"])) == [])
    case("pnx/001: epoch leaf key pnx/<run_id>", egress.epoch_leaf_key(v["epoch_leaf_key"]["run_id"]).hex() == v["epoch_leaf_key"]["key"])

    v = load("pnx_002_proofs.json")
    run, sheet = v["run"], v["sheet"]
    w = egress.EgressWitness(run_id=run["run_id"], salt=unhex(run["salt_hex"]), normalization=tuple(run["normalization"]))
    for b in run["bodies"]:
        w.ingest(unhex(b["body_hex"]), b["at"])
    case("pnx/002: run root rebuilt from the bodies", egress.prefixed(w.root) == sheet["root"] and len(w._map) == sheet["fingerprints"])
    case("pnx/002: sheet egress counters rebuilt", sheet["egress"] == {"bodies": w.bodies, "bytes": w.bytes_seen, "first_at": w.first_at, "last_at": w.last_at})
    unsigned = {k: x for k, x in sheet.items() if k != "signature"}
    case("pnx/002: sheet signature (CROVIA-PNX-SHEET-v1 over CSC-1)",
         verify_signature(run["witness_pubkey_hex"], egress.DOMAIN_SHEET + canonicalize(unsigned), unhex(sheet["signature"]["sig_hex"])))
    case("pnx/002: verify_sheet accepts", egress.verify_sheet(sheet) == [])
    for name, vec in v["proofs"].items():
        assets = {k: unhex(x) for k, x in vec["assets_hex"].items()}
        r = egress.verify_pnx(vec["proof"], assets)
        case(f"pnx/002 {name}: verifies with asset bytes", r.ok, "; ".join(r.errors))
        case(f"pnx/002 {name}: verdicts {vec['expect']['verdict']}", r.verdict == vec["expect"]["verdict"] and r.assets == vec["expect"]["assets"], str(r.assets))
        case(f"pnx/002 {name}: proof regenerated from the run is identical", w.prove(sheet, [(a, assets[a]) for a in (x["label"] for x in vec["proof"]["assets"])]) == vec["proof"])
        r = egress.verify_pnx(vec["proof"])
        case(f"pnx/002 {name}: hash-only mode accepts and warns",
             r.ok is v["hash_only"]["expect"]["ok"] and any(v["hash_only"]["expect"]["warning_contains"] in m for m in r.warnings), "; ".join(r.errors + r.warnings))

    for name, vec in load("pnx_003_invalid.json").items():
        r = egress.verify_pnx(vec["proof"], {k: unhex(x) for k, x in vec["assets_hex"].items()})
        case(f"pnx/003 invalid/{name} rejected", not r.ok and any(vec["expect_error_contains"] in e for e in r.errors), "; ".join(r.errors) or "accepted")
        case(f"pnx/003 invalid/{name}: hash-only verdict {'accepts' if vec['hash_only_ok'] else 'rejects'}",
             egress.verify_pnx(vec["proof"]).ok is vec["hash_only_ok"])

    try:
        import crovia_seal  # noqa: F401
        from tacet.pnx import verify_any
    except ImportError:
        print("  [SKIP] pnx/004 sealed bundles (crovia_seal reference not installed)")
        return
    v = load("pnx_004_sealed.json")
    for name, vec in ({"clean": v["clean"], "exposure": v["exposure"]} | v["invalid"]).items():
        r, outer = verify_any({"seal": vec["seal"], "query": vec["query"], "proof": vec["proof"]},
                              {k: unhex(x) for k, x in vec["assets_hex"].items()})
        exp = vec["expect"]
        if exp["ok"]:
            case(f"pnx/004 {name}: Seal and PNX proof verify, verdict {exp['verdict']}",
                 r.ok and outer["seal_ok"] and r.verdict == exp["verdict"], "; ".join(r.errors))
        else:
            case(f"pnx/004 invalid/{name} rejected (seal signature {'valid' if exp['seal_signature_ok'] else 'invalid'})",
                 not r.ok and outer["seal_signature_ok"] is exp["seal_signature_ok"] and any(vec["expect_error_contains"] in e for e in r.errors),
                 "; ".join(r.errors) or "accepted")


def fixtures_stream(label: str, n: int) -> bytes:
    """The vectors' byte source, restated here so a port need not import tacet.fixtures."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib_sha256(f"tacet-pnx-fixture:{label}:{i}".encode())
        i += 1
    return out[:n]


if __name__ == "__main__":
    sys.exit(main())
