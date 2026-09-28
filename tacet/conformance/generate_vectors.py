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
from tacet import egress  # noqa: E402
from tacet import fixtures as fx  # noqa: E402
from tacet.canonical import canonicalize  # noqa: E402
from tacet.fixtures import (DISCLOSED_TARGET, DISCLOSURE_EPOCH, MAP_ID, TARGET, build_scenario,  # noqa: E402
                            witness_set)

OUT = HERE / "vectors" / "v1"


def dump(name: str, obj) -> str:
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (OUT / name).write_text(data, encoding="utf-8")
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _resigned(sheet: dict, key) -> dict:
    """A run sheet with its current members, freshly signed by ``key`` (for faults the signature must not hide)."""
    s = {k: v for k, v in sheet.items() if k != "signature"}
    s["signature"] = {"alg": "ed25519", "domain": egress.DOMAIN_SHEET.strip().decode(),
                      "sig_hex": key.sign(egress.DOMAIN_SHEET + canonicalize(s)).hex()}
    return s


def pnx_vectors() -> dict[str, dict]:
    """The four ``pnx_00N`` vectors (PNX.md §9), all derived from ``tacet.fixtures.pnx_stream``."""
    sc = fx.build_pnx_scenario()
    salt = fx.PNX_SALT
    hexes = lambda bs: [b.hex() for b in bs]  # noqa: E731
    hexmap = lambda assets: {label: data.hex() for label, data in assets}  # noqa: E731

    # pnx_001: the fingerprint function, pinned byte for byte.
    kgram_data = fx.pnx_stream("kgrams", 40)
    winnow_data = fx.pnx_stream("winnow", 120)
    short_body = fx.pnx_stream("short-body", 40)
    secret, noise = fx.pnx_stream("secret", egress.THRESHOLD), fx.pnx_stream("noise-g", 100)
    classes = []
    for n in (31, 32, 46, 47, 100):
        a = fx.pnx_stream(f"class-{n}", n)
        klass, fps = egress.asset_fingerprints(a, salt)
        classes.append({"asset_hex": a.hex(), "asset_len": n, "detection": klass, "fingerprints": hexes(fps)})
    json_body = fx.PNX_BODIES[1]["body"]
    p001 = {
        "profile": egress.PROFILE,
        "params": {"k_gram": egress.K_GRAM, "window": egress.WINDOW, "threshold": egress.THRESHOLD, "hash": "sha256"},
        "domains": {"fingerprint": egress.DOMAIN_FINGERPRINT.decode(), "sheet": egress.DOMAIN_SHEET.decode(),
                    "leaf_value": egress.DOMAIN_LEAF_VALUE.decode()},
        "present_leaf_value": egress.PRESENT.hex(),
        "salt_hex": salt.hex(),
        "stream": {"construction": "SHA-256(\"tacet-pnx-fixture:<label>:<i>\") for i = 0, 1, ..., concatenated and truncated to n bytes",
                   "example": {"label": "kgrams", "n": 40, "hex": kgram_data.hex()}},
        "kgram_hashes": {"data_hex": kgram_data.hex(), "hashes": hexes(egress.kgram_hashes(kgram_data, salt))},
        "winnowing": {"data_hex": winnow_data.hex(), "fingerprints": sorted(hexes(egress.fingerprints(winnow_data, salt)))},
        "winnowing_short": {"data_hex": short_body.hex(), "fingerprints": sorted(hexes(egress.fingerprints(short_body, salt))),
                            "note": "fewer k-grams than one window: the single minimum is selected"},
        "detection_classes": classes,
        "guarantee": {"secret_hex": secret.hex(), "noise_hex": noise.hex(), "offsets": list(range(len(noise) + 1)),
                      "secret_fingerprints": sorted(hexes(egress.asset_fingerprints(secret, salt)[1])),
                      "expect": "for every offset o, FP(noise[:o] + secret + noise[o:]) shares at least one fingerprint with the secret"},
        "json_strings": {"body_hex": json_body.hex(), "derived_hex": hexes(egress.json_strings(json_body)),
                         "non_json_body_hex": fx.PNX_BODIES[0]["body"].hex(), "non_json_derived_hex": []},
        "epoch_leaf_key": {"run_id": fx.PNX_RUN_ID, "key": egress.epoch_leaf_key(fx.PNX_RUN_ID).hex()},
    }

    # pnx_002: a witnessed run, its signed sheet, and two proofs against it.
    def expect(proof, assets):
        r = egress.verify_pnx(proof, dict(assets))
        assert r.ok, r.errors
        return {"ok": True, "verdict": r.verdict, "assets": r.assets}
    p002 = {
        "run": {"run_id": fx.PNX_RUN_ID, "salt_hex": salt.hex(), "witness_pubkey_hex": sc.witness_key.public_hex,
                "normalization": [egress.NORMALIZE_JSON_STRINGS],
                "bodies": [{"at": b["at"], "body_hex": b["body"].hex(), "note": b["note"]} for b in fx.PNX_BODIES]},
        "sheet": sc.sheet,
        "proofs": {
            "clean": {"proof": sc.clean, "assets_hex": hexmap(fx.PNX_CLEAN_ASSETS), "expect": expect(sc.clean, fx.PNX_CLEAN_ASSETS)},
            "exposure": {"proof": sc.exposure, "assets_hex": hexmap(fx.PNX_EXPOSURE_ASSETS),
                         "expect": expect(sc.exposure, fx.PNX_EXPOSURE_ASSETS)},
        },
        "hash_only": {"expect": {"ok": True, "warning_contains": "not recomputed"},
                      "note": "without asset bytes a verifier checks the listed keys only and MUST warn"},
    }

    # pnx_003: faults a verifier MUST reject. `hash_only_ok` records what a verifier without the asset bytes
    # can and cannot see: a substituted or dropped fingerprint set is invisible to it, hence the §6 warning.
    invalid: dict[str, dict] = {}

    def fault(name, proof, assets, contains, hash_only_ok=False):
        invalid[name] = {"proof": proof, "assets_hex": hexmap(assets), "expect_error_contains": contains,
                         "hash_only_ok": hash_only_ok}

    bad = copy.deepcopy(sc.clean)
    bad["sheet"]["egress"]["bodies"] = 0
    fault("tampered_sheet", bad, fx.PNX_CLEAN_ASSETS, "witness signature invalid")
    bad = copy.deepcopy(sc.exposure)
    bad["assets"][1]["verdict"] = egress.VERDICT_ABSENT
    fault("forged_asset_verdict", bad, fx.PNX_EXPOSURE_ASSETS, "stated verdict")
    bad = copy.deepcopy(sc.clean)
    bad["verdict"] = egress.VERDICT_PRESENT
    fault("forged_overall_verdict", bad, fx.PNX_CLEAN_ASSETS, "overall verdict")
    bad = copy.deepcopy(sc.clean)
    bad["sheet"] = sc.other_sheet
    fault("foreign_root", bad, fx.PNX_CLEAN_ASSETS, "non-inclusion path invalid")
    bad = copy.deepcopy(sc.exposure)
    next(f for f in bad["assets"][1]["fingerprints"] if f["present"])["present"] = False
    fault("inclusion_relabelled_as_absent", bad, fx.PNX_EXPOSURE_ASSETS, "non-inclusion path invalid")
    fault("wrong_asset_bytes", copy.deepcopy(sc.clean), [("aws_key", fx.pnx_stream("not-the-key", 64)), fx.PNX_CLEAN_ASSETS[1]],
          "does not match asset_sha256", hash_only_ok=True)
    fault("missing_asset_bytes", copy.deepcopy(sc.clean), fx.PNX_CLEAN_ASSETS[:1], "asset bytes not supplied", hash_only_ok=True)
    decoy = sc.witness.prove(sc.sheet, [("decoy", fx.pnx_stream("decoy", 64))])["assets"][0]
    bad = copy.deepcopy(sc.clean)
    bad["assets"][0]["fingerprints"] = decoy["fingerprints"]
    fault("substituted_fingerprints", bad, fx.PNX_CLEAN_ASSETS, "fingerprint set does not match", hash_only_ok=True)
    bad = copy.deepcopy(sc.clean)
    del bad["assets"][1]["fingerprints"][0]
    fault("dropped_fingerprint", bad, fx.PNX_CLEAN_ASSETS, "fingerprint set does not match", hash_only_ok=True)
    bad = copy.deepcopy(sc.clean)
    bad["assets"][0]["detection"] = "partial"
    bad["assets"][0]["verdict"] = egress.VERDICT_ABSENT_PARTIAL
    bad["verdict"] = "mixed"
    fault("understated_detection_class", bad, fx.PNX_CLEAN_ASSETS, "detection class", hash_only_ok=False)
    for name, member, value, contains in (
            ("unknown_normalization", "normalization", ["base64-v1"], "unknown normalization"),
            ("inconsistent_params", "params", {"k_gram": 32, "window": 16, "threshold": 46, "hash": "sha256"}, "inconsistent params"),
            ("wrong_profile", "profile", "crovia.pnx.v0", "unknown profile")):
        bad = copy.deepcopy(sc.clean)
        bad["sheet"] = _resigned({**sc.sheet, member: value}, sc.witness_key)
        fault(name, bad, fx.PNX_CLEAN_ASSETS, contains)
    for name, vec in invalid.items():
        r = egress.verify_pnx(vec["proof"], {k: bytes.fromhex(v) for k, v in vec["assets_hex"].items()})
        assert not r.ok and any(vec["expect_error_contains"] in e for e in r.errors), (name, r.errors)
        assert egress.verify_pnx(vec["proof"]).ok is vec["hash_only_ok"], name
    p003 = invalid

    # pnx_004: delivery as an unmodified crovia.seal.v1, valid and faulty.
    from tacet.pnx import pnx_query, seal_pnx, verify_any  # noqa: E402  (needs crovia_seal)
    from tacet.wrap import TACET_VERSION  # noqa: E402
    nonces = iter("PNXCONFORMANCEVECTOR" + c * 6 for c in "ABCDEFGH")

    def sealed(proof, **kw):
        n = next(nonces)
        return seal_pnx(proof, sc.issuer, tacet_version=TACET_VERSION, emitted_at="2026-09-20T12:00:00.000Z",
                        nonce=n, seal_id=f"cs_2026_{n}", **kw)
    p004 = {
        "clean": {**sealed(sc.clean), "assets_hex": hexmap(fx.PNX_CLEAN_ASSETS),
                  "expect": {"ok": True, "seal_ok": True, "verdict": egress.VERDICT_ABSENT}},
        "exposure": {**sealed(sc.exposure), "assets_hex": hexmap(fx.PNX_EXPOSURE_ASSETS),
                     "expect": {"ok": True, "seal_ok": True, "verdict": egress.VERDICT_PRESENT}},
        "invalid": {},
    }
    bad = copy.deepcopy(sc.exposure)
    bad["assets"][1]["verdict"] = egress.VERDICT_ABSENT
    bad["verdict"] = "mixed"
    p004["invalid"]["forged_verdict_under_valid_seal"] = {**sealed(bad), "assets_hex": hexmap(fx.PNX_EXPOSURE_ASSETS),
                                                          "expect": {"ok": False, "seal_signature_ok": True}, "expect_error_contains": "stated verdict"}
    p004["invalid"]["query_describes_another_proof"] = {**sealed(sc.clean, query=pnx_query(sc.exposure)), "assets_hex": hexmap(fx.PNX_CLEAN_ASSETS),
                                                        "expect": {"ok": False, "seal_signature_ok": True}, "expect_error_contains": "query does not describe"}
    b = sealed(sc.clean)
    b["proof"] = copy.deepcopy(b["proof"])
    b["proof"]["verdict"] = egress.VERDICT_PRESENT
    p004["invalid"]["proof_modified_after_sealing"] = {**b, "assets_hex": hexmap(fx.PNX_CLEAN_ASSETS),
                                                       "expect": {"ok": False, "seal_signature_ok": True}, "expect_error_contains": "output_hash does not bind"}
    b = sealed(sc.clean)
    b["seal"] = copy.deepcopy(b["seal"])
    sig = b["seal"]["signature"]["sig_hex"]
    b["seal"]["signature"]["sig_hex"] = ("1" if sig[0] == "0" else "0") + sig[1:]
    p004["invalid"]["tampered_seal_signature"] = {**b, "assets_hex": hexmap(fx.PNX_CLEAN_ASSETS),
                                                  "expect": {"ok": False, "seal_signature_ok": False}, "expect_error_contains": "signature"}
    for name, vec in ({"clean": p004["clean"], "exposure": p004["exposure"]} | p004["invalid"]).items():
        r, outer = verify_any({"seal": vec["seal"], "query": vec["query"], "proof": vec["proof"]},
                              {k: bytes.fromhex(v) for k, v in vec["assets_hex"].items()})
        assert r.ok is vec["expect"]["ok"], (name, r.errors)
        if "seal_signature_ok" in vec["expect"]:
            assert outer["seal_signature_ok"] is vec["expect"]["seal_signature_ok"], name
            assert any(vec["expect_error_contains"] in e for e in r.errors), (name, r.errors)

    return {"pnx_001_fingerprints.json": p001, "pnx_002_proofs.json": p002, "pnx_003_invalid.json": p003, "pnx_004_sealed.json": p004,
            "pnx_005_reach.json": reach_vector(sc)}


# The connection log of pnx_005 (PNX.md §4a): seven attempts, three destinations
# the policy allows (one through a wildcard, one through a port-less rule), one
# it refuses, one the wildcard must not match (the apex).
REACH_POLICY = {"version": "crovia.pnx.policy.v1",
                "allow": ["api.github.com:443", "*.githubusercontent.com:443", "github.com"]}
REACH_LOG = [
    {"at": "2026-09-20T11:00:05Z", "host": "api.github.com", "port": 443, "ip": "140.82.112.5", "bytes_out": 4000, "bytes_in": 90000},
    {"at": "2026-09-20T11:02:00Z", "host": "API.github.com", "port": 443, "ip": "140.82.112.6", "bytes_out": 200, "bytes_in": 100},
    {"at": "2026-09-20T11:03:00Z", "host": "objects.githubusercontent.com", "port": 443, "ip": "185.199.108.133", "bytes_out": 300, "bytes_in": 700000},
    {"at": "2026-09-20T11:04:00Z", "host": "github.com", "port": 22, "ip": "140.82.121.4", "bytes_out": 1200, "bytes_in": 8000},
    {"at": "2026-09-20T11:05:00Z", "host": "pastebin.com", "port": 443, "bytes_out": 500, "bytes_in": 0},
    {"at": "2026-09-20T11:06:00Z", "host": "githubusercontent.com", "port": 443, "bytes_out": 10, "bytes_in": 0},
    {"at": "2026-09-20T11:07:00Z", "host": "api.github.com", "port": 443, "ip": "140.82.112.5", "bytes_out": 100, "bytes_in": 100},
]


def reach_vector(sc) -> dict:
    """pnx_005: the reach record, valid under every mode and disclosure, and the faults a verifier MUST reject."""
    from tacet import reach as rc  # noqa: E402
    from tacet.pnx import witness_from_state, witness_to_state  # noqa: E402
    policy = rc.Policy.from_json(REACH_POLICY)
    key, salt = sc.witness_key, fx.PNX_SALT

    def log(mode, policy_=policy, explicit=None):
        lg = rc.ReachLog(capture="proxy-connect", policy=policy_, mode=mode)
        for a in REACH_LOG:
            lg.attempt(a["host"], a["port"], a["at"], explicit, bytes_out=a["bytes_out"], bytes_in=a["bytes_in"], ip=a.get("ip"))
        return lg

    def sheet_with(record):
        # The same run as pnx_002 (same bodies, same salt, same root), plus the record.
        w = witness_from_state(witness_to_state(sc.witness))
        w.reach = record
        return w.sheet(key, fx.PNX_CLOSED_AT)

    def expect(sheet, with_policy, names=()):
        r = egress.verify_sheet(sheet)
        assert r == [], r
        rr = rc.verify_reach(sheet["reach"], salt, policy if with_policy else None, names)
        assert rr.ok, rr.errors
        return {"ok": True, "verdict": rr.verdict, "outside": rr.outside, "reached": rr.reached,
                "warning_contains": rr.warnings[0].split(":")[0] if rr.warnings else None}

    enforce, observe, salted, none = (sheet_with(log("enforce").record(salt)), sheet_with(log("observe").record(salt)),
                                      sheet_with(log("enforce").record(salt, "salted")), sheet_with(log("observe", None).record(salt)))
    names = ["api.github.com", "pastebin.com", "example.org"]
    valid = {
        "enforce": {"sheet": enforce, "expect_with_policy": expect(enforce, True), "expect_without_policy": expect(enforce, False)},
        "observe": {"sheet": observe, "expect_with_policy": expect(observe, True), "expect_without_policy": expect(observe, False)},
        "salted": {"sheet": salted, "names": names, "expect_with_policy": expect(salted, True, names),
                   "expect_without_policy": expect(salted, False, names)},
        "none": {"sheet": none, "expect_with_policy": expect(none, True), "expect_without_policy": expect(none, False)},
    }
    assert valid["observe"]["expect_with_policy"]["verdict"] == rc.VERDICT_OUTSIDE
    assert valid["observe"]["expect_with_policy"]["outside"] == ["githubusercontent.com:443", "pastebin.com:443"]
    assert valid["salted"]["expect_with_policy"]["reached"] == {"api.github.com": True, "pastebin.com": True, "example.org": False}

    # Faults. Each is re-signed so the signature does not hide it, except the last, where it must.
    invalid: dict[str, dict] = {}

    def fault(name, sheet, contains, *, with_policy=True, resign=True):
        s = _resigned(sheet, key) if resign else sheet
        errs = egress.verify_sheet(s)
        if not errs and with_policy:
            errs = rc.verify_reach(s["reach"], salt, policy).errors
        assert any(contains in e for e in errs), (name, errs)
        invalid[name] = {"sheet": s, "with_policy": with_policy, "expect_error_contains": contains}

    def mutated(base, fn):
        s = copy.deepcopy(base)
        fn(s["reach"])
        return s

    def fix_summary(r):
        r["summary"] = rc.summarize(r["destinations"])

    fault("unsorted_destinations", mutated(enforce, lambda r: r["destinations"].reverse()), "not sorted", with_policy=False)
    fault("duplicate_destination", mutated(enforce, lambda r: (r["destinations"].append(copy.deepcopy(r["destinations"][-1])), fix_summary(r))),
          "duplicate destination", with_policy=False)
    fault("wrong_summary", mutated(enforce, lambda r: r["summary"].__setitem__("allowed", 9)), "summary does not match", with_policy=False)
    fault("unknown_capture", mutated(enforce, lambda r: r.__setitem__("capture", "telepathy")), "unknown capture", with_policy=False)
    fault("unknown_outcome", mutated(enforce, lambda r: r["destinations"][0].__setitem__("outcome", "maybe")), "unknown outcome", with_policy=False)
    fault("blocked_without_policy", mutated(none, lambda r: (r["destinations"][4].__setitem__("outcome", "blocked"),
                                                             r["destinations"][4].__setitem__("bytes_out", 0), fix_summary(r))),
          "blocked without a policy", with_policy=False)
    fault("host_under_salted", mutated(salted, lambda r: r["destinations"][0].__setitem__("host", "api.github.com")),
          "not allowed under salted", with_policy=False)
    other = copy.deepcopy(enforce)
    other["reach"]["policy"]["hash"] = "sha256:" + "00" * 32
    fault("policy_hash_mismatch", other, "does not match the record")
    fault("blocked_destination_the_policy_allows", mutated(enforce, lambda r: (r["destinations"][0].__setitem__("outcome", "blocked"),
                                                                                 r["destinations"][0].__setitem__("bytes_out", 0),
                                                                                 r["destinations"][0].__setitem__("bytes_in", 0), fix_summary(r))),
          "inconsistent witness")
    fault("tampered_record_unchanged_signature", mutated(enforce, lambda r: (r["destinations"][4].__setitem__("outcome", "allowed"), fix_summary(r))),
          "witness signature invalid", with_policy=False, resign=False)

    # A draft 0.3 verifier (signature and params only) accepts every valid sheet: the record is a member like any other.
    for v in valid.values():
        s = v["sheet"]
        assert egress.verify_signature(s["witness"]["pubkey"]["key_hex"], egress.DOMAIN_SHEET + canonicalize(egress._unsigned(s)),
                                       bytes.fromhex(s["signature"]["sig_hex"]))
    return {
        "profile": egress.PROFILE, "reach_version": rc.REACH_VERSION, "policy_version": rc.POLICY_VERSION,
        "domain_reach": rc.DOMAIN_REACH.decode(),
        "policy": {"document": REACH_POLICY, "hash": policy.hash, "rules": len(policy.allow)},
        "log": REACH_LOG,
        "host_hashes": {n: rc.host_hash(salt, n) for n in names},
        "valid": valid, "invalid": invalid,
        "note": "every valid sheet has the root of pnx_002 (same bodies, same salt); a verifier of draft 0.3 accepts them all",
    }


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

    # 5b. The same invalid proofs under a *valid* outer Seal: a verifier that stops at the
    # Seal signature would accept these; a conformant one must reject every case.
    wrapped_invalid = {}
    for i, (name, vec) in enumerate(sorted(invalid.items())):
        p = vec["proof"]
        qi = build_query(map_id=MAP_ID, target_id=p["target_id"], from_epoch=p["from_epoch"], to_epoch=p["to_epoch"],
                         min_strength=p["strength"])
        b = wrap_in_seal(issuer=sc.issuer, query=qi, proof=p, emitted_at="2026-09-19T12:00:00.000Z",
                         nonce=f"TACETCONFORMANCEINVALID{'ABCDEFGH'[i]}AA", seal_id=f"cs_2026_TACETCONFORMANCEINVALID{'ABCDEFGH'[i]}AA")
        wrapped_invalid[name] = {**b, "expect": {"ok": False, "seal_ok": True}, "expect_error_contains": vec["expect_error_contains"]}
    index["files"]["wrapped_002_invalid.json"] = dump("wrapped_002_invalid.json", wrapped_invalid)

    # 6. Disclosed target: silence provable only before the disclosure epoch.
    pb = build_silence_proof(map_id=MAP_ID, target_id=DISCLOSED_TARGET, sheets=sc.sheets[:DISCLOSURE_EPOCH],
                             paths={e: sc.disclosed_paths[e] for e in range(DISCLOSURE_EPOCH)})
    index["files"]["silence_004_before_disclosure.json"] = dump("silence_004_before_disclosure.json", {
        "proof": pb, "disclosure_epoch": DISCLOSURE_EPOCH,
        "paths_after_disclosure": {str(e): sc.disclosed_paths[e].to_json() for e in range(DISCLOSURE_EPOCH, 12)},
        "expect": {"ok": True, "non_inclusion_after_disclosure": False},
    })

    # 7. PNX profile (crovia.pnx.v1): fingerprinting primitives, proofs, faults, sealed delivery.
    for name, obj in pnx_vectors().items():
        index["files"][name] = dump(name, obj)

    # 8. Static vectors captured from the live log (real Bitcoin anchors); indexed, never regenerated.
    for static in ("ots_001_live_anchors.json",):
        f = OUT / static
        if f.exists():
            index["files"][static] = hashlib.sha256(f.read_bytes()).hexdigest()

    dump("index.json", index)
    print(f"wrote {len(index['files']) + 1} files to {OUT}")


if __name__ == "__main__":
    main()
