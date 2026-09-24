"""Silence proofs: delta-encoded non-inclusion chains with the monotonicity rule (SPEC §8)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import merkle
from .epoch import SheetError, sheet_hash, validate_chain, witness_verify
from .hashing import DEPTH, EMPTY, prefixed, target_key, unprefixed
from .smt import CompactPath, root_from_path
from .snapshot import SnapshotError, snapshot_hash, validate_snapshot

PROOF_VERSION = "crovia.tacet.silence.v1"
QUERY_VERSION = "crovia.tacet.query.v1"

STRENGTH_MAP = 1
STRENGTH_SURFACE = 2
STRENGTH_WITNESSED = 3

# beacon_check(opened, epoch_start): True (round fully verified: chain, schedule and the round's
# bytes, either by a BLS check against the chain key or by comparison with a drand relay),
# False (wrong chain, round off the epoch start, or bytes that are not the chain's), or None
# (chain and schedule verified, bytes not checked: no BLS implementation and no relay reachable).
BeaconCheck = Callable[[Dict[str, Any], str], Optional[bool]]
# Returns True (anchor verified), False (anchor wrong) or None (could not be checked: no header source).
OtsCheck = Callable[[Dict[str, Any], bytes], Optional[bool]]


def epoch_ranges(epochs: Sequence[int]) -> str:
    """'0-5, 9, 12-13' for a list of epoch numbers (warnings stay readable over long ranges)."""
    out: List[str] = []
    for e in sorted(set(epochs)):
        if out and e == out[-1][1] + 1:
            out[-1][1] = e
        else:
            out.append([e, e])
    return ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in out)


class SilenceProofError(ValueError):
    """A silence proof is malformed or does not verify."""


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Delta encoding of consecutive paths
# ---------------------------------------------------------------------------

def encode_deltas(paths: Sequence[CompactPath], epochs: Sequence[int]) -> Dict[str, Any]:
    if len(paths) != len(epochs) or not paths:
        raise ValueError("paths and epochs must be non-empty and aligned")
    initial = paths[0].to_json()
    deltas: List[Dict[str, Any]] = []
    prev = paths[0].to_full()
    for path, epoch in zip(paths[1:], epochs[1:], strict=True):
        cur = path.to_full()
        changed = [[h, None if cur[h] == EMPTY[h] else cur[h].hex()]
                   for h in range(DEPTH) if cur[h] != prev[h]]
        deltas.append({"epoch": epoch, "changed": changed})
        prev = cur
    return {"initial": initial, "deltas": deltas}


def decode_paths(encoded: Dict[str, Any], epochs: Sequence[int]) -> List[List[bytes]]:
    full = CompactPath.from_json(encoded["initial"]).to_full()
    out = [list(full)]
    deltas = encoded.get("deltas", [])
    if len(deltas) != len(epochs) - 1:
        raise SilenceProofError("number of deltas must be number of epochs minus one")
    for delta, epoch in zip(deltas, epochs[1:], strict=True):
        if delta.get("epoch") != epoch:
            raise SilenceProofError(f"delta epoch {delta.get('epoch')} does not match sheet epoch {epoch}")
        for h, value in delta["changed"]:
            if not isinstance(h, int) or not 0 <= h < DEPTH:
                raise SilenceProofError("delta height out of range")
            full[h] = EMPTY[h] if value is None else bytes.fromhex(value)
        out.append(list(full))
    return out


# ---------------------------------------------------------------------------
# Silence computation (SPEC §8.4)
# ---------------------------------------------------------------------------

def compute_silence(sheets: Sequence[Dict[str, Any]], observed_epochs: set) -> Dict[str, Any]:
    """Silence is the sum of the durations of anchored epochs that carry a negative snapshot.

    Epochs are contiguous hourly windows in normal operation, so this equals the
    end-minus-start of each run of observed epochs; when sheets are separated by
    a time gap (operator downtime) the gap is not counted, because no epoch
    covers it.
    """
    by_epoch = {s["epoch"]: s for s in sheets}
    total_seconds = 0
    for e in observed_epochs:
        s = by_epoch.get(e)
        if s is None:
            continue
        total_seconds += int((_ts(s["epoch_end"]) - _ts(s["epoch_start"])).total_seconds())
    obs_sorted = sorted(observed_epochs)
    return {
        "map_epochs": len(sheets),
        "observed_epochs": len(observed_epochs),
        "observed_from": by_epoch[obs_sorted[0]]["epoch_start"] if obs_sorted else None,
        "observed_to": by_epoch[obs_sorted[-1]]["epoch_end"] if obs_sorted else None,
        "silence_seconds": total_seconds,
        "silence_days": format_silence_days(total_seconds),
    }


def format_silence_days(silence_seconds: int) -> str:
    """SPEC §9: two decimals, truncated (never rounded up), integer arithmetic only."""
    cents = (int(silence_seconds) * 100) // 86400
    return f"{cents // 100}.{cents % 100:02d}"


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def build_silence_proof(
    *,
    map_id: str,
    target_id: str,
    sheets: Sequence[Dict[str, Any]],
    paths: Dict[int, CompactPath],
    epoch_snapshot_hashes: Optional[Dict[int, List[bytes]]] = None,
    negative_snapshots: Sequence[Dict[str, Any]] = (),
    witnesses: Optional[Dict[int, List[Dict[str, Any]]]] = None,
    witness_set: Optional[Dict[str, Any]] = None,
    strength: int = STRENGTH_MAP,
) -> Dict[str, Any]:
    """Assemble a silence proof for `target_id` over the given contiguous sheets."""
    sheets = sorted(sheets, key=lambda s: s["epoch"])
    validate_chain(list(sheets))
    epochs = [s["epoch"] for s in sheets]
    key = target_key(target_id)
    ordered_paths = [paths[e] for e in epochs]
    for s, p in zip(sheets, ordered_paths, strict=True):
        if root_from_path(key, EMPTY[0], p.to_full()) != unprefixed(s["root"]):
            raise SilenceProofError(f"path for epoch {s['epoch']} is not a non-inclusion proof against the sheet root")

    proof: Dict[str, Any] = {
        "proof_version": PROOF_VERSION,
        "map_id": map_id,
        "target_id": target_id,
        "key": key.hex(),
        "from_epoch": epochs[0],
        "to_epoch": epochs[-1],
        "strength": strength,
        "sheets": list(sheets),
        "paths": encode_deltas(ordered_paths, epochs),
        "snapshots": [],
        "witnesses": {},
    }

    observed: set = set()
    if strength >= STRENGTH_SURFACE:
        if epoch_snapshot_hashes is None:
            raise ValueError("strength >= 2 requires epoch_snapshot_hashes")
        anchored = {s["epoch"] for s in sheets if s["closed"]["status"] == "bitcoin"}
        for snap in negative_snapshots:
            e = snap["epoch"]
            if e not in epoch_snapshot_hashes or snap["target_id"] != target_id or snap["result"] is not False:
                continue
            hashes = epoch_snapshot_hashes[e]
            h = snapshot_hash(snap)
            index = hashes.index(h)
            proof["snapshots"].append({
                "snapshot": snap,
                "index": index,
                "size": len(hashes),
                "path": [x.hex() for x in merkle.inclusion_path(hashes, index)],
            })
            if e in anchored:
                observed.add(e)
    if strength >= STRENGTH_WITNESSED:
        if not witnesses or not witness_set:
            raise ValueError("strength 3 requires witnesses and witness_set {k, n, ids}")
        proof["witness_set"] = witness_set
        for s in sheets:
            proof["witnesses"][prefixed(sheet_hash(s))] = list(witnesses.get(s["epoch"], []))

    proof["silence"] = compute_silence(sheets, observed)
    return proof


def build_query(*, map_id: str, target_id: str, from_epoch: int, to_epoch: int, min_strength: int) -> Dict[str, Any]:
    return {"query_version": QUERY_VERSION, "map_id": map_id, "target_id": target_id,
            "from_epoch": from_epoch, "to_epoch": to_epoch, "min_strength": min_strength}


# ---------------------------------------------------------------------------
# Verification (SPEC §8.5)
# ---------------------------------------------------------------------------

@dataclass
class SilenceVerifyResult:
    ok: bool
    strength_claimed: int
    strength_verified: int
    silence: Dict[str, Any] = field(default_factory=dict)
    anchored_epochs: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def verify_silence_proof(
    proof: Dict[str, Any],
    *,
    beacon_check: Optional[BeaconCheck] = None,
    ots_check: Optional[OtsCheck] = None,
    expected_operator_pubkey_hex: Optional[str] = None,
) -> SilenceVerifyResult:
    """Verify a silence proof.

    Everything about the proof's own bytes is checked here, offline: operator
    signatures, sheet chaining, non-inclusion under every root, observer
    signatures and inclusion of every negative snapshot, the silence figure,
    witness quorum. The two temporal bounds are external facts and go through
    hooks: `beacon_check(opened, epoch_start)` for the drand round and
    `ots_check(closed, sheet_hash)` for the Bitcoin anchor. Each hook returns
    True, False or None (could not be checked). A False is an error; a None is
    reported in `warnings` naming the epochs; an absent hook is reported in
    `warnings` too. Without hooks this function does not verify that the round
    bytes are the chain's or that the anchor sits in a Bitcoin block: it takes
    both as claimed and says so.
    """
    errors: List[str] = []
    warnings: List[str] = []
    claimed = int(proof.get("strength", 0))
    result = SilenceVerifyResult(ok=False, strength_claimed=claimed, strength_verified=0)

    if proof.get("proof_version") != PROOF_VERSION:
        result.errors.append("proof_version must be crovia.tacet.silence.v1")
        return result
    if claimed not in (STRENGTH_MAP, STRENGTH_SURFACE, STRENGTH_WITNESSED):
        result.errors.append("strength must be 1, 2 or 3")
        return result

    sheets = proof.get("sheets", [])
    try:
        validate_chain(sheets)
    except SheetError as e:
        result.errors.append(f"sheets: {e}")
        return result
    if sheets[0]["epoch"] != proof.get("from_epoch") or sheets[-1]["epoch"] != proof.get("to_epoch"):
        errors.append("from_epoch/to_epoch do not match the sheet range")
    if any(s["map_id"] != proof.get("map_id") for s in sheets):
        errors.append("map_id does not match sheets")
    operator_keys = {s["operator"]["pubkey"]["key_hex"] for s in sheets}
    if len(operator_keys) != 1:
        errors.append("operator key changes inside the range")
    if expected_operator_pubkey_hex and operator_keys != {expected_operator_pubkey_hex}:
        errors.append("operator key is not the expected one")

    # Temporal bounds.
    anchored: set = set()
    unchecked: List[int] = []
    beacon_unchecked: List[int] = []
    for s in sheets:
        if beacon_check is not None:
            verdict = beacon_check(s["opened"], s["epoch_start"])
            if verdict is False:
                errors.append(f"epoch {s['epoch']}: beacon check failed")
            elif verdict is None:
                beacon_unchecked.append(s["epoch"])
        if s["closed"]["status"] == "bitcoin":
            verdict = ots_check(s["closed"], sheet_hash(s)) if ots_check is not None else None
            if verdict is False:
                errors.append(f"epoch {s['epoch']}: OTS check failed")
            else:
                if verdict is None and ots_check is not None:
                    unchecked.append(s["epoch"])
                anchored.add(s["epoch"])
    if beacon_check is None:
        warnings.append("drand rounds taken as claimed: chain, schedule and round bytes not verified (no beacon_check provided)")
    elif beacon_unchecked:
        warnings.append(f"drand round bytes unchecked for epoch(s) {epoch_ranges(beacon_unchecked)}: chain and schedule "
                        "verified from the sheets, no BLS check and no drand relay consulted")
    if ots_check is None:
        warnings.append("Bitcoin anchors not externally verified (no ots_check provided)")
    elif unchecked:
        warnings.append(f"Bitcoin anchors unchecked for epoch(s) {epoch_ranges(unchecked)}: .ots proof or block header not obtained")
    result.anchored_epochs = len(anchored)

    # Non-inclusion in every epoch.
    key = bytes.fromhex(proof["key"])
    if key != target_key(proof["target_id"]):
        errors.append("key does not match target_id")
    epochs = [s["epoch"] for s in sheets]
    try:
        full_paths = decode_paths(proof["paths"], epochs)
    except (SilenceProofError, KeyError, ValueError) as e:
        result.errors = errors + [f"paths: {e}"]
        return result
    for s, path in zip(sheets, full_paths, strict=True):
        if root_from_path(key, EMPTY[0], path) != unprefixed(s["root"]):
            errors.append(f"epoch {s['epoch']}: slot is not empty (non-inclusion fails)")
    verified = STRENGTH_MAP if not errors else 0

    # Surface silence.
    observed: set = set()
    if claimed >= STRENGTH_SURFACE and verified >= STRENGTH_MAP:
        by_epoch = {s["epoch"]: s for s in sheets}
        for entry in proof.get("snapshots", []):
            snap = entry.get("snapshot", {})
            try:
                validate_snapshot(snap)
            except SnapshotError as e:
                errors.append(f"snapshot: {e}")
                continue
            e = snap["epoch"]
            sheet = by_epoch.get(e)
            if sheet is None:
                errors.append(f"snapshot for epoch {e} outside the range")
                continue
            if snap["target_id"] != proof["target_id"] or snap["result"] is not False:
                errors.append(f"epoch {e}: snapshot is not a negative snapshot of the target")
                continue
            if snap["beacon_round"] != sheet["opened"]["round"]:
                errors.append(f"epoch {e}: snapshot beacon_round does not match the epoch's opened.round")
                continue
            if not merkle.verify_inclusion(unprefixed(sheet["snapshots_root"]), snapshot_hash(snap),
                                           entry["index"], entry["size"], [bytes.fromhex(x) for x in entry["path"]]):
                errors.append(f"epoch {e}: snapshot not included under snapshots_root")
                continue
            if e in anchored:
                observed.add(e)
        expected_silence = compute_silence(sheets, observed)
        if proof.get("silence") != expected_silence:
            errors.append("silence block does not match recomputation under the monotonicity rule")
        if not errors:
            verified = STRENGTH_SURFACE
        result.silence = expected_silence
    else:
        result.silence = compute_silence(sheets, set())
        if claimed == STRENGTH_MAP and proof.get("silence") != result.silence:
            errors.append("silence block of a level-1 proof must report zero observed epochs")

    # Witnessed silence.
    if claimed >= STRENGTH_WITNESSED and verified >= STRENGTH_SURFACE:
        ws = proof.get("witness_set") or {}
        k, n, ids = ws.get("k"), ws.get("n"), set(ws.get("ids", []))
        if not isinstance(k, int) or not isinstance(n, int) or k < 1 or k > n or len(ids) != n:
            errors.append("witness_set must be {k, n, ids} with 1 <= k <= n == len(ids)")
        else:
            for s in sheets:
                entries = proof.get("witnesses", {}).get(prefixed(sheet_hash(s)), [])
                valid = {w["id"] for w in entries if w.get("id") in ids and witness_verify(w, s)}
                if len(valid) < k:
                    errors.append(f"epoch {s['epoch']}: {len(valid)} valid witness signatures, need {k}")
        if not errors:
            verified = STRENGTH_WITNESSED

    result.errors = errors
    result.warnings = warnings
    result.strength_verified = verified
    result.ok = not errors and verified >= claimed
    return result
