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

BeaconCheck = Callable[[Dict[str, Any], str], bool]
OtsCheck = Callable[[Dict[str, Any], bytes], bool]


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
    """Silence accrues only across maximal runs of consecutive anchored epochs with a negative snapshot."""
    by_epoch = {s["epoch"]: s for s in sheets}
    total_seconds = 0
    run_start: Optional[int] = None
    ordered = [s["epoch"] for s in sheets]
    for i, e in enumerate(ordered):
        observed = e in observed_epochs
        if observed and run_start is None:
            run_start = e
        last = i == len(ordered) - 1
        if run_start is not None and (not observed or last):
            run_end = e if observed else ordered[i - 1]
            total_seconds += int((_ts(by_epoch[run_end]["epoch_end"]) - _ts(by_epoch[run_start]["epoch_start"])).total_seconds())
            run_start = None
    obs_sorted = sorted(observed_epochs)
    return {
        "map_epochs": len(sheets),
        "observed_epochs": len(observed_epochs),
        "observed_from": by_epoch[obs_sorted[0]]["epoch_start"] if obs_sorted else None,
        "observed_to": by_epoch[obs_sorted[-1]]["epoch_end"] if obs_sorted else None,
        "silence_seconds": total_seconds,
        "silence_days": f"{total_seconds / 86400:.2f}",
    }


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
    """Verify a silence proof offline.

    `beacon_check(opened, epoch_start)` and `ots_check(closed, sheet_hash)` are
    optional hooks for external temporal verification (drand chain and
    OpenTimestamps). When absent, the structural checks still run and the
    result carries a warning that temporal bounds were not externally verified.
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
    for s in sheets:
        if beacon_check is not None and not beacon_check(s["opened"], s["epoch_start"]):
            errors.append(f"epoch {s['epoch']}: beacon check failed")
        if s["closed"]["status"] == "bitcoin":
            if ots_check is not None and not ots_check(s["closed"], sheet_hash(s)):
                errors.append(f"epoch {s['epoch']}: OTS check failed")
            else:
                anchored.add(s["epoch"])
    if beacon_check is None:
        warnings.append("beacon rounds not externally verified (no beacon_check provided)")
    if ots_check is None:
        warnings.append("Bitcoin anchors not externally verified (no ots_check provided)")
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
