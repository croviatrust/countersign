"""Epoch sheets: signed map heads with temporal bounds (SPEC §6)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .canonical import canonicalize
from .hashing import DOMAIN_EPOCH, DOMAIN_WITNESS, prefixed, sha256, unprefixed
from .keys import SigningKey, verify_signature

SHEET_VERSION = "crovia.tacet.epoch.v1"
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UNSIGNED_EXCLUDED = ("signature", "closed")


class SheetError(ValueError):
    """An epoch sheet is malformed or its signature/chain does not verify."""


def _signed_region(sheet: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in sheet.items() if k not in _UNSIGNED_EXCLUDED}


def sheet_hash(sheet: Dict[str, Any]) -> bytes:
    """H(CSC-1(sheet minus signature and closed))."""
    return sha256(canonicalize(_signed_region(sheet)))


def build_sheet(
    *,
    operator: SigningKey,
    map_id: str,
    epoch: int,
    epoch_start: str,
    epoch_end: str,
    root: bytes,
    size: int,
    prev_sheet_hash: Optional[bytes],
    opened: Dict[str, Any],
    snapshots_root: bytes,
) -> Dict[str, Any]:
    sheet: Dict[str, Any] = {
        "sheet_version": SHEET_VERSION,
        "map_id": map_id,
        "epoch": epoch,
        "epoch_start": epoch_start,
        "epoch_end": epoch_end,
        "root": prefixed(root),
        "prev_sheet_hash": prefixed(prev_sheet_hash) if prev_sheet_hash else None,
        "size": size,
        "opened": opened,
        "snapshots_root": prefixed(snapshots_root),
        "operator": {"id": operator.id, "pubkey": operator.pubkey_json()},
    }
    sig = operator.sign(DOMAIN_EPOCH + canonicalize(sheet))
    sheet["signature"] = {"alg": "ed25519", "domain": "TACET-EPOCH-v1", "sig_hex": sig.hex()}
    sheet["closed"] = {"kind": "ots", "status": "pending", "anchored_digest": prefixed(sheet_hash(sheet))}
    return sheet


def close_sheet(sheet: Dict[str, Any], *, block_height: int, proof_ref: str, block_time: str) -> Dict[str, Any]:
    """Record the Bitcoin confirmation of the sheet hash (outside the signed region)."""
    if unprefixed(sheet["closed"]["anchored_digest"]) != sheet_hash(sheet):
        raise SheetError("closed.anchored_digest does not match sheet_hash")
    sheet["closed"] = {
        "kind": "ots",
        "status": "bitcoin",
        "anchored_digest": sheet["closed"]["anchored_digest"],
        "block_height": block_height,
        "block_time": block_time,
        "proof_ref": proof_ref,
    }
    return sheet


def validate_sheet(sheet: Dict[str, Any]) -> None:
    """Structural and signature validation of a single sheet (SPEC §8.5 step 1, per sheet)."""
    if not isinstance(sheet, dict) or sheet.get("sheet_version") != SHEET_VERSION:
        raise SheetError("sheet_version must be crovia.tacet.epoch.v1")
    required = {"sheet_version", "map_id", "epoch", "epoch_start", "epoch_end", "root", "prev_sheet_hash",
                "size", "opened", "snapshots_root", "operator", "signature", "closed"}
    missing = required - set(sheet)
    extra = set(sheet) - required
    if missing or extra:
        raise SheetError(f"sheet fields: missing={sorted(missing)} extra={sorted(extra)}")
    if not isinstance(sheet["epoch"], int) or isinstance(sheet["epoch"], bool) or sheet["epoch"] < 0:
        raise SheetError("epoch must be a non-negative integer")
    for f in ("epoch_start", "epoch_end"):
        if not isinstance(sheet[f], str) or not _RFC3339.match(sheet[f]):
            raise SheetError(f"{f} must be RFC 3339 UTC seconds")
    if sheet["epoch_end"] <= sheet["epoch_start"]:
        raise SheetError("epoch_end must be after epoch_start")
    unprefixed(sheet["root"])
    unprefixed(sheet["snapshots_root"])
    if sheet["prev_sheet_hash"] is not None:
        unprefixed(sheet["prev_sheet_hash"])
    if not isinstance(sheet["size"], int) or sheet["size"] < 0:
        raise SheetError("size must be a non-negative integer")
    opened = sheet["opened"]
    if not isinstance(opened, dict) or opened.get("kind") != "drand":
        raise SheetError("opened must be a drand beacon object")
    for k in ("chain_hash", "round", "randomness", "signature"):
        if k not in opened:
            raise SheetError(f"opened.{k} is required")
    if not isinstance(opened["round"], int) or opened["round"] < 1:
        raise SheetError("opened.round must be a positive integer")
    op = sheet["operator"]
    if not isinstance(op, dict) or set(op) != {"id", "pubkey"} or set(op["pubkey"]) != {"alg", "key_hex"}:
        raise SheetError("operator must be {id, pubkey{alg,key_hex}}")
    sig = sheet["signature"]
    if not isinstance(sig, dict) or set(sig) != {"alg", "domain", "sig_hex"} or sig["domain"] != "TACET-EPOCH-v1":
        raise SheetError("signature must be {alg, domain='TACET-EPOCH-v1', sig_hex}")
    if not verify_signature(op["pubkey"]["key_hex"], DOMAIN_EPOCH + canonicalize(_signed_region(sheet)),
                            bytes.fromhex(sig["sig_hex"])):
        raise SheetError(f"operator signature invalid for epoch {sheet['epoch']}")
    closed = sheet["closed"]
    if not isinstance(closed, dict) or closed.get("kind") != "ots" or closed.get("status") not in ("pending", "bitcoin"):
        raise SheetError("closed must be an ots object with status pending|bitcoin")
    if unprefixed(closed["anchored_digest"]) != sheet_hash(sheet):
        raise SheetError("closed.anchored_digest does not match sheet_hash")
    if closed["status"] == "bitcoin":
        for k in ("block_height", "block_time", "proof_ref"):
            if k not in closed:
                raise SheetError(f"closed.{k} required when status is bitcoin")


def validate_chain(sheets: list) -> None:
    """Sheets must be contiguous in epoch, share map_id and operator, and chain by hash."""
    if not sheets:
        raise SheetError("empty sheet range")
    for s in sheets:
        validate_sheet(s)
    for prev, cur in zip(sheets, sheets[1:], strict=False):
        if cur["map_id"] != prev["map_id"]:
            raise SheetError("map_id changes inside the range")
        if cur["epoch"] != prev["epoch"] + 1:
            raise SheetError(f"epoch gap between {prev['epoch']} and {cur['epoch']}")
        if cur["prev_sheet_hash"] is None or unprefixed(cur["prev_sheet_hash"]) != sheet_hash(prev):
            raise SheetError(f"prev_sheet_hash of epoch {cur['epoch']} does not match epoch {prev['epoch']}")
        if cur["epoch_start"] < prev["epoch_end"]:
            raise SheetError(f"epoch {cur['epoch']} starts before epoch {prev['epoch']} ends")


def witness_sign(witness: SigningKey, sheet: Dict[str, Any]) -> Dict[str, Any]:
    sig = witness.sign(DOMAIN_WITNESS + sheet_hash(sheet))
    return {"id": witness.id, "pubkey": witness.pubkey_json(), "sig_hex": sig.hex()}


def witness_verify(entry: Dict[str, Any], sheet: Dict[str, Any]) -> bool:
    try:
        return verify_signature(entry["pubkey"]["key_hex"], DOMAIN_WITNESS + sheet_hash(sheet),
                                bytes.fromhex(entry["sig_hex"]))
    except (KeyError, ValueError, TypeError):
        return False
