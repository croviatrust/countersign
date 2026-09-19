"""Surface snapshots with published predicates (SPEC §7)."""
from __future__ import annotations

from typing import Any, Dict, Optional

from .canonical import canonicalize
from .hashing import DOMAIN_SNAPSHOT, prefixed, sha256
from .keys import SigningKey, verify_signature

SNAPSHOT_VERSION = "crovia.tacet.snapshot.v1"


class SnapshotError(ValueError):
    """A snapshot is malformed or its signature does not verify."""


def _unsigned(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in snapshot.items() if k != "signature"}


def snapshot_hash(snapshot: Dict[str, Any]) -> bytes:
    return sha256(DOMAIN_SNAPSHOT + canonicalize(_unsigned(snapshot)))


def build_snapshot(
    *,
    observer: SigningKey,
    target_id: str,
    surface_url: str,
    fetched_at: str,
    epoch: int,
    beacon_round: int,
    http_status: int,
    body: bytes,
    predicate_id: str,
    predicate_version: str,
    predicate_code_hash: bytes,
    result: bool,
    tls_cert_sha256: Optional[bytes] = None,
    resolved_ip: Optional[str] = None,
) -> Dict[str, Any]:
    snap: Dict[str, Any] = {
        "snapshot_version": SNAPSHOT_VERSION,
        "target_id": target_id,
        "surface_url": surface_url,
        "fetched_at": fetched_at,
        "epoch": epoch,
        "beacon_round": beacon_round,
        "http_status": http_status,
        "body_sha256": prefixed(sha256(body)),
        "body_len": len(body),
        "tls_cert_sha256": prefixed(tls_cert_sha256) if tls_cert_sha256 else None,
        "resolved_ip": resolved_ip,
        "predicate": {"id": predicate_id, "version": predicate_version, "code_hash": prefixed(predicate_code_hash)},
        "result": result,
        "observer": {"id": observer.id, "pubkey": observer.pubkey_json()},
    }
    sig = observer.sign(DOMAIN_SNAPSHOT + canonicalize(snap))
    snap["signature"] = {"alg": "ed25519", "domain": "TACET-SNAPSHOT-v1", "sig_hex": sig.hex()}
    return snap


def validate_snapshot(snapshot: Dict[str, Any]) -> None:
    if not isinstance(snapshot, dict) or snapshot.get("snapshot_version") != SNAPSHOT_VERSION:
        raise SnapshotError("snapshot_version must be crovia.tacet.snapshot.v1")
    required = {"snapshot_version", "target_id", "surface_url", "fetched_at", "epoch", "beacon_round",
                "http_status", "body_sha256", "body_len", "tls_cert_sha256", "resolved_ip", "predicate",
                "result", "observer", "signature"}
    if set(snapshot) != required:
        raise SnapshotError(f"snapshot fields must be exactly {sorted(required)}")
    if not isinstance(snapshot["result"], bool):
        raise SnapshotError("result must be boolean")
    pred = snapshot["predicate"]
    if not isinstance(pred, dict) or set(pred) != {"id", "version", "code_hash"}:
        raise SnapshotError("predicate must be {id, version, code_hash}")
    obs = snapshot["observer"]
    sig = snapshot["signature"]
    try:
        ok = verify_signature(obs["pubkey"]["key_hex"], DOMAIN_SNAPSHOT + canonicalize(_unsigned(snapshot)),
                              bytes.fromhex(sig["sig_hex"]))
    except (KeyError, ValueError, TypeError) as e:
        raise SnapshotError(f"snapshot signature unreadable: {e}") from e
    if not ok:
        raise SnapshotError("observer signature invalid")
