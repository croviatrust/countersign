"""Build and verify silence proofs from operator state (SPEC §8, §10)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from tacet.hashing import target_key
from tacet.keys import SigningKey
from tacet.silence import STRENGTH_SURFACE, build_query, build_silence_proof
from tacet.snapshot import snapshot_hash
from tacet.wrap import verify_wrapped, wrap_in_seal

from . import drand as drand_mod
from .config import MAP_ID, Settings
from .state import State


def slug(target_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", target_id)


def negative_epochs(state: State, target_id: str, from_epoch: int, to_epoch: int) -> List[int]:
    out = []
    for e in range(from_epoch, to_epoch + 1):
        if any(s["target_id"] == target_id and s["result"] is False for s in state.load_snapshots(e)):
            out.append(e)
    return out


def build(settings: Settings, issuer: SigningKey, target_id: str, *, from_epoch: int = 0,
          to_epoch: Optional[int] = None, strength: int = STRENGTH_SURFACE) -> Dict[str, Any]:
    st = State(settings.paths)
    last = st.latest_epoch()
    if last is None:
        raise RuntimeError("no epochs yet")
    to_epoch = last if to_epoch is None else min(to_epoch, last)
    sheets = list(st.iter_sheets(from_epoch, to_epoch))
    key = target_key(target_id)
    paths = st.paths_for_key(key, from_epoch, to_epoch)
    epoch_hashes: Dict[int, List[bytes]] = {}
    negatives: List[Dict[str, Any]] = []
    for e in range(from_epoch, to_epoch + 1):
        snaps = st.load_snapshots(e)
        epoch_hashes[e] = [snapshot_hash(s) for s in snaps]
        negatives.extend(s for s in snaps if s["target_id"] == target_id and s["result"] is False)
    proof = build_silence_proof(
        map_id=MAP_ID, target_id=target_id, sheets=sheets, paths=paths,
        epoch_snapshot_hashes=epoch_hashes, negative_snapshots=negatives, strength=strength,
    )
    query = build_query(map_id=MAP_ID, target_id=target_id, from_epoch=from_epoch, to_epoch=to_epoch, min_strength=strength)
    return wrap_in_seal(issuer=issuer, query=query, proof=proof)


def merkle_root(height: int) -> Optional[str]:
    """Merkle root (display order) of a Bitcoin block from a public explorer; None if unreachable.

    Verifiers that run a node should pass their own header source instead (SPEC §8.6).
    """
    import urllib.request

    from .config import USER_AGENT
    from .ots import _EXPLORERS
    for base in _EXPLORERS:
        try:
            req = urllib.request.Request(f"{base}/block-height/{height}", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as r:
                bhash = r.read().decode().strip()
            req = urllib.request.Request(f"{base}/block/{bhash}", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as r:
                b = json.loads(r.read().decode())
            root = b.get("merkle_root") or b.get("merkleroot")
            if root:
                return str(root).lower()
        except Exception:  # noqa: BLE001 - try the next explorer
            continue
    return None


class OtsChecker:
    """SPEC §8.6 anchor check: fetch the .ots, replay it in pure Python, compare the merkle root."""

    def __init__(self, header_source: Optional[Any] = merkle_root, fetch: bool = True) -> None:
        self.header_source = header_source
        self.fetch = fetch
        self.details: List[str] = []

    def __call__(self, closed: Dict[str, Any], sheet_hash_bytes: bytes) -> Optional[bool]:
        import urllib.request

        from tacet.ots import verify_sheet_anchor

        from .config import USER_AGENT
        if closed.get("anchored_digest") != "sha256:" + sheet_hash_bytes.hex():
            self.details.append("anchored_digest is not the sheet hash")
            return False
        ref = closed.get("proof_ref")
        if not ref:
            self.details.append("closed.proof_ref missing")
            return False
        if not self.fetch:
            self.details.append(f"{ref}: not fetched (offline); block {closed.get('block_height')} taken as claimed")
            return None
        try:
            req = urllib.request.Request(ref, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
        except Exception as e:  # noqa: BLE001 - unreachable proof file: unchecked, not failed
            self.details.append(f"{ref}: not fetched ({e})")
            return None
        verdict, detail = verify_sheet_anchor(data, sheet_hash_bytes, int(closed.get("block_height", -1)), self.header_source)
        self.details.append(detail)
        return verdict


def ots_check(closed: Dict[str, Any], sheet_hash_bytes: bytes) -> Optional[bool]:
    return OtsChecker()(closed, sheet_hash_bytes)


def verify_file(path: Path, *, expected_operator_pubkey_hex: Optional[str] = None,
                check_beacon: bool = True, check_ots: bool = True, offline: bool = False) -> Dict[str, Any]:
    """Verify a wrapped silence proof.

    Signatures, chaining, non-inclusion, snapshots, silence and witnesses are
    checked from the file alone. The drand rounds are checked for chain and
    schedule from the file, and their bytes against the public relays unless
    `offline`; the Bitcoin anchors need the .ots files and a block-header
    source. `offline=True` skips every network call: those items come back as
    warnings (unchecked), never as passes. The result lists what happened per
    sheet under `beacon` and `anchors`.
    """
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    kwargs: Dict[str, Any] = {}
    beacon = drand_mod.BeaconChecker(online=not offline) if check_beacon else None
    if beacon is not None:
        kwargs["beacon_check"] = beacon
    checker = OtsChecker(header_source=None if offline else merkle_root, fetch=not offline) if check_ots else None
    if checker is not None:
        kwargs["ots_check"] = checker
    if expected_operator_pubkey_hex:
        kwargs["expected_operator_pubkey_hex"] = expected_operator_pubkey_hex
    res = verify_wrapped(bundle, **kwargs)
    if beacon is not None:
        res["beacon"] = beacon.details
    if checker is not None:
        res["anchors"] = checker.details
    return res
