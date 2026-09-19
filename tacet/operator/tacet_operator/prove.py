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


def _ots_available() -> bool:
    import shutil
    return shutil.which("ots") is not None


def ots_check(closed: Dict[str, Any], sheet_hash_bytes: bytes) -> bool:
    """SPEC §8.5 step 2: fetch the .ots named by `proof_ref` and verify it attests `sheet_hash`."""
    import tempfile
    import urllib.request

    from . import ots as ots_mod
    from .config import USER_AGENT
    if closed.get("anchored_digest") != "sha256:" + sheet_hash_bytes.hex():
        return False
    ref = closed.get("proof_ref")
    if not ref:
        return False
    try:
        req = urllib.request.Request(ref, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
    except Exception:  # noqa: BLE001
        return False
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "sheet.ots"
        p.write_bytes(data)
        height = ots_mod.upgrade(p)
        if height is None or height != int(closed.get("block_height", -1)):
            return False
        return ots_mod.verify_digest(p, sheet_hash_bytes)


def verify_file(path: Path, *, expected_operator_pubkey_hex: Optional[str] = None,
                check_beacon: bool = True, check_ots: bool = True) -> Dict[str, Any]:
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    kwargs: Dict[str, Any] = {}
    if check_beacon:
        kwargs["beacon_check"] = drand_mod.beacon_check
    if check_ots and _ots_available():
        kwargs["ots_check"] = ots_check
    if expected_operator_pubkey_hex:
        kwargs["expected_operator_pubkey_hex"] = expected_operator_pubkey_hex
    res = verify_wrapped(bundle, **kwargs)
    if check_ots and not _ots_available():
        res.setdefault("warnings", []).append("ots client not installed: pip install opentimestamps-client")
    return res
