"""OpenTimestamps: the epoch's upper time bound (SPEC §6).

Uses the `ots` CLI already present on the operator host. `stamp` writes
`<epoch>.ots` for the sheet hash; `upgrade` asks the calendars for the Bitcoin
attestation and, once present, returns (block_height, block_time_iso) so the
sheet can be closed. Block time comes from a public block explorer and is
cached per height; verifiers should re-derive it from their own node.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

from .config import USER_AGENT

_HEIGHT = re.compile(r"BitcoinBlockHeaderAttestation\((\d+)\)")
_EXPLORERS = ("https://mempool.space/api", "https://blockstream.info/api")


class OTSError(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["ots", *args], capture_output=True, text=True, timeout=timeout, check=False)


def stamp(digest: bytes, out_path: Path) -> None:
    """Stamp a 32-byte digest. ots stamps files, so write the digest bytes to a temp file."""
    if out_path.exists():
        return
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "sheet_hash.bin"
        f.write_bytes(digest)
        r = _run(["stamp", str(f)])
        produced = Path(str(f) + ".ots")
        if r.returncode != 0 or not produced.exists():
            raise OTSError(f"ots stamp failed: {r.stderr.strip() or r.stdout.strip()}")
        out_path.write_bytes(produced.read_bytes())


def upgrade(ots_path: Path) -> Optional[int]:
    """Try to upgrade; return the Bitcoin block height if the proof is now complete."""
    _run(["upgrade", str(ots_path)])  # non-fatal if calendars are not ready
    info = _run(["info", str(ots_path)])
    m = _HEIGHT.search(info.stdout)
    return int(m.group(1)) if m else None


def verify_digest(ots_path: Path, digest: bytes) -> bool:
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "sheet_hash.bin"
        f.write_bytes(digest)
        sib = Path(str(f) + ".ots")
        sib.write_bytes(ots_path.read_bytes())
        r = _run(["verify", str(sib)])
        out = (r.stdout + r.stderr).lower()
        return "success" in out or "bitcoin block" in out


def block_time(height: int, cache: Path) -> Optional[str]:
    cache.parent.mkdir(parents=True, exist_ok=True)
    known = json.loads(cache.read_text()) if cache.exists() else {}
    if str(height) in known:
        return known[str(height)]
    for base in _EXPLORERS:
        try:
            req = urllib.request.Request(f"{base}/block-height/{height}", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as r:
                bhash = r.read().decode().strip()
            req = urllib.request.Request(f"{base}/block/{bhash}", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as r:
                b = json.loads(r.read().decode())
            ts = int(b.get("timestamp") or b.get("time"))
            import datetime as _dt
            iso = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            known[str(height)] = iso
            cache.write_text(json.dumps(known, indent=0, sort_keys=True))
            return iso
        except Exception:  # noqa: BLE001
            continue
    return None


def status(ots_path: Path) -> Tuple[str, Optional[int]]:
    h = upgrade(ots_path)
    return ("bitcoin", h) if h else ("pending", None)
