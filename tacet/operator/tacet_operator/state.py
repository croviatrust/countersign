"""Persistent operator state: the map, slot values, sheets, and replay of the map at any epoch."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from tacet.hashing import object_hash
from tacet.smt import CompactPath, SparseMerkleMap

from .config import Paths


def _read_json(p: Path, default: Any) -> Any:
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def _write_json(p: Path, obj: Any) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)


class State:
    def __init__(self, paths: Paths):
        self.paths = paths
        paths.ensure()

    # -- map ------------------------------------------------------------------

    def load_map(self) -> SparseMerkleMap:
        raw: Dict[str, str] = _read_json(self.paths.map_file, {})
        return SparseMerkleMap({bytes.fromhex(k): bytes.fromhex(v) for k, v in raw.items()})

    def save_map(self, m: SparseMerkleMap) -> None:
        _write_json(self.paths.map_file, {k.hex(): m.get(k).hex() for k in sorted(m.keys())})  # type: ignore[union-attr]

    def value(self, key: bytes) -> Optional[Dict[str, Any]]:
        return _read_json(self.paths.values / f"{key.hex()}.json", None)

    def put_value(self, key: bytes, value: Dict[str, Any], seal: Dict[str, Any]) -> bytes:
        """Store the slot value with the Seal that asserts it; also publish it. Returns value_hash."""
        vh = object_hash(value)
        rec = {"key": key.hex(), "value": value, "value_hash": "sha256:" + vh.hex(), "seal": seal}
        _write_json(self.paths.values / f"{key.hex()}.json", rec)
        pub = self.paths.public / "values"
        pub.mkdir(parents=True, exist_ok=True)
        _write_json(pub / f"{key.hex()}.json", rec)
        return vh

    def meta(self, key: bytes) -> Dict[str, Any]:
        return _read_json(self.paths.values / f"{key.hex()}.meta.json", {})

    def put_meta(self, key: bytes, meta: Dict[str, Any]) -> None:
        _write_json(self.paths.values / f"{key.hex()}.meta.json", meta)

    # -- sheets / changes / snapshots ------------------------------------------

    def sheet_path(self, epoch: int) -> Path:
        return self.paths.sheets / f"{epoch}.json"

    def load_sheet(self, epoch: int) -> Optional[Dict[str, Any]]:
        return _read_json(self.sheet_path(epoch), None)

    def save_sheet(self, sheet: Dict[str, Any]) -> None:
        _write_json(self.sheet_path(sheet["epoch"]), sheet)

    def latest_epoch(self) -> Optional[int]:
        epochs = [int(p.stem) for p in self.paths.sheets.glob("*.json") if p.stem.isdigit()]
        return max(epochs) if epochs else None

    def iter_sheets(self, start: int = 0, end: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        last = self.latest_epoch()
        if last is None:
            return
        end = last if end is None else min(end, last)
        for e in range(start, end + 1):
            s = self.load_sheet(e)
            if s is None:
                raise FileNotFoundError(f"sheet {e} missing: chain is broken")
            yield s

    def save_changes(self, epoch: int, changes: List[Tuple[bytes, bytes]]) -> None:
        _write_json(self.paths.changes / f"{epoch}.json", [[k.hex(), v.hex()] for k, v in changes])

    def load_changes(self, epoch: int) -> List[Tuple[bytes, bytes]]:
        raw = _read_json(self.paths.changes / f"{epoch}.json", [])
        return [(bytes.fromhex(k), bytes.fromhex(v)) for k, v in raw]

    def save_snapshots(self, epoch: int, snaps: List[Dict[str, Any]]) -> None:
        p = self.paths.snapshots / f"{epoch}.jsonl"
        tmp = p.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for s in snaps:
                fh.write(json.dumps(s, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        tmp.replace(p)

    def load_snapshots(self, epoch: int) -> List[Dict[str, Any]]:
        p = self.paths.snapshots / f"{epoch}.jsonl"
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

    # -- replay -----------------------------------------------------------------

    def paths_for_key(self, key: bytes, from_epoch: int, to_epoch: int) -> Dict[int, CompactPath]:
        """Replay the map from genesis and return the non-inclusion path of `key` at each epoch in range."""
        m = SparseMerkleMap()
        out: Dict[int, CompactPath] = {}
        last: Optional[CompactPath] = None
        for e in range(0, to_epoch + 1):
            changes = self.load_changes(e)
            for k, v in changes:
                m.set(k, v)
            if changes or last is None:
                last = m.prove(key)  # the path only moves when the map moves
            if e >= from_epoch:
                out[e] = last
        return out

    # -- cursor -----------------------------------------------------------------

    def cursor(self) -> int:
        return int(_read_json(self.paths.cursor, {"cursor": 0}).get("cursor", 0))

    def save_cursor(self, c: int) -> None:
        _write_json(self.paths.cursor, {"cursor": c})
