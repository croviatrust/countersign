"""The witness log: an append-only Merkle log of evidence digests.

Layout of a log directory::

    logdir/
      witness.key        # Ed25519 private seed (hex)  — secret
      witness.pub        # Ed25519 public key (hex)    — public
      entries.jsonl      # one canonical leaf record per line, append-only
      sth.json           # latest signed tree head
      sth_history.jsonl  # every STH ever signed, append-only

Leaf record (canonical JSON, one line)::

    {"digest": "<sha256 hex of the evidence>",
     "index": 42,
     "note": "optional free-text label",
     "witnessed_at": "2026-08-06T19:30:00Z"}

Only *digests* enter the log. The evidence itself never leaves the
client, which is what makes a public witness privacy-safe.

Signed tree head (STH)::

    {"format": "countersign/sth.v1",
     "key_id": "…", "root_hash": "…", "timestamp": "…", "tree_size": 43,
     "signature": "<ed25519 over canonical STH without 'signature'>"}
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from . import keys as keys_mod
from . import merkle
from .canonical import canonical_bytes, is_hex_digest

ENTRIES_NAME = "entries.jsonl"
STH_NAME = "sth.json"
STH_HISTORY_NAME = "sth_history.jsonl"

STH_FORMAT = "countersign/sth.v1"


class LogError(RuntimeError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sth_signing_bytes(sth: Dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in sth.items() if k != "signature"}
    return canonical_bytes(unsigned)


@dataclass
class WitnessReceipt:
    """What the caller gets back after a digest is witnessed."""

    digest: str
    index: int
    leaf_hash: str
    sth: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "digest": self.digest,
            "index": self.index,
            "leaf_hash": self.leaf_hash,
            "sth": self.sth,
        }


class WitnessLog:
    """Append-only witness log rooted at a directory."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.entries_path = self.dir / ENTRIES_NAME
        self.sth_path = self.dir / STH_NAME
        self.sth_history_path = self.dir / STH_HISTORY_NAME

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def init(cls, directory: Path) -> "WitnessLog":
        log = cls(directory)
        log.dir.mkdir(parents=True, exist_ok=True)
        if log.entries_path.exists():
            raise LogError(f"log already initialized at {log.dir}")
        keys_mod.generate(log.dir)
        log.entries_path.touch()
        log._seal()  # sign the empty-tree STH so the log has a verifiable genesis
        return log

    def key(self) -> keys_mod.WitnessKey:
        return keys_mod.load(self.dir)

    # -- reading -----------------------------------------------------------

    def iter_entries(self) -> Iterator[Dict[str, Any]]:
        if not self.entries_path.exists():
            raise LogError(f"no log at {self.dir}; run 'countersign init'")
        with self.entries_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def entries(self) -> List[Dict[str, Any]]:
        return list(self.iter_entries())

    def leaf_hashes(self) -> List[bytes]:
        return [merkle.leaf_hash(canonical_bytes(e)) for e in self.iter_entries()]

    def latest_sth(self) -> Dict[str, Any]:
        if not self.sth_path.exists():
            raise LogError(f"no STH at {self.sth_path}")
        return json.loads(self.sth_path.read_text(encoding="utf-8"))

    def find(self, digest: str) -> Optional[Dict[str, Any]]:
        """Most recent entry for *digest*, or None."""
        found = None
        for entry in self.iter_entries():
            if entry["digest"] == digest:
                found = entry
        return found

    # -- writing -----------------------------------------------------------

    def witness(self, digest: str, note: str = "") -> WitnessReceipt:
        """Append *digest* to the log and sign a fresh tree head."""
        if not is_hex_digest(digest):
            raise LogError("digest must be a lowercase 64-char sha256 hex string")
        entries = self.entries()
        record: Dict[str, Any] = {
            "digest": digest,
            "index": len(entries),
            "witnessed_at": _utc_now_iso(),
        }
        if note:
            record["note"] = note

        line = canonical_bytes(record).decode("utf-8")
        with self.entries_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")

        sth = self._seal()
        return WitnessReceipt(
            digest=digest,
            index=record["index"],
            leaf_hash=merkle.leaf_hash(canonical_bytes(record)).hex(),
            sth=sth,
        )

    def _seal(self) -> Dict[str, Any]:
        """Recompute the root over all entries and sign a new STH."""
        key = self.key()
        if not key.can_sign():
            raise LogError("private key missing; cannot sign tree head")
        hashes = self.leaf_hashes()
        sth: Dict[str, Any] = {
            "format": STH_FORMAT,
            "tree_size": len(hashes),
            "root_hash": merkle.root(hashes).hex(),
            "timestamp": _utc_now_iso(),
            "key_id": key.key_id,
        }
        sth["signature"] = key.sign(sth_signing_bytes(sth))
        self.sth_path.write_text(
            json.dumps(sth, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.sth_history_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(canonical_bytes(sth).decode("utf-8") + "\n")
        return sth

    # -- auditing ----------------------------------------------------------

    def audit(self) -> Dict[str, Any]:
        """Full self-check of the log. Returns a report; raises nothing.

        Checks:
        1. every entry parses and its index matches its position
        2. the latest STH signature verifies and matches the recomputed root
        3. every historical STH signature verifies
        4. historical STHs are append-consistent (tree sizes never shrink and
           each older root is a Merkle prefix of the newer tree)
        """
        problems: List[str] = []
        entries: List[Dict[str, Any]] = []
        try:
            entries = self.entries()
        except (json.JSONDecodeError, LogError) as exc:
            problems.append(f"entries unreadable: {exc}")

        for pos, entry in enumerate(entries):
            if entry.get("index") != pos:
                problems.append(f"entry at position {pos} has index {entry.get('index')}")
            if not is_hex_digest(entry.get("digest", "")):
                problems.append(f"entry {pos} has malformed digest")

        key = keys_mod.public_only(self.key().public_hex)
        hashes = [merkle.leaf_hash(canonical_bytes(e)) for e in entries]
        computed_root = merkle.root(hashes).hex()

        try:
            sth = self.latest_sth()
            if sth["tree_size"] != len(entries):
                problems.append(
                    f"latest STH tree_size {sth['tree_size']} != entry count {len(entries)}"
                )
            if sth["root_hash"] != computed_root:
                problems.append("latest STH root_hash does not match recomputed root")
            if not key.verify(sth_signing_bytes(sth), sth["signature"]):
                problems.append("latest STH signature invalid")
        except (LogError, KeyError) as exc:
            problems.append(f"latest STH unreadable: {exc}")

        prev_size = -1
        if self.sth_history_path.exists():
            with self.sth_history_path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh):
                    line = line.strip()
                    if not line:
                        continue
                    hist = json.loads(line)
                    if not key.verify(sth_signing_bytes(hist), hist["signature"]):
                        problems.append(f"historical STH #{lineno} signature invalid")
                    if hist["tree_size"] < prev_size:
                        problems.append(f"historical STH #{lineno} tree shrank")
                    else:
                        size = hist["tree_size"]
                        if size <= len(hashes):
                            old_root = merkle.root(hashes[:size]).hex()
                            if old_root != hist["root_hash"]:
                                problems.append(
                                    f"historical STH #{lineno} root not a prefix of current tree"
                                )
                        prev_size = size

        return {
            "ok": not problems,
            "tree_size": len(entries),
            "root_hash": computed_root,
            "problems": problems,
        }
