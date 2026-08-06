"""Adapters: turn existing evidence artifacts into digests to witness.

Countersign is format-agnostic by design — it witnesses *digests*, so any
evidence format works without Countersign needing to understand it:

- a whole file (audit packet, receipt chain export, PDF report, tarball)
- each line of a JSONL stream (per-receipt witnessing for receipt chains
  produced by tools like Agent Receipts, Provedex, RootSign, Fuze, or any
  OpenTelemetry GenAI JSONL export)
- a raw digest computed by the caller

Digesting rule for JSONL lines: SHA-256 over the exact line bytes with
trailing newline stripped. Producers that re-serialize JSON will get a
different digest; witness the bytes you store, not a reformatting.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator, Tuple


def digest_file(path: Path) -> str:
    """SHA-256 hex of the raw bytes of a file (streamed)."""
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_jsonl_digests(path: Path) -> Iterator[Tuple[int, str]]:
    """Yield ``(line_number, digest)`` for each non-empty line of a JSONL file.

    Line numbers are 1-based. The digest covers the exact line bytes
    (UTF-8, trailing CR/LF stripped) — no JSON parsing is performed, so
    the witnessed digest is stable regardless of key ordering.
    """
    with Path(path).open("rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            yield lineno, hashlib.sha256(line).hexdigest()
