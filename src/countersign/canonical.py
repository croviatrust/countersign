"""Canonical JSON encoding and hashing.

Countersign hashes and signs canonical JSON bytes. The encoding is a
deterministic subset of JSON (sorted keys, no whitespace, UTF-8):

- objects: keys sorted lexicographically by Unicode code point
- no insignificant whitespace
- strings: UTF-8, non-ASCII characters NOT escaped
- numbers: only integers are allowed in signed structures (floats are
  rejected to avoid cross-language serialization ambiguity, the main
  gap between this profile and full RFC 8785/JCS)

Anything that must be signed or hashed goes through this module.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically encoded."""


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise CanonicalizationError(
            "floats are not allowed in signed structures; use integers or strings"
        )
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)
    elif value is None or isinstance(value, (str, int, bool)):
        return
    else:
        raise CanonicalizationError(f"unsupported type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Encode a JSON-compatible value to canonical bytes."""
    _reject_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(value: Any) -> str:
    """SHA-256 hex digest of the canonical encoding of *value*."""
    return sha256_hex(canonical_bytes(value))


def is_hex_digest(s: str) -> bool:
    """True if *s* is a lowercase 64-char hex SHA-256 digest."""
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        bytes.fromhex(s)
    except ValueError:
        return False
    return s == s.lower()
