"""CSC-1 canonical JSON, the profile used by Crovia Seal (SPEC §4.2).

Strict subset of RFC 8785: object keys sorted by UTF-16 code units, integers
only (no floats), integers within the JavaScript safe range, no whitespace,
strings escaped per RFC 8785 §3.2.2.2. The output is byte-identical to the
Crovia Seal reference canonicalizer; tests assert this when that package is
installed.
"""
from __future__ import annotations

from typing import Any

JS_SAFE_INT_MAX = (1 << 53) - 1
JS_SAFE_INT_MIN = -JS_SAFE_INT_MAX

_ESCAPES = {
    "\"": "\\\"",
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented in CSC-1."""


def _utf16_key(s: str) -> tuple:
    return tuple(int.from_bytes(s.encode("utf-16-be")[i:i + 2], "big")
                 for i in range(0, len(s.encode("utf-16-be")), 2))


def _serialize_string(s: str) -> str:
    out = ["\""]
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append("\"")
    return "".join(out)


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not JS_SAFE_INT_MIN <= value <= JS_SAFE_INT_MAX:
            raise CanonicalizationError(f"integer outside JS safe range: {value}")
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError("CSC-1 forbids floats; encode numbers as strings or integers")
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_serialize_string(k) + ":" + _serialize(v) for k, v in items) + "}"
    raise CanonicalizationError(f"unsupported type: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the CSC-1 encoding of `value` as UTF-8 bytes."""
    return _serialize(value).encode("utf-8")
