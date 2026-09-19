"""Domain-separated hashing for TACET (SPEC §4.3, §5.1)."""
from __future__ import annotations

import hashlib
from typing import Any, List

from .canonical import canonicalize

DEPTH = 256

DOMAIN_EMPTY = b"TACET-EMPTY-v1\n"
DOMAIN_LEAF = b"TACET-LEAF-v1\n"
DOMAIN_NODE = b"TACET-NODE-v1\n"
DOMAIN_EPOCH = b"TACET-EPOCH-v1\n"
DOMAIN_WITNESS = b"TACET-WITNESS-v1\n"
DOMAIN_SNAPSHOT = b"TACET-SNAPSHOT-v1\n"

SHA256_PREFIX = "sha256:"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def prefixed(digest: bytes) -> str:
    return SHA256_PREFIX + digest.hex()


def unprefixed(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith(SHA256_PREFIX) or len(value) != len(SHA256_PREFIX) + 64:
        raise ValueError(f"expected 'sha256:<64 hex>', got {value!r}")
    return bytes.fromhex(value[len(SHA256_PREFIX):])


def object_hash(obj: Any) -> bytes:
    """SHA-256 of the CSC-1 encoding of `obj`."""
    return sha256(canonicalize(obj))


def _build_empty_table() -> List[bytes]:
    table = [sha256(DOMAIN_EMPTY)]
    for _ in range(DEPTH):
        table.append(sha256(DOMAIN_NODE + table[-1] + table[-1]))
    return table


#: EMPTY[h] is the hash of an empty subtree of height h; EMPTY[256] is the root of an empty map.
EMPTY: List[bytes] = _build_empty_table()


def leaf_hash(key: bytes, value_hash: bytes) -> bytes:
    return sha256(DOMAIN_LEAF + key + value_hash)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(DOMAIN_NODE + left + right)


def target_key(target_id: str) -> bytes:
    """Slot key of a target (SPEC §4.1): SHA-256 of the NFC-normalised id."""
    import unicodedata
    normalised = unicodedata.normalize("NFC", target_id).strip()
    return sha256(normalised.encode("utf-8"))


def namespace_key(namespace: str, name: str = "") -> bytes:
    """Key of a reserved namespace entry such as surfaces/<target> or witnesses."""
    return sha256((namespace + ("/" + name if name else "")).encode("utf-8"))


def key_bit(key: bytes, height_index: int) -> int:
    """Bit of `key` at path position `height_index` (0 = MSB, chosen at the root)."""
    return (key[height_index // 8] >> (7 - height_index % 8)) & 1
