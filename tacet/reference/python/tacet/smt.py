"""Sparse Merkle map of depth 256 with compact inclusion / non-inclusion proofs (SPEC §5).

Path convention: position `i` (0..255) is the bit of the key consumed at depth
`i` from the root; the sibling recorded at that position has height
`255 - i`. Proofs are stored leaf-side first, so `siblings[h]` is the sibling
of height `h` (h = 0 is the sibling leaf).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .hashing import DEPTH, EMPTY, key_bit, leaf_hash, node_hash


@dataclass(frozen=True)
class CompactPath:
    """Sibling path with default (empty) siblings elided.

    `bitmap` has bit `h` set iff the sibling of height `h` is present in
    `siblings`, which lists present siblings in increasing height.
    """
    bitmap: int
    siblings: Tuple[bytes, ...]

    @classmethod
    def from_full(cls, full: List[bytes]) -> "CompactPath":
        bitmap = 0
        present = []
        for h, sib in enumerate(full):
            if sib != EMPTY[h]:
                bitmap |= 1 << h
                present.append(sib)
        return cls(bitmap, tuple(present))

    def to_full(self) -> List[bytes]:
        full: List[bytes] = []
        it = iter(self.siblings)
        for h in range(DEPTH):
            full.append(next(it) if (self.bitmap >> h) & 1 else EMPTY[h])
        return full

    def to_json(self) -> dict:
        return {"bitmap": f"{self.bitmap:064x}", "siblings": [s.hex() for s in self.siblings]}

    @classmethod
    def from_json(cls, obj: dict) -> "CompactPath":
        return cls(int(obj["bitmap"], 16), tuple(bytes.fromhex(s) for s in obj["siblings"]))


def root_from_path(key: bytes, leaf: bytes, siblings: List[bytes]) -> bytes:
    """Fold a leaf hash up to the root along `key` using leaf-side-first siblings."""
    if len(siblings) != DEPTH:
        raise ValueError("a full path has exactly 256 siblings")
    node = leaf
    for h in range(DEPTH):
        position = DEPTH - 1 - h
        sib = siblings[h]
        node = node_hash(sib, node) if key_bit(key, position) else node_hash(node, sib)
    return node


class SparseMerkleMap:
    """In-memory sparse Merkle map keyed by 32-byte keys holding 32-byte value hashes."""

    def __init__(self, entries: Optional[Dict[bytes, bytes]] = None):
        self._entries: Dict[bytes, bytes] = dict(entries or {})
        self._cache: Dict[Tuple[int, bytes], bytes] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: bytes) -> bool:
        return key in self._entries

    def get(self, key: bytes) -> Optional[bytes]:
        return self._entries.get(key)

    def set(self, key: bytes, value_hash: bytes) -> None:
        if len(key) != 32 or len(value_hash) != 32:
            raise ValueError("key and value_hash must be 32 bytes")
        self._entries[key] = value_hash
        # Only the subtrees on this key's path change. Clearing the whole cache
        # made every prove after a set rehash the entire map, so an operator
        # replaying history paid (epochs x map size x 256) hashes per proof.
        bits = _bit_string(key)
        for depth in range(DEPTH):
            self._cache.pop((depth, bits[:depth]), None)

    def copy(self) -> "SparseMerkleMap":
        return SparseMerkleMap(self._entries)

    def keys(self) -> Iterable[bytes]:
        return self._entries.keys()

    def _subtree(self, depth: int, prefix: bytes, keys: List[bytes]) -> bytes:
        """Hash of the subtree at `depth` whose path so far is `prefix` (bit string as bytes of '0'/'1')."""
        height = DEPTH - depth
        if not keys:
            return EMPTY[height]
        if depth == DEPTH:
            (k,) = keys
            return leaf_hash(k, self._entries[k])
        cache_key = (depth, prefix)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        if len(keys) == 1:
            # A lone key: every sibling below is empty, so fold its leaf up
            # directly instead of recursing (same hashes, no per-level entries).
            (k,) = keys
            node = leaf_hash(k, self._entries[k])
            for h in range(height):
                node = node_hash(EMPTY[h], node) if key_bit(k, DEPTH - 1 - h) else node_hash(node, EMPTY[h])
            self._cache[cache_key] = node
            return node
        left = [k for k in keys if key_bit(k, depth) == 0]
        right = [k for k in keys if key_bit(k, depth) == 1]
        digest = node_hash(self._subtree(depth + 1, prefix + b"0", left),
                           self._subtree(depth + 1, prefix + b"1", right))
        self._cache[cache_key] = digest
        return digest

    def root(self) -> bytes:
        return self._subtree(0, b"", sorted(self._entries))

    def prove(self, key: bytes) -> CompactPath:
        """Sibling path for `key`; serves as inclusion or non-inclusion proof depending on membership."""
        full: List[bytes] = [b""] * DEPTH
        keys = sorted(self._entries)
        prefix = b""
        for depth in range(DEPTH):
            bit = key_bit(key, depth)
            same = [k for k in keys if key_bit(k, depth) == bit]
            other = [k for k in keys if key_bit(k, depth) != bit]
            other_prefix = prefix + (b"0" if bit else b"1")
            full[DEPTH - 1 - depth] = self._subtree(depth + 1, other_prefix, other)
            prefix = prefix + (b"1" if bit else b"0")
            keys = same
        return CompactPath.from_full(full)


def _bit_string(key: bytes) -> bytes:
    """The key as the '0'/'1' prefix alphabet used by `_subtree` cache entries."""
    return format(int.from_bytes(key, "big"), "0256b").encode()


def verify_inclusion(root: bytes, key: bytes, value_hash: bytes, path: CompactPath) -> bool:
    return root_from_path(key, leaf_hash(key, value_hash), path.to_full()) == root


def verify_non_inclusion(root: bytes, key: bytes, path: CompactPath) -> bool:
    return root_from_path(key, EMPTY[0], path.to_full()) == root
