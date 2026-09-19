"""RFC 6962 Merkle tree for per-epoch snapshot sets (SPEC §6 `snapshots_root`)."""
from __future__ import annotations

import hashlib
from typing import List, Sequence


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return _leaf(leaves[0])
    k = _largest_power_of_two_below(len(leaves))
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(leaves: Sequence[bytes], index: int) -> List[bytes]:
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    if len(leaves) == 1:
        return []
    k = _largest_power_of_two_below(len(leaves))
    if index < k:
        return inclusion_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(root: bytes, leaf: bytes, index: int, size: int, path: Sequence[bytes]) -> bool:
    if not 0 <= index < size:
        return False
    node = _leaf(leaf)
    fn, sn = index, size - 1
    for sib in path:
        if fn % 2 == 1 or fn == sn:
            node = _node(sib, node)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            node = _node(node, sib)
        fn //= 2
        sn //= 2
    return sn == 0 and node == root
