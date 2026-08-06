"""RFC 6962 / RFC 9162 Merkle tree: root, inclusion proofs, consistency proofs.

Hash conventions (identical to Certificate Transparency):

- leaf hash: SHA-256(0x00 || leaf_bytes)
- node hash: SHA-256(0x01 || left || right)
- empty tree root: SHA-256("")

All public functions work on lists of *leaf hashes* (bytes), so callers
hash their leaf content once via :func:`leaf_hash` and reuse the result.
"""

from __future__ import annotations

import hashlib
from typing import List

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(leaf_bytes: bytes) -> bytes:
    return _sha256(LEAF_PREFIX + leaf_bytes)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(NODE_PREFIX + left + right)


def _largest_power_of_two_lt(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(leaf_hashes: List[bytes]) -> bytes:
    """Merkle tree hash over an ordered list of leaf hashes."""
    n = len(leaf_hashes)
    if n == 0:
        return _sha256(b"")
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_two_lt(n)
    return node_hash(root(leaf_hashes[:k]), root(leaf_hashes[k:]))


def inclusion_path(index: int, leaf_hashes: List[bytes]) -> List[bytes]:
    """Audit path proving leaf *index* is in the tree (RFC 9162 2.1.3)."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for tree of size {n}")
    if n == 1:
        return []
    k = _largest_power_of_two_lt(n)
    if index < k:
        return inclusion_path(index, leaf_hashes[:k]) + [root(leaf_hashes[k:])]
    return inclusion_path(index - k, leaf_hashes[k:]) + [root(leaf_hashes[:k])]


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, path: List[bytes], expected_root: bytes
) -> bool:
    """Verify an inclusion proof (RFC 9162 2.1.3.2)."""
    if index >= tree_size or index < 0 or tree_size <= 0:
        return False
    fn, sn = index, tree_size - 1
    r = leaf
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def consistency_path(first: int, leaf_hashes: List[bytes]) -> List[bytes]:
    """Proof that the first *first* leaves are a prefix of the tree (RFC 9162 2.1.4)."""
    n = len(leaf_hashes)
    if not 0 < first <= n:
        raise IndexError(f"first={first} out of range for tree of size {n}")
    if first == n:
        return []
    return _subproof(first, leaf_hashes, True)


def _subproof(m: int, hashes: List[bytes], complete_subtree: bool) -> List[bytes]:
    n = len(hashes)
    if m == n:
        return [] if complete_subtree else [root(hashes)]
    k = _largest_power_of_two_lt(n)
    if m <= k:
        return _subproof(m, hashes[:k], complete_subtree) + [root(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [root(hashes[:k])]


def verify_consistency(
    first: int,
    second: int,
    first_root: bytes,
    second_root: bytes,
    path: List[bytes],
) -> bool:
    """Verify a consistency proof between two tree sizes (RFC 9162 2.1.4.2)."""
    if first <= 0 or second < first:
        return False
    if first == second:
        return path == [] and first_root == second_root
    # If first is an exact power of two, prepend first_root to the path.
    if first & (first - 1) == 0:
        path = [first_root] + list(path)
    else:
        path = list(path)
    if not path:
        return False

    fn, sn = first - 1, second - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root
