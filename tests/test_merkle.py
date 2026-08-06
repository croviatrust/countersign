"""Exhaustive property tests for the RFC 6962/9162 Merkle implementation."""

import hashlib

import pytest

from countersign import merkle


def make_leaves(n):
    return [merkle.leaf_hash(f"leaf-{i}".encode()) for i in range(n)]


def test_empty_tree_root_is_sha256_of_empty_string():
    assert merkle.root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_root_is_the_leaf_hash():
    leaves = make_leaves(1)
    assert merkle.root(leaves) == leaves[0]


def test_known_rfc9162_structure_size_3():
    # For 3 leaves: root = node(node(l0, l1), l2)
    leaves = make_leaves(3)
    expected = merkle.node_hash(merkle.node_hash(leaves[0], leaves[1]), leaves[2])
    assert merkle.root(leaves) == expected


@pytest.mark.parametrize("n", range(1, 34))
def test_inclusion_roundtrip_all_sizes_all_indices(n):
    leaves = make_leaves(n)
    r = merkle.root(leaves)
    for i in range(n):
        path = merkle.inclusion_path(i, leaves)
        assert merkle.verify_inclusion(leaves[i], i, n, path, r), (n, i)


@pytest.mark.parametrize("n", range(2, 20))
def test_inclusion_fails_for_wrong_leaf(n):
    leaves = make_leaves(n)
    r = merkle.root(leaves)
    path = merkle.inclusion_path(0, leaves)
    wrong = merkle.leaf_hash(b"not-in-tree")
    assert not merkle.verify_inclusion(wrong, 0, n, path, r)


@pytest.mark.parametrize("n", range(2, 20))
def test_inclusion_fails_for_wrong_index(n):
    leaves = make_leaves(n)
    r = merkle.root(leaves)
    path = merkle.inclusion_path(0, leaves)
    assert not merkle.verify_inclusion(leaves[0], 1, n, path, r)


def test_inclusion_fails_for_tampered_path():
    leaves = make_leaves(8)
    r = merkle.root(leaves)
    path = merkle.inclusion_path(3, leaves)
    tampered = [path[0][::-1]] + path[1:]
    assert not merkle.verify_inclusion(leaves[3], 3, 8, tampered, r)


def test_inclusion_out_of_range():
    leaves = make_leaves(4)
    r = merkle.root(leaves)
    assert not merkle.verify_inclusion(leaves[0], 4, 4, [], r)
    assert not merkle.verify_inclusion(leaves[0], -1, 4, [], r)
    with pytest.raises(IndexError):
        merkle.inclusion_path(4, leaves)


@pytest.mark.parametrize("n", range(1, 34))
def test_consistency_roundtrip_all_prefixes(n):
    leaves = make_leaves(n)
    new_root = merkle.root(leaves)
    for m in range(1, n + 1):
        old_root = merkle.root(leaves[:m])
        path = merkle.consistency_path(m, leaves)
        assert merkle.verify_consistency(m, n, old_root, new_root, path), (m, n)


@pytest.mark.parametrize("n", range(2, 20))
def test_consistency_fails_when_history_rewritten(n):
    leaves = make_leaves(n)
    new_root = merkle.root(leaves)
    m = max(1, n // 2)
    # Pretend the old tree contained a different leaf 0.
    forged = [merkle.leaf_hash(b"forged")] + leaves[1:m]
    forged_old_root = merkle.root(forged)
    path = merkle.consistency_path(m, leaves)
    assert not merkle.verify_consistency(m, n, forged_old_root, new_root, path)


def test_consistency_same_size_is_identity():
    leaves = make_leaves(5)
    r = merkle.root(leaves)
    assert merkle.verify_consistency(5, 5, r, r, [])
    assert not merkle.verify_consistency(5, 5, r, r[::-1], [])


def test_consistency_rejects_bad_ranges():
    leaves = make_leaves(4)
    r = merkle.root(leaves)
    assert not merkle.verify_consistency(0, 4, r, r, [])
    assert not merkle.verify_consistency(5, 4, r, r, [])
