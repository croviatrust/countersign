import pytest

from countersign.canonical import (
    CanonicalizationError,
    canonical_bytes,
    digest_of,
    is_hex_digest,
)


def test_key_order_is_deterministic():
    a = canonical_bytes({"b": 1, "a": 2})
    b = canonical_bytes({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_no_whitespace_and_utf8():
    assert canonical_bytes({"k": "già"}) == '{"k":"già"}'.encode("utf-8")


def test_nested_structures():
    v = {"z": [1, {"y": None, "x": True}], "a": "s"}
    assert canonical_bytes(v) == b'{"a":"s","z":[1,{"x":true,"y":null}]}'


def test_floats_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"a": 1.5})
    with pytest.raises(CanonicalizationError):
        canonical_bytes([1, [2, [3.0]]])


def test_non_string_keys_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({1: "a"})


def test_digest_is_stable():
    assert digest_of({"a": 1}) == digest_of({"a": 1})
    assert digest_of({"a": 1}) != digest_of({"a": 2})


def test_is_hex_digest():
    good = "a" * 64
    assert is_hex_digest(good)
    assert not is_hex_digest("A" * 64)  # uppercase rejected
    assert not is_hex_digest("a" * 63)
    assert not is_hex_digest("g" * 64)
    assert not is_hex_digest(None)
