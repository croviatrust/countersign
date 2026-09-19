"""OpenTimestamps proof verification without a Bitcoin node (SPEC §8.6).

Pure standard library. Parses a ``.ots`` file, replays its operation tree from
the file digest and collects every ``BitcoinBlockHeaderAttestation`` leaf: the
32-byte message at such a leaf is the merkle root of the attested block, in
internal byte order (explorers show it byte-reversed).

The caller supplies the header source: a callable ``height -> merkle_root_hex``
(display order, as printed by every explorer and by ``bitcoin-cli getblock``).
When it returns ``None`` the anchor is *unchecked*, which callers must report
as a warning, never as a failure.

Format reference: https://github.com/opentimestamps/python-opentimestamps
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
MAJOR_VERSION = 1

# Operation tags.
OP_SHA1 = 0x02
OP_RIPEMD160 = 0x03
OP_SHA256 = 0x08
OP_KECCAK256 = 0x67
OP_APPEND = 0xF0
OP_PREPEND = 0xF1
OP_REVERSE = 0xF2
OP_HEXLIFY = 0xF3

# Attestation tags (8 bytes each).
ATT_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
ATT_BITCOIN = bytes.fromhex("0588960d73d71901")
ATT_LITECOIN = bytes.fromhex("06869a0d73d71b45")
ATT_ETHEREUM = bytes.fromhex("30fe8087b5c7ead7")

_MAX_RESULT = 4096
_MAX_ATT_PAYLOAD = 8192

HeaderSource = Callable[[int], Optional[str]]


class OTSError(ValueError):
    pass


@dataclass
class BitcoinAttestation:
    height: int
    merkle_root: bytes  # internal byte order

    @property
    def merkle_root_hex(self) -> str:
        """Display order, as shown by explorers and bitcoin-cli."""
        return self.merkle_root[::-1].hex()


@dataclass
class ParsedProof:
    file_hash_op: int
    file_digest: bytes
    bitcoin: List[BitcoinAttestation] = field(default_factory=list)
    pending: List[str] = field(default_factory=list)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def bytes(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise OTSError("truncated proof")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def byte(self) -> int:
        return self.bytes(1)[0]

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                return value
            shift += 7
            if shift > 63:
                raise OTSError("varuint too large")

    def varbytes(self, max_len: int) -> bytes:
        n = self.varuint()
        if n > max_len:
            raise OTSError(f"varbytes too long ({n})")
        return self.bytes(n)

    def at_end(self) -> bool:
        return self.i >= len(self.d)


def _digest_len(op: int) -> int:
    return {OP_SHA1: 20, OP_RIPEMD160: 20, OP_SHA256: 32, OP_KECCAK256: 32}[op]


def _apply(op: int, arg: Optional[bytes], msg: bytes) -> bytes:
    if op == OP_SHA256:
        return hashlib.sha256(msg).digest()
    if op == OP_SHA1:
        return hashlib.sha1(msg).digest()  # noqa: S324 - format-mandated
    if op == OP_RIPEMD160:
        try:
            return hashlib.new("ripemd160", msg).digest()
        except ValueError as e:  # OpenSSL without legacy provider
            raise OTSError("ripemd160 not available in this Python build") from e
    if op == OP_KECCAK256:
        raise OTSError("keccak256 operations are not supported")
    if op == OP_APPEND:
        return msg + (arg or b"")
    if op == OP_PREPEND:
        return (arg or b"") + msg
    if op == OP_REVERSE:
        return msg[::-1]
    if op == OP_HEXLIFY:
        return msg.hex().encode("ascii")
    raise OTSError(f"unknown op 0x{op:02x}")


def _read_op(r: _Reader, tag: int) -> Tuple[int, Optional[bytes]]:
    if tag in (OP_APPEND, OP_PREPEND):
        return tag, r.varbytes(_MAX_RESULT)
    if tag in (OP_SHA1, OP_RIPEMD160, OP_SHA256, OP_KECCAK256, OP_REVERSE, OP_HEXLIFY):
        return tag, None
    raise OTSError(f"unknown op tag 0x{tag:02x}")


def _read_attestation(r: _Reader, msg: bytes, out: ParsedProof) -> None:
    tag = r.bytes(8)
    payload = _Reader(r.varbytes(_MAX_ATT_PAYLOAD))
    if tag == ATT_BITCOIN:
        height = payload.varuint()
        if len(msg) != 32:
            raise OTSError("Bitcoin attestation over a message that is not 32 bytes")
        out.bitcoin.append(BitcoinAttestation(height=height, merkle_root=msg))
    elif tag == ATT_PENDING:
        out.pending.append(payload.varbytes(1000).decode("utf-8", "replace"))
    # Litecoin, Ethereum and unknown attestations are skipped by design.


def _read_timestamp(r: _Reader, msg: bytes, out: ParsedProof, depth: int = 0) -> None:
    if depth > 256:
        raise OTSError("proof nesting too deep")

    def tag_or_attestation(tag: int) -> None:
        if tag == 0x00:
            _read_attestation(r, msg, out)
        else:
            op, arg = _read_op(r, tag)
            result = _apply(op, arg, msg)
            if len(result) > _MAX_RESULT:
                raise OTSError("operation result too long")
            _read_timestamp(r, result, out, depth + 1)

    tag = r.byte()
    while tag == 0xFF:
        tag_or_attestation(r.byte())
        tag = r.byte()
    tag_or_attestation(tag)


def parse(data: bytes) -> ParsedProof:
    """Parse a detached ``.ots`` proof; raises OTSError on malformed input."""
    r = _Reader(data)
    if r.bytes(len(MAGIC)) != MAGIC:
        raise OTSError("not an OpenTimestamps proof (bad magic)")
    if r.varuint() != MAJOR_VERSION:
        raise OTSError("unsupported OpenTimestamps version")
    op = r.byte()
    if op not in (OP_SHA1, OP_RIPEMD160, OP_SHA256, OP_KECCAK256):
        raise OTSError("file hash op must be a cryptographic hash")
    digest = r.bytes(_digest_len(op))
    out = ParsedProof(file_hash_op=op, file_digest=digest)
    _read_timestamp(r, digest, out)
    if not r.at_end():
        raise OTSError("trailing bytes after proof")
    return out


def expected_merkle_roots(data: bytes) -> Dict[int, List[str]]:
    """``{block_height: [merkle_root_hex, ...]}`` claimed by the proof (display order)."""
    p = parse(data)
    out: Dict[int, List[str]] = {}
    for a in p.bitcoin:
        out.setdefault(a.height, []).append(a.merkle_root_hex)
    return out


def verify_sheet_anchor(
    ots_bytes: bytes,
    sheet_hash_bytes: bytes,
    block_height: int,
    header_source: Optional[HeaderSource],
) -> Tuple[Optional[bool], str]:
    """SPEC §8.6. Returns ``(verdict, detail)``.

    ``verdict`` is True when the proof commits SHA-256(sheet_hash bytes) to the
    merkle root of ``block_height`` as reported by ``header_source``; False when
    the proof is malformed, stamps a different digest, names no Bitcoin
    attestation at that height, or the merkle root differs; None when the
    header source is absent or unreachable (anchor *unchecked*).
    """
    try:
        p = parse(ots_bytes)
    except OTSError as e:
        return False, f"malformed OTS proof: {e}"
    if p.file_hash_op != OP_SHA256 or p.file_digest != hashlib.sha256(sheet_hash_bytes).digest():
        return False, "OTS proof does not stamp SHA-256(sheet_hash bytes)"
    at_height = [a for a in p.bitcoin if a.height == int(block_height)]
    if not at_height:
        heights = sorted({a.height for a in p.bitcoin})
        return False, f"no Bitcoin attestation at block {block_height} (proof has {heights or 'none'})"
    expected = {a.merkle_root_hex for a in at_height}
    if header_source is None:
        return None, f"block {block_height} merkle root should be {sorted(expected)[0]} (unchecked: no header source)"
    try:
        actual = header_source(int(block_height))
    except Exception as e:  # noqa: BLE001 - any transport failure means "unchecked"
        actual = None
        reason = str(e)
    else:
        reason = "header source returned nothing"
    if actual is None:
        return None, f"block {block_height} merkle root should be {sorted(expected)[0]} (unchecked: {reason})"
    if actual.lower() in expected:
        return True, f"block {block_height} merkle root {actual.lower()} matches the proof"
    return False, f"block {block_height} merkle root {actual.lower()} differs from the proof's {sorted(expected)}"
