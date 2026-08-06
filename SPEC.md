# Countersign Witness Protocol — v0.1 (draft)

Status: draft. This document specifies the data structures and verification
rules so that independent implementations can produce and verify compatible
artifacts. Normative words (MUST, SHOULD, MAY) follow RFC 2119 usage.

## 1. Overview

A **witness** maintains an append-only log of **evidence digests**. The log
is a Merkle tree using the RFC 6962/9162 hashing construction. After every
append the witness signs a **tree head**. Any entry can be exported as a
**proof bundle** verifiable offline against the witness public key.

The witness never sees evidence content — only SHA-256 digests. Privacy of
the underlying evidence is therefore preserved by construction; the witness
learns at most cardinality and timing.

## 2. Cryptographic primitives

- Hash: SHA-256.
- Merkle tree: RFC 6962 domain separation.
  - `leaf_hash = SHA-256(0x00 || leaf_bytes)`
  - `node_hash = SHA-256(0x01 || left || right)`
  - empty tree root = `SHA-256("")`
- Signatures: Ed25519 (RFC 8032). `key_id` = first 16 hex chars of
  `SHA-256(public_key_bytes)`.

## 3. Canonical encoding

All signed or hashed JSON structures MUST be encoded as **canonical JSON**:

- object keys sorted lexicographically by Unicode code point;
- separators `,` and `:` with no whitespace;
- UTF-8, non-ASCII characters not escaped;
- numbers MUST be integers. Floats MUST be rejected by producers.

This is a profile of, not full conformance to, RFC 8785 (JCS). The integer
restriction removes the number-serialization ambiguity that motivates most
of JCS's complexity.

## 4. Leaf record

One evidence digest per leaf. Leaf bytes = canonical JSON of:

```json
{"digest": "<64 lowercase hex chars, sha256 of the evidence>",
 "index": <0-based position in the log, integer>,
 "note": "<optional free-text label; omitted when empty>",
 "witnessed_at": "<UTC ISO-8601, e.g. 2026-08-06T19:30:00Z>"}
```

Requirements:

- `digest` MUST be lowercase 64-char hex. The witness MUST reject others.
- `index` MUST equal the leaf's position; verifiers MUST check this.
- Witnesses MAY accept duplicate digests (re-witnessing is meaningful:
  it proves existence at multiple times).

## 5. Signed tree head (STH)

```json
{"format": "countersign/sth.v1",
 "key_id": "<16 hex>",
 "root_hash": "<64 hex, Merkle root over all leaves>",
 "signature": "<128 hex, Ed25519>",
 "timestamp": "<UTC ISO-8601>",
 "tree_size": <integer>}
```

`signature` is Ed25519 over the canonical JSON of the STH **without** the
`signature` field. A witness MUST sign a new STH after every append (or
batch of appends) and MUST retain every STH it ever signed (`sth_history`).
Tree size MUST be non-decreasing across the history; each historical root
MUST be consistent (RFC 9162 §2.1.4) with every later tree.

## 6. Proof bundle

```json
{"format": "countersign/proof.v1",
 "entry": { …leaf record… },
 "inclusion_path": ["<64 hex>", …],
 "sth": { …signed tree head… },
 "witness": {"public_key": "<64 hex>", "key_id": "<16 hex>"}}
```

### 6.1 Verification algorithm

A verifier with a pinned witness public key `P` MUST:

1. Check `format` fields of the bundle and the STH.
2. If pinning, check `witness.public_key == P`; check
   `sth.key_id == key_id(P)`.
3. Verify the Ed25519 signature over the canonical STH (without
   `signature`) with `P`.
4. Compute `leaf_hash` of the canonical leaf record and verify Merkle
   inclusion (RFC 9162 §2.1.3.2) at `entry.index` in a tree of
   `sth.tree_size` with root `sth.root_hash`.
5. Accept only if all checks pass.

A successful verification establishes: *the evidence whose SHA-256 equals
`entry.digest` was witnessed at `entry.witnessed_at` and covered by a tree
head signed at `sth.timestamp`; any later modification of the evidence
changes its digest and invalidates the proof.*

### 6.2 What verification does NOT establish

Truthfulness of the evidence; honesty of the witness; existence *before*
the witnessed time. See `SECURITY.md`.

## 7. Transport (informative, v0.2 direction)

A hosted witness SHOULD expose:

- `POST /v1/witness` `{"digest": "…", "note": "…"}` → witness receipt
- `GET /v1/sth` → latest STH
- `GET /v1/proof?digest=…[&index=…]` → proof bundle
- `GET /v1/consistency?first=…&second=…` → consistency proof
- `GET /v1/public-key` → the witness identity

Clients SHOULD pin the public key out-of-band (repository, DNS, existing
trust root) rather than trusting the endpoint's self-report.

## 8. Extensibility

Unknown top-level fields in any structure MUST cause rejection by verifiers
(conservative posture; forward compatibility is provided by the `format`
version string, not by ignoring fields).

## 9. Interop test vectors

`tests/` in the reference implementation exhaustively cross-checks inclusion
and consistency proofs for all tree sizes ≤ 33. A frozen vector file for
cross-language implementations is planned for v0.2.
