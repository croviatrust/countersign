# Security Policy

## Threat model (v0.1)

Countersign makes one claim: **a witnessed digest existed no later than the
signed tree head that covers it, and the witness cannot silently rewrite or
reorder history without detection.**

What v0.1 protects against:

- **Backdating** — an operator cannot claim evidence existed earlier than its
  witnessed timestamp without forging the witness signature.
- **Silent rewriting** — changing or removing a witnessed entry changes the
  Merkle root; historical signed tree heads and consistency proofs expose it.
- **Selective disclosure attacks on verifiers** — proof bundles verify offline
  against a pinned public key; the verifier does not trust operator storage.

What v0.1 does NOT protect against (explicit non-goals for now, roadmap items):

- **A malicious witness colluding with the operator.** A single witness is a
  trust anchor, not a trustless system. Mitigations on the roadmap: multiple
  independent witnesses (cosigning), public log gossip, and external anchoring
  (RFC 3161 TSA, Bitcoin/OpenTimestamps — already operational in the Crovia
  substrate and planned as `countersign anchor`).
- **Semantic falsehood of the evidence itself.** Countersign proves integrity
  and time, not truth. Garbage in, witnessed garbage out.
- **Key compromise.** If `witness.key` leaks, the attacker can sign forged
  tree heads. Keep it out of the agent process, back it up offline, and rotate
  via a new log with a cross-reference entry. HSM/KMS support is on the roadmap.
- **Local witness on the same machine as the agent** proves little against an
  attacker with local root. Run the witness on separate infrastructure (or use
  a public witness) for adversarial scenarios.

## Cryptography

- Hashing: SHA-256, RFC 6962/9162 Merkle tree domain separation
  (`0x00` leaf prefix, `0x01` node prefix).
- Signatures: Ed25519 via the `cryptography` package (OpenSSL backend).
- Canonical encoding: deterministic JSON subset (sorted keys, UTF-8, no
  floats). Documented in `SPEC.md`; floats are rejected at signing time to
  avoid cross-language serialization ambiguity.

## Reporting a vulnerability

Email hello@croviatrust.com with a description and reproduction steps.
Please do not open public issues for exploitable vulnerabilities. You will
get an acknowledgment within 72 hours.
