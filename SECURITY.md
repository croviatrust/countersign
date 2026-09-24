# Security Policy

This repository holds two components with different claims. Read the one you
are attacking.

## TACET (`tacet/`)

TACET makes one claim per proof: **for every epoch listed, an observer fetched
the named surfaces after the epoch's drand round was published, the public
predicate returned "no disclosure found" on those bytes, and the epoch sheet
committing to that verdict was stamped into Bitcoin.** Silence is the sum of
such anchored, observed epochs; it never accrues without observation.

What a TACET proof protects against:

- **Backdating** — an epoch sheet cannot pre-date its drand opening round
  (randomness unknowable in advance) nor post-date its Bitcoin anchor.
- **Selective omission** — the Sparse Merkle Map commits to every target slot;
  a non-inclusion proof shows exactly one value, or its absence, under the root.
- **Rewriting a verdict** — the surface bytes are hashed into the snapshot,
  the snapshot into the sheet, the sheet into Bitcoin. Changing any of them
  changes a root that is already anchored.
- **Predicate drift** — the predicate id, version and code hash are in the
  sheet; a verifier re-runs the same code on the same bytes.
- **Operator disappearance** — proofs verify against the pinned keys in
  `trust_root.json`, the drand chain and a Bitcoin block header. No Crovia
  server is needed once a proof is in hand. Offline, the verifier checks
  everything the file contains (signatures, chaining, non-inclusion, snapshots,
  silence) plus each round's chain and schedule; the round bytes need a drand
  relay (or a BLS12-381 check, which no Crovia verifier implements) and the
  anchors need the `.ots` files and a block header. What was not checked is
  named in the result's warnings — see SPEC §8.5.1.

What a TACET proof does **not** claim (explicit non-goals, stated in
`tacet/SPEC.md §13`):

- **Truth about the provider.** A proof says the disclosure was not found on
  the observed surfaces by this predicate. It does not say the provider has no
  disclosure elsewhere, nor infer intent.
- **Surfaces the operator never fetched.** A target's surface list is public;
  a proof over `README.md` says nothing about a paper or a blog post.
- **A malicious operator that fabricates fetched bytes.** The operator signs
  what it says it saw. Mitigation: independent observers (Countersign
  witnesses) that fetch the same surface in the same epoch; a level-3 proof
  requires at least one. Until then the operator key is a trust anchor.
- **Key compromise.** `operator`, `observer` and `issuer` seeds live at
  `TACET_STATE/keys/` with mode 0600. Rotation: publish a new
  `trust_root.json` referencing the retiring key by fingerprint and the epoch
  at which it stops signing; verifiers pin both.

Cryptography: SHA-256; Sparse Merkle Map of depth 256 with the empty-subtree
table in `tacet/reference/python/tacet/smt.py`; Ed25519 (`cryptography`);
canonical JSON per CSC-1 (byte-identical to `crovia_seal`); drand League of
Entropy chain `8990e7a9…` (30 s rounds); OpenTimestamps for Bitcoin attestation.

## Countersign witness (`countersign/`)

Countersign makes one claim: **a witnessed digest existed no later than the
signed tree head that covers it, and the witness cannot silently rewrite or
reorder history without detection.**

Protects against backdating, silent rewriting and selective disclosure to
verifiers (proof bundles verify offline against a pinned key).

Non-goals in v0.1: a witness colluding with the operator (single witness is a
trust anchor; cosigning and gossip are roadmap), semantic falsehood of the
evidence itself, key compromise, and a witness co-located with the process it
witnesses. RFC 6962/9162 Merkle tree with `0x00`/`0x01` domain separation,
Ed25519, deterministic JSON without floats.

## Reporting a vulnerability

Email info@croviatrust.com with a description and reproduction steps. Please
do not open public issues for exploitable vulnerabilities. You will receive an
acknowledgment within 72 hours and a fix or a public statement within 30 days.

A break of a TACET proof's cryptographic claim (a forged anchored epoch, a
non-inclusion proof for a key that is present, a predicate collision that
changes a verdict without changing the bytes) is the highest severity we
recognise and will be published in the release notes with credit.
