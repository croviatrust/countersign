# PNX — Proof of Non-Exfiltration

**TACET profile `crovia.pnx.v1` · status: draft 0.1 · 2026-09-19**

Reference implementation: `reference/python/tacet/egress.py` (tests in `reference/python/tests/test_egress.py`).

## 1. The problem

Enterprises now run AI agents with read access to source code, secrets and
customer data. When an incident is suspected, or when an auditor asks, the only
available evidence is the vendor's own log: self-reported, mutable, and silent
about what was *not* sent. Nobody can hand a regulator a statement of the form
"during this run, none of these 4,000 protected assets left the perimeter" that
the regulator can check without trusting the company or the vendor.

TACET already proves negatives about public surfaces (a model card did not
disclose training data during a Bitcoin-bounded window). PNX applies the same
construction — salted fingerprints, a sparse Merkle map, signed sheets, drand
opening and Bitcoin closing — to the outbound traffic of an agent.

## 2. Roles

| Role | Holds | Produces |
|---|---|---|
| **Egress witness** | a signing key; sees outbound bodies in clear (local LLM proxy, egress proxy, CI sidecar) | fingerprints → sparse Merkle map → signed **run sheet** |
| **Prover** (the operator of the agent) | the protected assets | **PNX proof**: per asset, non-inclusion (or inclusion) paths against the run root |
| **Verifier** (auditor, customer, regulator, court) | the proof; optionally the assets | verdict, offline |
| **TACET epoch** | the run root as a leaf | drand round before, Bitcoin block after |

Only the run sheet and the proof ever leave the perimeter. Neither contains
traffic bytes or asset bytes.

## 3. Fingerprinting

Parameters of `crovia.pnx.v1`: `k_gram = 32`, `window = 16`, `hash = sha256`,
`threshold = k_gram + window − 1 = 47`.

For a byte string `B` and a 16-byte per-run `salt`:

1. `h_i = SHA-256("CROVIA-PNX-FP-v1\n" ‖ salt ‖ B[i : i+32])` for `0 ≤ i ≤ |B| − 32`.
2. Over every window of 16 consecutive `h_i`, select the minimum; on ties the
   rightmost. The set of selected hashes is `FP(B)` (winnowing, Schleimer,
   Wilkerson & Aiken, SIGMOD 2003).

**Guarantee.** If an asset `A` and a body `B` share any substring of length
≥ 47 bytes, then `FP(A) ∩ FP(B) ≠ ∅`. This is a property of winnowing, not of
the hash: the shared substring contains at least one full window of 16
k-grams, whose minimum is selected identically on both sides.

Assets between 32 and 46 bytes are checked with *all* their k-gram hashes
(class `partial`: detection is possible, not guaranteed). Assets under 32 bytes
are `undetectable` and are **never counted as clean**.

## 4. The run sheet

```json
{
  "profile": "crovia.pnx.v1",
  "run_id": "ci-4711/agent-review",
  "salt_hex": "…16 bytes…",
  "params": {"k_gram": 32, "window": 16, "threshold": 47, "hash": "sha256"},
  "egress": {"bodies": 212, "bytes": 1834112, "first_at": "…", "last_at": "…"},
  "fingerprints": 118201,
  "root": "sha256:…",
  "closed_at": "2026-09-19T22:00:00Z",
  "witness": {"id": "…", "pubkey": {"alg": "ed25519", "key_hex": "…"}},
  "signature": {"alg": "ed25519", "domain": "CROVIA-PNX-SHEET-v1", "sig_hex": "…"}
}
```

Every fingerprint is a key of a depth-256 sparse Merkle map (TACET SPEC §5)
whose leaf value is the constant `SHA-256("CROVIA-PNX-PRESENT-v1\n")`. The
signature covers the CSC-1 canonical encoding of the sheet without the
`signature` member, prefixed by the domain string.

To inherit TACET's temporal sandwich the witness (or the operator) commits
`root` into the current epoch map under key `SHA-256("pnx/" ‖ run_id)`. From
then on the run root is provably older than a Bitcoin block and younger than
a drand round; the epoch's OpenTimestamps receipt verifies without a node
(SPEC §8.6).

## 5. The proof

For each labelled asset the prover recomputes `FP(A)` with the run salt and
attaches, per fingerprint, a compact sibling path against `root`. A path is a
non-inclusion proof when the key is absent and an inclusion proof when it is
present. Verdicts per asset: `absent`, `absent-partial`, `present`,
`undetectable`. The proof's overall verdict is `present` if any asset is
present, `absent` if every asset is `absent`, otherwise `mixed`.

The same object is therefore both a clean bill and, when a fingerprint *is*
in the map, a signed, anchored record of exposure — evidence that a specific
protected string left the perimeter during a bounded window.

## 6. Verification

1. Check the sheet: profile, parameter consistency, Ed25519 signature.
2. If the asset bytes are supplied, recompute `asset_sha256`, the detection
   class and the fingerprint set; refuse the proof if any differ. If they are
   not supplied, verify the paths for the listed keys and emit a warning: the
   result then proves non-inclusion of *those keys*, not of any asset.
3. Verify each path against `root`.
4. Recompute every verdict and the overall verdict; refuse on mismatch.
5. Optionally: verify the epoch leaf `pnx/<run_id>` → run root, the epoch
   sheet signature, the drand round and the Bitcoin anchor as in TACET §8.

No network is needed for steps 1–4. Step 5 needs one drand fetch and one
block-header fetch, exactly as the existing TACET verifiers do.

## 7. What a PNX proof does not claim

- Nothing about bytes the witness did not see (traffic that bypassed the
  proxy, TLS the proxy could not terminate, side channels).
- Nothing about paraphrase, translation, summarisation or encodings the witness
  did not normalise. `crovia.pnx.v1` fingerprints raw bytes; a future profile
  may add base64/URL/UTF-16 normalisation layers as additional bodies.
- Nothing about assets shorter than 32 bytes.
- The witness must be honest about *what it ingested*. Multi-witness
  countersigning of the same egress (Countersign) removes the single point of
  trust; a single-witness sheet is a statement by that witness.

## 8. Where it plugs in

- **Causari** (`re proxy`) already sees every prompt and completion of an
  agent session locally; it is the natural egress witness for developer
  machines. Causari records what the agent did; PNX proves what it did not do.
- **CI**: a sidecar around any AI step (review bots, autonomous PR agents)
  producing a PNX proof per job, posted as a check.
- **Egress proxies / gateways**: the fingerprinting is one pass over request
  bodies; the map fits in memory for a day of traffic.

## 9. Conformance (to be added to `conformance/`)

Vectors for: winnowing guarantee at every offset, `partial` and
`undetectable` classes, inclusion evidence, tampered sheet, tampered verdict,
path against a foreign root, hash-only mode warning. The Python tests cover
each case today; the JSON vectors and the browser verifier extension are the
next step.
