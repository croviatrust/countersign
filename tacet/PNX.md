# PNX — Proof of Non-Exfiltration

**TACET profile `crovia.pnx.v1` · status: draft 0.3 · 2026-09-20**

Reference implementation: `reference/python/tacet/egress.py` (tests in `reference/python/tests/test_egress.py`);
second implementation: `site/registry/seal/verify/pnx-verify.js` (browser). Conformance vectors: §9.

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

**Normalisation layers.** The raw bytes of every body are always fingerprinted.
A witness MAY additionally fingerprint *derived bodies* produced by a declared
normalisation layer, and MUST list the layers it applied in the run sheet
(`normalization`, sorted; empty when none). `crovia.pnx.v1` defines one layer:

- `json-strings-v1`: if the body parses as JSON (UTF-8), every string value in
  the document, decoded, of at least `k_gram` bytes is a derived body. LLM
  request bodies are JSON, so a file quoted inside one arrives with its
  newlines and quotes escaped and its raw bytes never form a 47-byte run; the
  decoded strings restore the guarantee for anything quoted inside JSON.

Derived bodies add fingerprints only; `egress.bodies` and `egress.bytes` count
raw bodies. A verifier MUST reject a sheet that names a layer it does not know.

## 4. The run sheet

```json
{
  "profile": "crovia.pnx.v1",
  "run_id": "ci-4711/agent-review",
  "salt_hex": "…16 bytes…",
  "params": {"k_gram": 32, "window": 16, "threshold": 47, "hash": "sha256"},
  "egress": {"bodies": 212, "bytes": 1834112, "first_at": "…", "last_at": "…"},
  "normalization": ["json-strings-v1"],
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
  did not normalise. `crovia.pnx.v1` fingerprints raw bytes plus the layers the
  sheet declares (today `json-strings-v1`); base64, URL-encoding and UTF-16
  are not normalised and a leak in those encodings is outside the proof.
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

Tooling (reference, Apache-2.0): the `tacet-pnx` command line
(`pip install crovia-tacet`: `keygen`, `witness`, `prove`, `verify`; exit
codes 0 absent / 1 present or uncovered / 2 invalid) and the GitHub Action
`croviatrust/pnx-action`, which witnesses captured egress in a job, proves a
set of assets and secrets, writes the verdict to the job summary and uploads
the proof as an artifact. Both read capture logs as `.jsonl`
(`{"at": ..., "body": ...}` or `{"body_b64": ...}`) or one body per file.

## 9. Conformance

The vectors live in `conformance/vectors/v1/` next to the TACET core vectors,
are generated deterministically by `conformance/generate_vectors.py` and are
exercised by both runners, `conformance/run_conformance.py` (Python reference)
and `conformance/run_conformance_js.cjs` (the browser verifier
`site/registry/seal/verify/pnx-verify.js`, run in Node). All byte strings in
the vectors are hex; every pseudo-random input is `SHA-256("tacet-pnx-fixture:"
‖ label ‖ ":" ‖ i)` for `i = 0, 1, …`, concatenated and truncated, so a runner in
any language can rebuild the inputs from the labels.

| Vector | What it pins |
|---|---|
| `pnx_001_fingerprints.json` | The fingerprint function of §3, byte for byte: salted k-gram hashes, winnowed set of a 120-byte body, the single-minimum case for a body shorter than one window, the constant leaf value, the four detection classes at 31 / 32 / 46 / 47 / 100 bytes, the `json-strings-v1` derived bodies of a JSON request (and none for a non-JSON body), the epoch leaf key `pnx/<run_id>`, and the winnowing guarantee: a 47-byte secret inserted into a 100-byte body at every one of the 101 offsets shares at least one fingerprint with the secret. |
| `pnx_002_proofs.json` | A witnessed run of four bodies (a raw leak, a leak quoted inside a JSON string that only `json-strings-v1` can find, a body shorter than a k-gram, unrelated traffic), its signed run sheet, and two proofs against it with the asset bytes: `clean` (two assets, verdict `absent`) and `exposure` (five assets: `absent`, `present` via raw bytes, `present` via `json-strings-v1`, `absent-partial`, `undetectable`; verdict `present`). A verifier MUST rebuild the run root from the bodies, MUST verify both proofs with the assets and, without the assets, MUST accept them with the §6 warning. |
| `pnx_003_invalid.json` | **MUST fail** with the stated reason: tampered sheet (signature), forged asset verdict, forged overall verdict, path against a foreign root, an inclusion relabelled as absent, wrong asset bytes, missing asset bytes, substituted fingerprint set, dropped fingerprint, understated detection class, unknown normalisation layer, inconsistent parameters, wrong profile. Each case records `hash_only_ok`: whether a verifier *without* the asset bytes can see the fault. Substituted or dropped fingerprints and an understated class are invisible to it, which is why §6 step 2 requires the warning. |
| `pnx_004_sealed.json` | The `clean` and `exposure` proofs delivered inside an unmodified `crovia.seal.v1` (query = run id and asset hashes, `checks.pnx` = verdict, counts, run root), and four sealed faults: a forged verdict under a valid Seal, a query describing another proof, a proof modified after sealing, a tampered Seal signature. A verifier that stops at the Seal signature accepts the first three; a conformant one rejects all four. |

Run both suites from the repository root:

```
python3 tacet/conformance/run_conformance.py
node tacet/conformance/run_conformance_js.cjs
```
