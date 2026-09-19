# TACET — Verifiable Silence for AI Training Disclosure

**Version:** 0.1-draft · **Status:** Working draft · **License:** CC0 (text), Apache-2.0 (code)
**Editor:** Crovia Trust · `info@croviatrust.com`

> *tacet* (Latin, "it is silent"): the notation a composer writes on a part that
> does not play for a whole movement. The silence is deliberate, measured, and
> written into the score so that anyone reading it knows exactly where it
> begins and ends.

---

## 1. Purpose

Existing transparency logs prove **presence**: a certificate was logged, a
binary was published, a key was registered. TACET is a transparency log whose
primary product is a portable, offline-verifiable proof of **absence over
time**: that for a given AI model, no training-data disclosure satisfying a
public predicate existed in the log, and none was found on the model's
monitored public surfaces, across a contiguous range of anchored epochs.

TACET turns the sentence *"no contemporaneous disclosure was observed between
date A and date B"* from a signed opinion of an observer into an arithmetic
fact that anyone can check against Bitcoin, a public randomness beacon, and
the signatures of independent witnesses. It does not accuse. It records
auditability debt with a defined, reproducible unit.

## 2. Design constraints

1. **Uses only established primitives.** SHA-256, Ed25519 (RFC 8032), sparse
   Merkle trees, RFC 8785-style canonical JSON (CSC-1, as in Crovia Seal),
   drand public randomness, OpenTimestamps. Nothing here needs new
   cryptography; the contribution is the object and the protocol.
2. **Reuses Crovia Seal unchanged.** Every artifact that leaves TACET is
   wrapped in a `crovia.seal.v1` object as specified in `draft-crovia-seal-01`.
   TACET adds no field, no modality and no anchor kind to the Seal
   specification. Any conformant Seal verifier can verify the outer layer.
3. **Trust-minimised.** The log operator cannot back-date, forward-date, or
   silently rewrite an epoch without being caught by anyone holding a prior
   epoch sheet, a beacon value, or a Bitcoin anchor. Witnesses are optional
   and permissionless.
4. **Silence never accrues without observation.** The silence counter of a
   target is a function of anchored, negative observations only. When
   observation stops, the counter stops.
5. **Non-accusatory by construction.** A TACET proof states a property of
   the log and of committed surface snapshots. It carries no verdict field.

## 3. Terminology

| Term | Meaning |
|---|---|
| **Target** | An AI model identified by a canonical `target_id` (§4.1). |
| **Slot** | The position of a target in the verifiable map (§5). |
| **Value** | What a slot holds: nothing, a *commitment*, a *disclosure*, or a *retraction* (§5.3). |
| **Epoch** | A fixed observation period (default: 1 hour, aligned to UTC). Each epoch produces one *epoch sheet*. |
| **Epoch sheet** | The signed head of the map for one epoch, with its temporal bounds (§6). |
| **Snapshot** | A commitment to the bytes fetched from one public surface of a target during an epoch, with the result of the predicate (§7). |
| **Predicate** | A published, versioned, deterministic rule that decides whether fetched bytes constitute a disclosure (§7.3). |
| **Silence proof** | A proof that a slot was empty across a range of epochs, at one of three strength levels (§8). |
| **Witness** | An independent party that countersigns epoch sheets it has verified (§9). |
| **Operator** | The party running the map and issuing epoch sheets (initially Crovia Trust). |

Requirement words (MUST, SHOULD, MAY) are used as in RFC 2119.

## 4. Canonical encoding

### 4.1 Target identifiers

A `target_id` is a UTF-8 string of the form `<organization>/<model>` as used by
the hosting platform (e.g. `meta-llama/Llama-3.1-8B`). Normalisation: Unicode
NFC, trim ASCII whitespace, no case folding (platform ids are case-sensitive).
Identifiers that are not of the form `org/model`, or that denote internal
infrastructure (collectors, file paths, test ids), MUST NOT be inserted into
the map. An operator MUST publish its exclusion rules.

The slot **key** is `SHA-256(UTF-8(target_id))`, a 256-bit value, read
MSB-first as the path from the root of the map.

### 4.2 Canonical JSON

All TACET objects are canonicalised with **CSC-1**, the canonical JSON profile
of Crovia Seal (RFC 8785 subset: UTF-16 code-unit key ordering, no floats,
integers within ±(2⁵³−1), no insignificant whitespace). Hashes of objects are
`SHA-256(CSC-1(object))` and written as `sha256:<64 lowercase hex>`.

### 4.3 Domain separation

Every signature and every hash of a TACET structure is domain-separated by a
fixed ASCII prefix followed by a single `0x0A`:

| Purpose | Prefix bytes |
|---|---|
| Empty leaf | `TACET-EMPTY-v1\n` |
| Leaf hash | `TACET-LEAF-v1\n` |
| Inner node | `TACET-NODE-v1\n` |
| Epoch sheet signature | `TACET-EPOCH-v1\n` |
| Witness countersignature | `TACET-WITNESS-v1\n` |
| Snapshot hash | `TACET-SNAPSHOT-v1\n` |

## 5. The verifiable map

### 5.1 Structure

The map is a **sparse Merkle tree of depth 256**. A key's slot is the leaf
reached by following its bits from the root (bit 0 = left). Let
`H(x) = SHA-256(x)`.

```
EMPTY[0]      = H("TACET-EMPTY-v1\n")
EMPTY[d]      = H("TACET-NODE-v1\n" || EMPTY[d-1] || EMPTY[d-1])       for 1 ≤ d ≤ 256
leaf(key, v)  = H("TACET-LEAF-v1\n" || key || value_hash(v))
node(l, r)    = H("TACET-NODE-v1\n" || l || r)
```

`EMPTY[d]` is the hash of an empty subtree of height `d`. The root of an
empty map is `EMPTY[256]`. `value_hash(v)` is defined in §5.3.

### 5.2 Proofs

A **proof** for key `k` at root `R` is the list of the 256 sibling hashes on
the path from the leaf to the root, leaf-side first. A proof is **compact** if
siblings equal to the corresponding `EMPTY[d]` are omitted and replaced by a
256-bit bitmap (`bitmap[d] = 1` iff the sibling at height `d` is present).

- **Inclusion**: recomputing the root from `leaf(k, v)` and the siblings yields `R`.
- **Non-inclusion**: recomputing the root from `EMPTY[0]` and the siblings yields `R`.

For a map holding `n` keys, a compact non-inclusion proof contains at most
`⌈log₂ n⌉ + 1` hashes with overwhelming probability, plus 32 bytes of bitmap.

### 5.3 Slot values

A slot value is one of:

```json
{"kind": "commitment", "commit_hash": "sha256:…", "committer": {"alg":"ed25519","key_hex":"…"}, "seal_hash": "sha256:…"}
{"kind": "disclosure", "summary_hash": "sha256:…", "summary_url": "https://…", "snapshot_hash": "sha256:…", "seal_hash": "sha256:…", "reveals": "sha256:…" | null}
{"kind": "retraction", "of": "sha256:…", "seal_hash": "sha256:…"}
```

`value_hash(v) = H(CSC-1(v))`. `seal_hash` is the hash of the `crovia.seal.v1`
object by which the party asserting the value signed it; `commit_hash =
H(summary_bytes || salt)` with a 32-byte salt revealed at disclosure time in
`reveals`.

**Transitions.** A slot moves only forward: `∅ → commitment → disclosure`,
`∅ → disclosure`, `disclosure → retraction`. A slot MUST never return to `∅`.
Consequently a non-inclusion proof at epoch `e` implies non-inclusion at every
epoch `< e` for the same map, and silence is a monotone predicate on epochs.

## 6. Epoch sheets and the temporal sandwich

At the start of each epoch the operator fetches the current **drand** round
(chain hash pinned in the trust root). At the end it computes the map root and
signs an epoch sheet:

```json
{
  "sheet_version": "crovia.tacet.epoch.v1",
  "map_id": "urn:crovia:tacet:map:disclosure",
  "epoch": 4123,
  "epoch_start": "2026-09-19T09:00:00Z",
  "epoch_end":   "2026-09-19T10:00:00Z",
  "root": "sha256:…",
  "prev_sheet_hash": "sha256:…",
  "size": 6867,
  "opened": {"kind": "drand", "chain_hash": "…", "round": 1234567, "randomness": "…", "signature": "…"},
  "snapshots_root": "sha256:…",
  "operator": {"id": "urn:crovia:tacet:operator:crovia-trust", "pubkey": {"alg": "ed25519", "key_hex": "…"}},
  "signature": {"alg": "ed25519", "domain": "TACET-EPOCH-v1", "sig_hex": "…"},
  "closed": {"kind": "ots", "status": "pending" | "bitcoin", "anchored_digest": "sha256:…", "block_height": 956737, "proof_ref": "…"}
}
```

- `sheet_hash = H(CSC-1(sheet \ {signature, closed}))`. The signature is
  Ed25519 over `"TACET-EPOCH-v1\n" || CSC-1(sheet \ {signature, closed})`.
- `prev_sheet_hash` chains sheets; the genesis sheet has `null`.
- `opened` binds the epoch to a randomness value that did not exist before
  `epoch_start`: nothing in the epoch (root, snapshots) could have been
  produced earlier. **Lower time bound.**
- `closed` is an OpenTimestamps attestation of `sheet_hash` confirmed in a
  Bitcoin block. The sheet existed before that block. **Upper time bound.**
  The `closed` field is filled in after confirmation and is outside the
  signed region; verifiers check it independently against the OTS proof.
- `snapshots_root` is the Merkle root (RFC 6962 tree) of all snapshot hashes
  taken during the epoch (§7), so that every observation is bound to the
  epoch's temporal sandwich.

An epoch whose `closed.status` is `bitcoin` is **anchored**. Only anchored
epochs contribute to silence at strength ≥ 2 (§8.3).

## 7. Surface snapshots and predicates

### 7.1 Surfaces

For each target the operator publishes a **surface list**: the public URLs
where the target's training-data disclosure is expected to appear (model card,
vendor documentation page, repository README, regulator-mandated summary
location). Surface lists are versioned objects in the map under a reserved
namespace key `H("surfaces/" || target_id)`, so that changes to what is
monitored are themselves logged.

### 7.2 Snapshot

```json
{
  "snapshot_version": "crovia.tacet.snapshot.v1",
  "target_id": "meta-llama/Llama-3.1-8B",
  "surface_url": "https://huggingface.co/meta-llama/Llama-3.1-8B",
  "fetched_at": "2026-09-19T09:17:02Z",
  "epoch": 4123,
  "beacon_round": 1234567,
  "http_status": 200,
  "body_sha256": "sha256:…",
  "body_len": 48213,
  "tls_cert_sha256": "sha256:…" | null,
  "resolved_ip": "…" | null,
  "predicate": {"id": "crovia.pred.art53-summary", "version": "1.0.0", "code_hash": "sha256:…"},
  "result": false,
  "observer": {"id": "urn:crovia:observer:hetzner-1", "pubkey": {"alg": "ed25519", "key_hex": "…"}},
  "signature": {"alg": "ed25519", "domain": "TACET-SNAPSHOT-v1", "sig_hex": "…"}
}
```

`snapshot_hash = H("TACET-SNAPSHOT-v1\n" || CSC-1(snapshot \ {signature}))`.
The `beacon_round` MUST equal the `opened.round` of the epoch the snapshot
belongs to. A snapshot with `result: false` is a **negative snapshot**.

### 7.3 Predicates

A predicate is a pure function `bytes → bool` published as source code with a
`code_hash`, a semantic version, and test vectors. Predicates decide whether
fetched bytes contain a disclosure of the kind the surface is expected to
carry (for example: a link to a document following the EU AI Office training
content summary template; a `crovia.seal.v1` object whose subject is the
summary; structured `training_data` metadata). Predicates MUST be
re-executable by third parties on archived copies of the surface (e.g. the
Internet Archive), so that a negative snapshot can be independently re-derived
from public data. The operator MUST NOT change a predicate's behaviour without
incrementing its version.

## 8. Silence proofs

### 8.1 Object

```json
{
  "proof_version": "crovia.tacet.silence.v1",
  "map_id": "urn:crovia:tacet:map:disclosure",
  "target_id": "meta-llama/Llama-3.1-8B",
  "key": "<64 hex>",
  "from_epoch": 2000,
  "to_epoch": 4123,
  "strength": 1 | 2 | 3,
  "sheets": [ <epoch sheet>, … ],
  "paths": {
    "initial": {"bitmap": "<64 hex>", "siblings": ["<64 hex>", …]},
    "deltas": [ {"epoch": 2001, "changed": [[height, "<64 hex>"], …]}, … ]
  },
  "snapshots": [ <negative snapshot>, … ],
  "witnesses": { "<sheet_hash>": [ {"id": "…", "pubkey": {...}, "sig_hex": "…"}, … ] },
  "silence": {
    "map_epochs": 2124,
    "observed_epochs": 2117,
    "observed_from": "2026-06-24T10:00:00Z",
    "observed_to":   "2026-09-19T10:00:00Z",
    "silence_seconds": 7513200,
    "silence_days": "86.96"
  }
}
```

`silence_days` is a decimal string (CSC-1 has no floats); `silence_seconds`
is the normative integer. Level-3 proofs additionally carry
`"witness_set": {"k": 2, "n": 3, "ids": [...]}`.

### 8.2 Delta-encoded non-inclusion chains

A naïve proof over `N` epochs carries `N` compact paths. TACET encodes the
path for `from_epoch` once (`paths.initial`) and, for each subsequent epoch,
only the siblings that changed (`paths.deltas[i].changed`, a list of
`(height, new_hash)`; a sibling that becomes the default is encoded with
`new_hash = null`). The verifier reconstructs the path incrementally,
recomputes the root for every epoch from `EMPTY[0]`, and checks it against
`sheets[i].root`. Because a sibling changes only when a key sharing that
prefix with the target changed in that epoch, deltas are small and often
empty; a year of hourly epochs for a map of 10⁴ keys typically fits in a few
hundred kilobytes, while remaining fully verifiable without trusting any
intermediate summary.

The proof MUST include every sheet in `[from_epoch, to_epoch]`; sheets chain
via `prev_sheet_hash`, so a gap is detectable.

### 8.3 Strength levels

| Level | Name | What is proven | Required content |
|---|---|---|---|
| 1 | `map-silence` | The slot was empty in every epoch of the range. | sheets, paths |
| 2 | `surface-silence` | Level 1, and for every *observed* epoch at least one negative snapshot for the target exists, is included under `snapshots_root`, and carries the epoch's beacon round. | + snapshots with Merkle inclusion against `snapshots_root`, only anchored epochs counted |
| 3 | `witnessed-silence (k/n)` | Level 2, and every sheet in the range carries at least `k` valid witness countersignatures from the proof's declared witness set of size `n`. | + witnesses |

A level-1 proof states only that nobody put a disclosure *in this map*. It
MUST be displayed as "map silence", never as evidence about the world. Level 2
is the minimum for any public statement about a target's disclosure.

### 8.4 Monotonicity rule (normative)

```
observed_epochs      = #{ e ∈ [from, to] : sheet(e).closed.status == "bitcoin"
                           ∧ ∃ negative snapshot s for target with s.epoch == e }
silence_seconds      = Σ over observed epochs e of (epoch_end(e) − epoch_start(e))
silence_days         = silence_seconds / 86400, rendered as a decimal string
```

Epochs without a negative snapshot (observer down, surface unreachable,
predicate error) contribute **nothing**. Unanchored epochs contribute nothing.
Time between two sheets that no epoch covers (operator downtime; sheets may be
separated in time, never in number) contributes nothing.
`silence_days` therefore cannot grow while observation is paused, and a
verifier can recompute it from the proof alone. `observed_to` MUST accompany
every displayed silence figure.

### 8.5 Verification algorithm

1. Verify each sheet's operator signature; verify `prev_sheet_hash` chaining
   over the range; verify `map_id` and monotonically increasing `epoch`.
2. For each sheet, verify `opened` is a valid drand round for the pinned chain
   whose time is ≤ `epoch_start` + tolerance, and (if `closed.status ==
   bitcoin`) verify the OTS proof of `sheet_hash` and record the block time.
3. Reconstruct the path per epoch from `paths`; for each epoch recompute the
   root from `EMPTY[0]`; require equality with `sheets[i].root`.
4. Level ≥ 2: verify each snapshot's observer signature, `beacon_round`,
   `result == false`, `target_id`, and its inclusion in the epoch's
   `snapshots_root`. Recompute `silence` per §8.4 and require equality with
   the proof's `silence` block.
5. Level 3: verify witness signatures over each `sheet_hash`; require ≥ `k`.
6. Verify the outer Seal (§10).

## 9. Witnesses

A witness is any party that (a) fetches epoch sheets, (b) independently
verifies signature, chaining, `opened` and `closed`, and (c) publishes
countersignatures `Ed25519("TACET-WITNESS-v1\n" || sheet_hash)`. A witness MAY
additionally run its own observer and publish its own snapshots; a snapshot
from a second observer for the same target and epoch strengthens a level-2
proof and is included in the `snapshots` list. Witness identities and keys are
published in a witness list in the map under `H("witnesses")`. The protocol is
that of Crovia Countersign; TACET specifies only the signed bytes.

## 10. Seal wrapping (portable proof)

A silence proof is delivered as a `crovia.seal.v1` object, unmodified from
`draft-crovia-seal-01`:

| Seal field | Content |
|---|---|
| `subject.input_hash`, `input_len` | hash and length of `CSC-1(query)`, where `query = {"query_version":"crovia.tacet.query.v1","map_id","target_id","from_epoch","to_epoch","min_strength"}` |
| `subject.output_hash`, `output_len` | hash and length of `CSC-1(silence proof)` |
| `subject.modality` | `"text"` (the proof is canonical JSON text) |
| `generator.id` | `"crovia/tacet"` |
| `generator.version` | TACET reference version |
| `generator.weights_hash` | `null` |
| `generator.params` | `{"map_id": …, "strength": "2", "epochs": "2000-4123"}` (strings) |
| `chain` | previous silence proof Seal for the same target, so a target's proofs form a chain |
| `anchor` | `{"kind":"crovia-beacon", …}` with the drand round current at emission |
| `witnesses` | Seal-level countersignatures (optional) |
| `checks` | `{"tacet": {"strength": 2, "silence_days": 86.96, "last_negative_snapshot_at": …}}` — a human-readable summary; non-normative |

The proof file is `{"seal": <seal>, "query": <query>, "proof": <silence proof>}`.
Verification: `verify_seal(seal)` per the Seal specification; then check
`seal.subject.input_hash == H(CSC-1(query))` and `output_hash ==
H(CSC-1(proof))`; then §8.5. A verifier that only implements Crovia Seal can
still establish who issued the proof, when (lower-bounded by the beacon), and
that the bytes are intact.

## 11. Commit-then-reveal for vendors

A vendor MAY pre-register a model's training-data summary before release:

1. Vendor computes `commit_hash = H(summary_bytes || salt)` and emits a
   `crovia.seal.v1` with `output_hash = commit_hash`, `generator.id` = the
   model id, `modality = "text"`.
2. The operator (or any relay) inserts `{"kind":"commitment", …}` into the
   target's slot. The epoch sheet's temporal sandwich proves when.
3. At release the vendor publishes the summary at a surface URL and emits a
   Seal over the summary bytes; the operator inserts
   `{"kind":"disclosure", …, "reveals": salt}`. Verifiers check
   `H(summary || salt) == commit_hash`.

The vendor obtains a proof of timely, unchanged publication that does not
depend on the operator's honesty. A silence proof for a committed slot is
impossible by construction (the slot is non-empty), so the vendor also gains
a guarantee against false silence claims. The three observable states of a
target are therefore `never-committed`, `committed-unrevealed`, `revealed`,
and TACET reports which one applies.

## 12. Public data layout

The operator publishes, content-addressed and immutable once anchored:

```
/tacet/<map_id>/sheets/<epoch>.json          epoch sheet
/tacet/<map_id>/snapshots/<epoch>.jsonl      snapshots of the epoch
/tacet/<map_id>/values/<epoch>.jsonl         slot writes of the epoch
/tacet/<map_id>/witness/<epoch>.jsonl        countersignatures received
/tacet/<map_id>/HEAD.json                    latest sheet + pointers
```

Consumers fetch `HEAD.json` (small) and only the sheets they need. No page
loads a whole-history file.

## 13. Security considerations

- **Back-dating** an epoch is prevented by `opened` (beacon randomness is
  unpredictable); **forward-dating** by `closed` (Bitcoin block time).
- **Split view** (showing different sheets to different parties) is detected
  by witnesses and by any two consumers comparing `sheet_hash` for the same
  epoch; the OTS anchor commits to one hash per epoch.
- **Selective observation** (not fetching a surface to manufacture silence)
  cannot inflate silence: an epoch without a negative snapshot contributes
  zero (§8.4). It can only *reduce* the proven silence, which is the
  conservative failure mode.
- **Predicate gaming** by an operator is bounded by predicate publication and
  reproducibility on archived copies (§7.3).
- **Key compromise** of the operator: sheets remain chained and anchored;
  a compromised key can produce forged sheets only going forward, and only
  until witnesses refuse to countersign an unchained head. Key rotation is
  logged in the map under `H("operator")`.
- A silence proof is **not** a proof that a disclosure exists nowhere. It is
  a proof about the map and about the listed surfaces under the listed
  predicate. The proof carries the surface list and predicate so that its
  scope is explicit.

## 14. Conformance

An implementation is conformant if it passes the vectors in
`tacet/conformance/vectors/v1/`: empty-map root, inclusion and non-inclusion
proofs, delta-chain reconstruction, sheet signature and chaining, silence
computation under paused observation, rejection of a proof with a missing
sheet, rejection of a proof whose silence block overstates observed epochs,
and round-trip of the Seal wrapper against the Crovia Seal reference verifier.

---

*TACET is an open protocol stewarded by Crovia Trust. The text of this
specification is dedicated to the public domain (CC0).*
