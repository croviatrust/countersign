# TACET

**Verifiable silence for AI training disclosure.** A transparency log whose
primary product is a portable, offline-verifiable proof that no disclosure
existed for a model across a contiguous range of Bitcoin-anchored epochs, and
that none was found on the model's monitored public surfaces.

TACET is stewarded by Crovia Trust and delivered as an unmodified
[Crovia Seal](https://github.com/croviatrust/crovia-seal) (`crovia.seal.v1`,
IETF `draft-crovia-seal-01`). It adds nothing to the Seal format: a silence
proof is the Seal's *output*, the query that produced it is the Seal's *input*.

```
tacet/
  SPEC.md                         The protocol (v0.1-draft, CC0)
  reference/python/tacet/         Reference implementation (Apache-2.0)
  conformance/generate_vectors.py Deterministic vector generator
  conformance/run_conformance.py  107-case runner; port this to other languages
  conformance/vectors/v1/         Committed vectors (520 KB)
```

## What a silence proof says

> Between drand round *r₁* (not before *T₁*) and Bitcoin block *b* (not after
> *T₂*), the slot of `<org>/<model>` in map `urn:crovia:tacet:map:disclosure`
> was empty in every one of *N* consecutive epochs; in *M* of them, an
> observer fetched the model card, ran predicate
> `crovia.pred.hf-card-training-data@1.0.0` and recorded a negative result
> bound to that epoch's beacon round; every epoch head is countersigned by at
> least *k* of *n* named witnesses.

(Illustrative wording of a level-3 proof. The live operator currently issues
level-2 proofs; witnesses are the next milestone.)

and, crucially, what it does **not** say: nothing about intent, nothing about
surfaces that were not listed, nothing about epochs in which nobody looked.
Silence never accrues without an anchored negative observation (SPEC §8.4).

## Three strengths

| Level | Name | Proves |
|---|---|---|
| 1 | map-silence | the slot was empty in the map at every epoch |
| 2 | surface-silence | + a negative, beacon-bound snapshot exists for every counted epoch |
| 3 | witnessed-silence (k/n) | + every epoch head carries ≥ k witness countersignatures |

## Try it

```bash
pip install -e <crovia-seal>/reference/python      # Seal reference, for the wrapper
pip install -e tacet/reference/python
python3 tacet/conformance/run_conformance.py         # 107 passed, 0 failed
node tacet/conformance/run_conformance_js.cjs        # 76 passed, 0 failed (browser verifier)
cd tacet/reference/python && python3 -m pytest       # unit tests
```

```python
from tacet.fixtures import build_scenario, witness_set, MAP_ID, TARGET
from tacet import build_silence_proof, verify_silence_proof, build_query, wrap_in_seal, verify_wrapped

sc = build_scenario()                       # 12 hourly epochs, observer down in 7-9, epoch 11 unanchored
proof = build_silence_proof(map_id=MAP_ID, target_id=TARGET, sheets=sc.sheets, paths=sc.paths,
                            epoch_snapshot_hashes=sc.snapshot_hashes, negative_snapshots=sc.negative_snapshots,
                            witnesses=sc.witness_sigs, witness_set=witness_set(sc), strength=3)
print(proof["silence"])   # observed_epochs 8, silence_seconds 28800 — not 12 hours
bundle = wrap_in_seal(issuer=sc.issuer, query=build_query(map_id=MAP_ID, target_id=TARGET,
                      from_epoch=0, to_epoch=11, min_strength=2), proof=proof)
print(verify_wrapped(bundle)["ok"])         # True — verified by the Crovia Seal reference, then by TACET
```

## Design notes

- **Sparse Merkle map, depth 256**, domain-separated hashes, compact proofs
  (empty siblings elided by bitmap). Non-inclusion at epoch *e* implies
  non-inclusion at every earlier epoch because slots only move forward.
- **Delta-encoded non-inclusion chains**: one full path, then per-epoch
  sibling changes. In the fixture, 11 deltas carry 3 hashes in total.
- **Temporal sandwich**: each epoch sheet embeds the drand round taken at
  epoch open (lower bound) and is OpenTimestamps-anchored after close (upper
  bound). Verification hooks `beacon_check` / `ots_check` are pluggable; the
  result carries an explicit warning when they are absent.
- **Commit-then-reveal**: a vendor may pre-register `H(summary || salt)` and
  reveal at release. A committed slot cannot be proven silent.
- **Fail-closed**: unknown fields, missing sheets, overstated silence,
  mismatched beacon rounds and insufficient witnesses are all rejected; see
  `conformance/vectors/v1/invalid_001.json`.

## Status

v0.1-draft. The reference passes its own conformance suite and round-trips
through the Crovia Seal reference verifier. Not yet running against the live
Crovia Substrate; that integration lives in `crovia-core-engine`.
