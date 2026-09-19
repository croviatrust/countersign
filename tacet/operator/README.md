# TACET operator

Runs the TACET log in production. The [reference](../reference/python) defines
the objects; this package fetches, signs, anchors and publishes them.

```
every hour   tacet-operator run-epoch        drand round → observe surfaces → update map → sign sheet → OTS stamp
every 6 h    tacet-operator refresh-anchors  upgrade OTS proofs; close sheets confirmed in Bitcoin
daily        tacet-operator publish --proofs rebuild featured silence proofs (crovia.seal.v1)
```

## What one epoch does

1. Fetches the current **drand** round (chain `8990e7…`, pinned in `trust_root.json`).
   Nothing in the epoch could have existed before that round: lower time bound.
2. Fetches the surfaces of the featured targets and of a rotating slice of the
   target list (default 120 per hour, 0.6 s apart, `crovia-tacet-observer` user
   agent). Surface = the raw model card `…/raw/main/README.md`; for gated
   repositories (401/403) the rendered model page.
3. Runs the public predicate `crovia.pred.hf-card-training-data 1.0.0`
   ([source](tacet_operator/predicates/hf_card_training_data_v1.py), hashed
   byte-for-byte into every snapshot) on the bytes and signs a **snapshot**
   with the observer key. Non-200 responses produce no snapshot: a fetch failure
   is indeterminate, never absence.
4. Applies forward-only slot transitions: a positive snapshot for an empty slot
   inserts a `disclosure` value; two consecutive negatives for a disclosed slot
   insert a `retraction`. Every value is asserted by a `crovia.seal.v1` signed
   with the Seal-issuer key (`values/<key>.json`).
5. Signs the **epoch sheet** (root, size, `snapshots_root`, `opened` beacon,
   `prev_sheet_hash`) with the operator key and stamps `sheet_hash` with
   OpenTimestamps. When the calendar reaches Bitcoin, `refresh-anchors` fills
   `closed` (block height, block time, proof URL): upper time bound.

The operator is the only writer; all changes of an epoch are applied in one
batch, so the sheet's root is the root at `epoch_end`. Missed hours are
back-filled with empty sheets (historical drand round): the chain stays
contiguous and those hours contribute no silence.

## Silence proofs

```
tacet-operator prove mistralai/Mistral-7B-v0.1 --strength 2 -o proof.seal.json
tacet-operator verify proof.seal.json --operator-pubkey <key_hex from trust_root.json>
```

A proof carries every sheet in the range, the delta-encoded non-inclusion
path, the negative snapshots with their Merkle inclusion in each epoch's
`snapshots_root`, and the `silence` block recomputed by the verifier:
`silence_seconds` = sum of the durations of anchored epochs that hold a negative
snapshot for the target. Unobserved, unanchored or unreachable hours count
zero. The bundle is wrapped in an unmodified `crovia.seal.v1`.

## Keys

Three Ed25519 seeds in `state/keys/` (mode 0600), created on first run:
`operator` (signs sheets), `observer` (signs snapshots), `issuer`
(`urn:crovia:seal-issuer:tacet`, signs Seals: value assertions and proofs).
Public keys are published in `trust_root.json`.

## Install

```bash
pip install -e ../reference/python -e <crovia-seal>/reference/python -e .
TACET_STATE=/opt/crovia/tacet/state TACET_PUBLIC=/var/www/registry/data/tacet tacet-operator keys
```

Tests: `pytest -q tests` (predicate vectors are real model cards; the epoch
test uses a fake network, fake drand and fake OTS).
