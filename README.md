<p align="center">
  <img src="https://croviatrust.com/logo.png" width="72" alt="">
</p>

<h1 align="center">TACET — verifiable silence for AI training disclosure</h1>

<p align="center">
  <a href="https://croviatrust.com/registry/tacet/"><b>Live log</b></a> ·
  <a href="tacet/SPEC.md">Specification</a> ·
  <a href="https://croviatrust.com/whitepaper.html">Whitepaper</a> ·
  <a href="https://croviatrust.com/registry/lacuna/">LACUNA candidates</a> ·
  <a href="CANON.md">Canon</a>
</p>

<p align="center">
  <a href="https://github.com/croviatrust/countersign/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/croviatrust/countersign/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Spec" src="https://img.shields.io/badge/TACET-v0.1--draft-1ec5ff">
  <img alt="Seal" src="https://img.shields.io/badge/wraps-crovia.seal.v1-1ec5ff">
  <img alt="License" src="https://img.shields.io/badge/code-Apache--2.0-lightgrey">
  <img alt="Spec license" src="https://img.shields.io/badge/spec-CC0-lightgrey">
</p>

Transparency logs prove that something **was** published. TACET is a transparency
log whose product is the opposite: a portable, offline-verifiable proof that, for a
given AI model, **no training-data disclosure was found on its public surfaces in
any of these hours** — each hour opened by a public randomness beacon and closed by a
Bitcoin block.

It runs in production. Every hour since `2026-09-19T18:00Z`, Crovia's operator fetches
the model cards of the systems under watch, runs a public predicate over the bytes,
signs what it saw, commits the verdicts to one sparse Merkle map, and anchors the
epoch in Bitcoin. When a lab stays silent, the silence stops being an opinion.

## Verify a live proof in 30 seconds

```bash
git clone https://github.com/croviatrust/countersign
git clone https://github.com/croviatrust/crovia-seal
pip install -e countersign/tacet/reference/python -e crovia-seal/reference/python -e countersign/tacet/operator
pip install opentimestamps-client   # optional: verifies the Bitcoin anchors too

curl -sO https://croviatrust.com/registry/data/tacet/proofs/mistralai__Mistral-7B-v0.1.seal.json
tacet-operator verify mistralai__Mistral-7B-v0.1.seal.json
```

```json
{
 "ok": true,
 "seal_ok": true,
 "issuer_id": "urn:crovia:seal-issuer:tacet",
 "seal_id": "cs_2026_RNJ7YAYIYQATT4CSBMVB5RJYNY",
 "strength_verified": 2,
 "silence": { "map_epochs": 2, "observed_epochs": 0, "observed_to": null, "silence_days": "0.00" },
 "errors": []
}
```

(Output from the first day of the log: two epochs in the map, none yet confirmed in
Bitcoin, so `observed_epochs` is 0 and the silence figure is 0.00 — by construction.
The featured proofs are rebuilt daily; the numbers grow only as anchors confirm.)

The verifier recomputes every map root from the empty tree, checks the chain of
sheets, checks that each drand round matches its epoch start, fetches each
OpenTimestamps proof and verifies it against the sheet hash, verifies the observer
signature on every negative snapshot and its Merkle inclusion in the hour, and
recomputes the silence figure. No Crovia server is trusted at any step.

## How an hour becomes evidence

```
   drand round r ─────▶  epoch e  ─────▶  Bitcoin block h
   (not before T₁)          │              (not after T₂)
                            │
      fetch card ──▶ predicate(bytes) ──▶ signed snapshot ──▶ snapshots_root
                                                  │
                                       slot(model) in sparse Merkle map
                                                  │
                     sheet = { root, prev_sheet_hash, beacon, snapshots_root }  ── signed, then OTS-anchored
```

A **silence proof** for one model over epochs `[a, b]` is the delta-encoded chain of
non-inclusion paths for its slot, plus one negative snapshot per counted hour, wrapped
in a [`crovia.seal.v1`](https://github.com/croviatrust/crovia-seal). Three strengths:

| Level | Name | Proves |
|---|---|---|
| 1 | `map-silence` | the slot was empty in the map in every epoch — says nothing about the world |
| 2 | `surface-silence` | + a negative, beacon-bound, signed snapshot exists for every counted, **anchored** epoch |
| 3 | `witnessed-silence (k/n)` | + every epoch sheet carries ≥ k countersignatures from independent witnesses |

**Monotonicity rule.** `silence_days` is the sum of anchored epochs that hold a negative
snapshot. Hours nobody looked, hours not yet in Bitcoin, and operator downtime add
nothing. Silence cannot grow while observation is paused, and any verifier can
recompute it from the proof alone.

## What TACET does not say

Nothing about intent ("hid", "refused" never appear). Nothing about surfaces that were
not listed. Nothing about hours in which nobody looked. Nothing about quality: the
predicate is deliberately permissive — a `datasets:` tag counts as disclosure. A
level-2 proof is a proof about what was served to the observer; level 3 (independent
witnesses) is the next milestone.

Providers are protected too: a model can **commit-then-reveal** its training-data
summary (SPEC §11). A committed slot can never yield a silence proof.

## Repository

```
tacet/SPEC.md                    The protocol, v0.1-draft (CC0)
tacet/reference/python/          Reference implementation: SMT, epoch sheets, snapshots, proofs, Seal wrapping
tacet/conformance/               Deterministic vectors + 28-case runner — port this to other languages
tacet/operator/                  Production operator: run-epoch, refresh-anchors, publish, prove, verify
tacet/operator/tacet_operator/predicates/   Public predicates with real-card vectors
CANON.md, canon/canon.json       Single source of truth for every Crovia surface: names, formats, numbers, endpoints
tools/audit_surfaces.py          Audits the live site against the canon
site/                            Sources of croviatrust.com
src/countersign/                 Original countersign: CT-style Merkle log + signed tree heads (witness role)
```

```bash
cd tacet/reference/python && python -m pytest -q      # reference: 28 passed
cd tacet/operator          && python -m pytest -q      # operator: predicate vectors, fake-network epochs, proof round-trip
python tacet/conformance/run_conformance.py            # 28 passed, 0 failed
```

## Public data

Everything the operator produces is public, CC-BY-4.0, browsable and CORS-open under
[`/registry/data/tacet/`](https://croviatrust.com/registry/data/tacet/):

| File | Contents |
|---|---|
| `latest.json` | latest epoch sheet summary; totals since genesis |
| `targets.json` | per model: last verdict, negative and anchored-negative epochs |
| `trust_root.json` | operator / observer / issuer keys, map id, genesis, drand chain |
| `sheets/<e>.json`, `snapshots/<e>/…`, `ots/<e>.ots` | every sheet, every signed snapshot, every Bitcoin proof |
| `proofs/index.json` | featured level-2 silence proofs, rebuilt daily |

## Run your own witness or observer

The operator is a plain Python package. `tacet-operator run-epoch --targets targets.txt`
opens an epoch, observes, commits, signs and stamps; `refresh-anchors` closes epochs
once Bitcoin confirms; `publish` writes the discovery files; `prove` builds a proof for
any target and range. A second observer for the same target and epoch strengthens a
level-2 proof; a witness countersigning epoch sheets is what turns it into level 3 —
open an issue if you want to run one.

## Status

| | |
|---|---|
| Live operator | croviatrust.com, hourly, since 2026-09-19 18:00 UTC |
| Predicate | `crovia.pred.hf-card-training-data` 1.0.0 (Hugging Face model cards) |
| Anchoring | OpenTimestamps → Bitcoin; refreshed every 6 h |
| Proof strength in production | 2 (level 3 needs independent witnesses — planned) |
| Seal format | `crovia.seal.v1`, IETF `draft-crovia-seal`, unmodified |

## Cite

> Crovia Trust. *TACET: Verifiable Silence for AI Training Disclosure*, v0.1-draft, 2026.
> https://github.com/croviatrust/countersign/blob/main/tacet/SPEC.md

See [`CITATION.cff`](CITATION.cff). Contact: info@croviatrust.com · security: see [`SECURITY.md`](SECURITY.md).

## License

Code Apache-2.0. Specification texts CC0. Public data CC-BY-4.0.
All commits are authored by Crovia Trust.
