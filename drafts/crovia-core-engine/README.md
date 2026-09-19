# Crovia Core Engine — the Substrate

[![CI](https://github.com/croviatrust/crovia-core-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/croviatrust/crovia-core-engine/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

**Crovia records what AI providers disclose about training data, and the
absence of it, as signed, Bitcoin-anchored facts.** This repository is the
Crovia Substrate: the collectors that observe public surfaces, the observer
that turns fetches into signed envelopes, the sealer that Merkle-seals the
AXIOM ledger every hour, the anchoring job that commits roots to Bitcoin via
OpenTimestamps, and the builders that publish `croviatrust.com/registry/`.

## What the ledger contains

| Envelope | Meaning |
|---|---|
| `AX.OBS` | An observation of a public surface (model card, documentation page, repository) at a point in time. |
| `AX.NEC` | A necessary-disclosure check: what the surface was expected to carry and whether it did. |
| `AX.ABS` | A negative observation: no contemporaneous disclosure satisfying the published predicate was found. |
| `AX.LAC` | A LACUNA record for an AI model: a signed statement over a window of `AX.ABS`. Only model targets (`org/model`) count. |

Every envelope is Ed25519-signed by the observer key in
`registry/data/substrate/trust_root.json`; every hour the ledger's Merkle root
is published in `latest_seal.json`; new roots are stamped with OpenTimestamps
and listed in `ots_anchors.json` once confirmed in Bitcoin.

Headline figures shown on the site are defined in
[CANON.md §4](https://github.com/croviatrust/countersign/blob/main/CANON.md)
and recomputable from the public data files; `ops/phase0/` contains the
post-processors that enforce those definitions.

## Layout

```
crovia/            CLI (`crovia-verify`, `crovia-run`) and library
substrate/         observer, sealer, anchoring, public index builders
collectors/        surface collectors (Hugging Face, vendor docs, Wayback)
ops/               deployment, nginx, cron, smoke, phase0 post-processors
schemas/           JSON schemas for envelopes and public files
tests/             pytest; CI runs on every push
legacy/            2025 royalty / CRC-1 evidence-pack engine (frozen; `pip install crovia==1.1.0`)
```

## Run locally

```bash
pip install -e .[dev]
pytest
crovia-verify registry/data/substrate/latest_seal.json --ledger axiom_ledger.jsonl
```

`crovia-verify` recomputes the Merkle root of a ledger file and checks it
against a published seal and, when an OTS proof is given, against Bitcoin.

## Deployment

The server pulls from `main`; nothing is copied by hand. `ops/DEPLOY.md`
describes the hourly pipeline (collect → observe → seal → build → post-process
→ smoke) and the cron schedule. Public routes and data files are those listed
in the canon; anything else returns 301 or 403.

## Status

- Substrate: live since 2026-01; hourly seals.
- Collectors: see `registry/data/substrate/collectors.json` for per-collector
  last run. Collectors that have not run in 7 days are reported as paused on
  the site, and silence figures stop accruing for their targets.
- LACUNA issuance: paused since 2026-06; resumes on TACET observers
  (`countersign/tacet`), which bind every negative observation to a public
  randomness round and a Bitcoin anchor.

## Crovia surfaces

| Surface | URL |
|---|---|
| Ledger and registry | https://croviatrust.com/registry/ |
| LACUNA (absence records) | https://croviatrust.com/registry/lacuna/ |
| Crovia Seal: spec, verifier, log | https://croviatrust.com/registry/seal/ |
| Issuer trust root | https://seal.croviatrust.com/trust-root.json |
| Machine-readable index | https://croviatrust.com/llms.txt |
| MCP server | https://croviatrust.com/mcp |
| Canon (source of truth for all of the above) | https://github.com/croviatrust/countersign/blob/main/CANON.md |

Repositories: [crovia-seal](https://github.com/croviatrust/crovia-seal) (the standard) ·
[crovia-core-engine](https://github.com/croviatrust/crovia-core-engine) (the substrate) ·
[countersign](https://github.com/croviatrust/countersign) (witnessing and TACET) ·
[crovia-evidence-lab](https://github.com/croviatrust/crovia-evidence-lab) (public data) ·
[causari](https://github.com/croviatrust/causari) (sibling product: code provenance).

Crovia records facts about public surfaces. It does not infer intent, allege
wrongdoing or enforce compliance. Contact: info@croviatrust.com.
