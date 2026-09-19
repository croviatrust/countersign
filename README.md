# Crovia — canon, TACET, and the path back to consistency

**Crovia records what AI providers disclose about training data, and the
absence of it, as signed, Bitcoin-anchored facts.**

This workspace holds the material that brings every Crovia surface back into
agreement and gives the project its new core protocol. It is laid out to be
moved into `croviatrust/countersign` with a copy; no new repository is needed.

```
CANON.md                 Single source of truth: names, the one Seal format, headline-number
canon/canon.json         definitions, complete endpoint list, retired paths, repo roles, wording
tacet/                   TACET: verifiable silence proofs — SPEC.md, Python reference, conformance
tools/audit_surfaces.py  Audits the LIVE surfaces against the canon and writes a report
reports/                 Audits of 2026-09-19: baseline 3 critical / 17 high → latest 0 critical / 3 high
ops/phase0/              Server-side post-processors that make the live numbers true today
drafts/                  Mirrored READMEs for the four active repos, llms.txt, apply plan
.github/workflows/       Tests, conformance, vector determinism, canon checks, weekly audit
```

## Why

An audit of the live surfaces on 2026-09-07 found three incompatible objects
all called "Crovia Seal", a home page counting collector heartbeats as LACUNA
certificates, a silence figure that kept growing five months after the last
observation, a Bitcoin anchoring job stamping the same July root 38 times,
and a mirror serving different HTML. Each is fixed here in the order that
keeps every surface consistent at every step (`drafts/README.md`).

## What TACET adds

Transparency logs prove presence. TACET is a transparency log whose product
is a portable, offline-verifiable proof of **absence over time**: the slot of
a model in a sparse Merkle map was empty across a contiguous range of
epochs, each bounded below by a drand round and above by a Bitcoin block,
with a negative surface snapshot bound to every counted epoch and k-of-n
witness countersignatures on every epoch head. Silence never accrues without
an anchored negative observation. The proof is delivered as an unmodified
`crovia.seal.v1`. See `tacet/SPEC.md` and `tacet/README.md`.

## Run

```bash
git clone --depth 1 https://github.com/croviatrust/crovia-seal /tmp/crovia-seal
pip install -e /tmp/crovia-seal/reference/python -e "tacet/reference/python[test]"
(cd tacet/reference/python && python3 -m pytest -q)  # 28 passed
python3 tacet/conformance/run_conformance.py         # 28 passed, 0 failed
python3 tools/audit_surfaces.py                      # ~4 min, writes reports/
```

## Status 2026-09-19

Applied and pushed as Crovia Trust: `countersign` (canon, TACET, audit tool), `crovia-seal`
(one Seal format, conformant `seal-svc` in production, draft-01 profile classifier merged),
`crovia-core-engine` (README, CI, `ops/phase0`, indeterminate-acquisition fix merged),
`crovia-evidence-lab` (README; hourly sync repaired after a four-month stall). Live
surfaces: LACUNA 0, silence observation-bounded, anchors counted as distinct roots,
retired paths redirect, mirror normalised. Remaining high findings are time-bound: the two
OTS items clear after the 04:30 refresh promotes today's stamped roots; the LACUNA-candidates
item clears only when observation resumes (TACET observers).

Open decisions for the maintainer:

- `crovia-core-engine` branches `public/evidence-first-surface` (a parallel `public-site/`
  claims surface), `site/webroot-mirror`, `feat/claim-evaluation-spec`: not merged; they
  would add a second source of truth next to the canon.
- `snapshots/global_ranking.json` is published hourly in `crovia-evidence-lab` (CC-BY-4.0)
  while `/registry/data/global_ranking.json` is labelled professional-tier and returns 403.
  Either stop syncing it or make it public; the canon must say which.
- Old backups on the data volume (`safety_backups` 4.5 GB, pre-retrofit ledger copy,
  `evidence-lab-pre-filter-*.tar.gz`) still await a keep/delete decision.

## Identity

All commits are authored by `Crovia Trust <info@croviatrust.com>`.
Specification texts are CC0; code is Apache-2.0.
