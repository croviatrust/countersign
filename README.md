<p align="center">
  <a href="https://croviatrust.com/registry/tacet/"><img src=".github/social-preview.png" width="720" alt="TACET — verifiable silence. Hourly, signed, Bitcoin-anchored proofs that an AI model published no training-data disclosure."></a>
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
  <a href="https://croviatrust.com/registry/tacet/"><img alt="TACET epochs (live)" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fcroviatrust.com%2Fregistry%2Fdata%2Ftacet%2Fbadges%2Fepochs.json"></a>
  <a href="https://croviatrust.com/registry/data/tacet/targets.json"><img alt="models observed (live)" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fcroviatrust.com%2Fregistry%2Fdata%2Ftacet%2Fbadges%2Fmodels.json"></a>
  <a href="https://croviatrust.com/registry/data/tacet/latest.json"><img alt="signed observations of absence (live)" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fcroviatrust.com%2Fregistry%2Fdata%2Ftacet%2Fbadges%2Fnegative.json"></a>
</p>
<p align="center">
  <a href="https://pypi.org/project/crovia-tacet/"><img alt="PyPI crovia-tacet" src="https://img.shields.io/pypi/v/crovia-tacet?label=crovia-tacet&color=1ec5ff"></a>
  <a href="https://pypi.org/project/crovia-tacet-operator/"><img alt="PyPI crovia-tacet-operator" src="https://img.shields.io/pypi/v/crovia-tacet-operator?label=crovia-tacet-operator&color=1ec5ff"></a>
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

**In the browser, nothing to install, including the Bitcoin anchors:**
[croviatrust.com/registry/seal/verify/?url=…Qwen__Qwen3-32B.seal.json](https://croviatrust.com/registry/seal/verify/?url=https%3A%2F%2Fcroviatrust.com%2Fregistry%2Fdata%2Ftacet%2Fproofs%2FQwen__Qwen3-32B.seal.json)
— `site/registry/seal/verify/tacet-verify.js` + `ots-verify.js` are a second, independent
implementation of SPEC §8.5–8.6 in plain JS on WebCrypto. With network checks on, the page
parses every OpenTimestamps proof itself and compares its merkle root with the Bitcoin
block header from a public explorer. No Bitcoin node, no `ots` client, no Crovia server
trusted.

**On the command line, same checks, pure Python, standard library only for the anchors:**

```bash
pip install crovia-tacet-operator crovia-seal

curl -sO https://croviatrust.com/registry/data/tacet/proofs/Qwen__Qwen3-32B.seal.json
tacet-operator verify Qwen__Qwen3-32B.seal.json
```

```json
{
 "ok": true,
 "seal_ok": true,
 "issuer_id": "urn:crovia:seal-issuer:tacet",
 "strength_verified": 2,
 "silence": { "map_epochs": 3, "observed_epochs": 3,
              "observed_from": "2026-09-19T18:00:00Z", "observed_to": "2026-09-19T21:00:00Z",
              "silence_seconds": 10800, "silence_days": "0.12" },
 "anchors": [
  "block 967736 merkle root a27c668a4d320942f8cb3906efbfefefaedda9d760d5d52bdb74f7a7e0f1a0d4 matches the proof",
  "block 967736 merkle root a27c668a4d320942f8cb3906efbfefefaedda9d760d5d52bdb74f7a7e0f1a0d4 matches the proof",
  "block 967740 merkle root a41b0f50275c48922c27d6335434b5afb91ddc4bb4f80e9d96edd1e9f3b16af7 matches the proof"
 ],
 "errors": [], "warnings": []
}
```

(Output from the first three hours of the log, all three confirmed in Bitcoin blocks
967736 and 967740. `silence_days` is truncated, never rounded: 10 800 s is `0.12`.)

The verifier recomputes every map root from the empty tree, checks the chain of
sheets, checks that each drand round matches its epoch start, parses each
OpenTimestamps proof and matches its merkle root to the Bitcoin block header,
verifies the observer signature on every negative snapshot and its Merkle inclusion
in the hour, and recomputes the silence figure. Run a node? Pass your own header
source to `tacet.ots.verify_sheet_anchor`; the explorer is only the default.

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

## PNX — the same machine, pointed at agents (draft)

TACET proves what a public surface did not contain. **PNX — Proof of
Non-Exfiltration** (`tacet/PNX.md`, profile `crovia.pnx.v1`) proves what an AI
agent did not send out. An egress witness fingerprints every outbound body
(salted 32-byte k-grams, winnowed with window 16), commits the fingerprints to
the same sparse Merkle map and signs a run sheet; the operator then proves, per
protected asset, non-inclusion against the run root. Any shared substring of
47 bytes or more is always detected; shorter assets are reported as `partial`
or `undetectable` and never counted as clean. The run root is committed into a
TACET epoch, so it inherits the drand opening and the Bitcoin closing.

The auditor sees neither the traffic nor the secrets and verifies offline:

```python
from tacet import egress
from tacet.keys import SigningKey

w = egress.EgressWitness(run_id="ci-4711/agent-review")
w.ingest(request_body, "2026-09-19T22:00:03Z")            # for every outbound body
sheet = w.sheet(SigningKey.generate("witness-ci"), "2026-09-19T22:59:59Z")
proof = w.prove(sheet, [("openai_key", b"sk-live-..."), ("customers.csv", open("customers.csv","rb").read())])
egress.verify_pnx(proof, {"openai_key": b"sk-live-...", "customers.csv": ...}).verdict   # 'absent' | 'present' | 'mixed'
```

Status: reference + tests shipped; conformance vectors, browser verifier and a
one-command `tacet-egress` proxy are next (see `GROWTH.md`).

## Repository

```
tacet/SPEC.md                    The protocol, v0.1-draft (CC0)
tacet/PNX.md                     Proof of Non-Exfiltration profile for agent egress, draft 0.1
tacet/reference/python/          Reference implementation: SMT, epoch sheets, snapshots, proofs, Seal wrapping
tacet/conformance/               Deterministic vectors + real Bitcoin-anchored .ots vectors; 47-case runner (Python) + 20-case Node runner for the browser verifier — port this to other languages
tacet/operator/                  Production operator: run-epoch, refresh-anchors, publish, prove, verify
tacet/operator/tacet_operator/predicates/   Public predicates with real-card vectors
CANON.md, canon/canon.json       Single source of truth for every Crovia surface: names, formats, numbers, endpoints
tools/audit_surfaces.py          Audits the live site against the canon
site/                            Sources of croviatrust.com; site/registry/seal/verify/tacet-verify.js is the browser verifier
src/countersign/                 Original countersign: CT-style Merkle log + signed tree heads (witness role)
```

```bash
cd tacet/reference/python && python -m pytest -q      # reference: 43 passed (incl. PNX)
cd tacet/operator          && python -m pytest -q      # operator: predicate vectors, fake-network epochs, proof round-trip
python tacet/conformance/run_conformance.py            # 47 passed, 0 failed
node   tacet/conformance/run_conformance_js.cjs        # browser verifier against the same vectors: 20 passed
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
| Anchoring | OpenTimestamps → Bitcoin; refreshed every 2 h; verifiable without a node (SPEC §8.6) |
| Proof strength in production | 2 (level 3 needs independent witnesses — planned) |
| Seal format | `crovia.seal.v1`, IETF `draft-crovia-seal`, unmodified |

## Cite

> Crovia Trust. *TACET: Verifiable Silence for AI Training Disclosure*, v0.1-draft, 2026.
> https://github.com/croviatrust/countersign/blob/main/tacet/SPEC.md

See [`CITATION.cff`](CITATION.cff). Contact: info@croviatrust.com · security: see [`SECURITY.md`](SECURITY.md).

## License

Code Apache-2.0. Specification texts CC0. Public data CC-BY-4.0.
All commits are authored by Crovia Trust.
