# Countersign · TACET

[![CI](https://github.com/croviatrust/countersign/actions/workflows/ci.yml/badge.svg)](https://github.com/croviatrust/countersign/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Spec: CC0](https://img.shields.io/badge/Spec-CC0-lightgrey.svg?style=flat-square)](https://creativecommons.org/publicdomain/zero/1.0/)

**Crovia records what AI providers disclose about training data, and the
absence of it, as signed, Bitcoin-anchored facts.** This repository is the
witness protocol and the home of **TACET**, the transparency log in which
*non-inclusion* (silence) is a first-class, portable, offline-verifiable
proof.

## Two things live here

### Countersign — independent witnessing

Self-signed evidence proves nothing in a dispute. Countersign is the missing
party: an independent witness that countersigns and timestamps evidence
digests in an append-only Merkle log (RFC 6962 construction) and lets anyone
verify a single entry offline. Certificate Transparency, for what AI systems
did and for what Crovia observed.

```bash
pip install -e ".[dev]"
python examples/demo.py            # append, countersign, export a proof, verify it offline
countersign --help
```

Protocol: `SPEC.md`. Roadmap: `ROADMAP.md`. Security policy: `SECURITY.md`.

### TACET — verifiable silence

Existing transparency logs prove presence. TACET proves **absence over
time**: that for a given AI model no training-data disclosure existed in the
log, and none was found on the model's monitored public surfaces, across a
contiguous range of epochs each bounded below by a drand randomness round and
above by a Bitcoin block.

- `tacet/SPEC.md` — the protocol (v0.1-draft, CC0)
- `tacet/reference/python` — reference implementation
- `tacet/conformance/` — deterministic vectors and a 28-case runner

A TACET silence proof is delivered as an unmodified `crovia.seal.v1` object:
the query is the Seal's input, the proof its output, the drand round its
anchor, the witnesses its countersignatures. Any Seal verifier can check the
outer layer; a TACET verifier checks the rest, offline.

```python
from tacet import verify_wrapped
import json
print(verify_wrapped(json.load(open("llama-3.1-8b.silence.json")))["silence"])
# {'observed_epochs': 2117, 'silence_seconds': 7621200, 'silence_days': '88.21', 'observed_to': '…'}
```

Silence never accrues without an anchored negative observation (SPEC §8.4).
Three strength levels: map-silence, surface-silence, witnessed-silence (k/n).

## Relationship to LACUNA

LACUNA on `croviatrust.com` is the human-readable view of absence records.
TACET is the protocol that makes each of those records a verifiable object
with a defined unit, an explicit scope (surfaces + predicate) and a temporal
sandwich. Countersign witnesses provide the k/n countersignatures.

## Status

- Countersign: v0.1, single-operator log.
- TACET: v0.1-draft; reference passes conformance and round-trips through the
  Crovia Seal reference verifier; first anchored epoch pending on the
  substrate integration in `crovia-core-engine`.

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
