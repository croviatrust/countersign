# PNX — Proof of Non-Exfiltration · GitHub Action

**Prove that your secrets, customer data and source files never left an AI agent's run.**
Not a log you have to trust: a portable proof anyone can verify offline.

[![Spec](https://img.shields.io/badge/spec-crovia.pnx.v1-0ea5e9)](https://croviatrust.com/registry/tacet/spec/#pnx)
[![Internet-Draft](https://img.shields.io/badge/IETF-draft--crovia--tacet-lightgrey)](https://datatracker.ietf.org/doc/draft-crovia-tacet/)
[![PyPI](https://img.shields.io/pypi/v/crovia-tacet?label=crovia-tacet)](https://pypi.org/project/crovia-tacet/)

Enterprises run coding agents with read access to source, secrets and customer data.
When an auditor or an incident asks *"did any of this leave?"*, the only answer today is
the vendor's own log. PNX gives you a signed statement of the form **"during this run,
none of these protected assets appeared in the agent's outbound traffic"** that a
regulator, a customer or your own security team can check without trusting you, the
vendor, or GitHub.

PNX is a profile of [TACET](https://croviatrust.com/registry/tacet/spec/), the
verifiable-silence protocol by [Crovia Trust](https://croviatrust.com). The proof is
delivered as an unmodified [`crovia.seal.v1`](https://croviatrust.com/registry/seal/spec/).

## How it works

1. **Witness.** Everything the agent sent out (captured by your LLM gateway, proxy, or
   the agent's own request log) is cut into 32-byte k-grams, hashed with a per-run salt and
   winnowed. The fingerprints are committed to a sparse Merkle map; the **run sheet**
   (root, salt, byte and body counts, timestamps) is signed by the witness key.
2. **Prove.** For each protected asset the prover recomputes the asset's fingerprints and
   attaches a non-inclusion path against the run root. If a fingerprint *is* in the map, the
   inclusion path is attached instead: the same object becomes evidence of exposure.
3. **Verify.** Anyone with the proof and the assets re-derives every fingerprint and checks
   every path against the signed root. Nothing about the traffic, and nothing about the
   assets beyond their SHA-256, is in the proof.

Guarantee: any shared substring of **≥ 47 bytes** between an asset and the egress is always
detected, in the raw bytes and inside the decoded string values of JSON request bodies
(`json-strings-v1`, declared in the run sheet). Shorter assets are reported as `absent-partial` (best effort) or `undetectable`
and are **never counted as clean**.

## Usage

```yaml
- name: Run the agent behind a capturing gateway
  run: ./scripts/run-agent.sh          # writes request bodies to ./egress/*.json or a gateway .jsonl log

- name: Prove non-exfiltration
  uses: croviatrust/pnx-action@v1
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}     # only needed so it can be protected below
    STRIPE_KEY:     ${{ secrets.STRIPE_KEY }}
  with:
    egress: |
      egress/
      logs/gateway.jsonl
    assets: |
      data/customers.csv
      src/billing/
    asset-env: |
      OPENAI_API_KEY
      STRIPE_KEY
    witness-seed: ${{ secrets.PNX_WITNESS_SEED }}      # openssl rand -hex 32, once
```

The step fails when any asset is `present` (or cannot be covered), writes a table to the
job summary, and uploads `run.sheet.json` + `pnx.proof.json` as the `pnx-proof` artifact.

Verify the artifact anywhere:

```bash
pip install crovia-tacet
tacet-pnx verify pnx.proof.json --assets-dir src/billing --asset data/customers.csv=data/customers.csv
# VALID · verdict absent · run acme/agent-ci/8123/1 · witness urn:github:acme/agent-ci:pnx-witness
```

Exit codes: `0` valid and every asset absent · `1` valid but something present, undetectable
or partial · `2` proof invalid.

### Inputs

| input | default | what |
|---|---|---|
| `egress` | — | files (one body each), directories, or `.jsonl` capture logs (`{"at","body"}` or `{"body_b64"}`) |
| `assets` | | protected files or directories, one per line |
| `asset-env` | | env var names whose values must not appear (labels become `env:NAME`) |
| `run-id` | `owner/repo/run_id/attempt` | run identifier in the sheet |
| `witness-id` | `urn:github:owner/repo:pnx-witness` | witness key id |
| `witness-seed` | ephemeral | hex 32-byte Ed25519 seed (secret); stable identity across runs |
| `seal-seed` | | issuer seed; delivers the proof inside a `crovia.seal.v1` |
| `fail-on-present` | `true` | fail unless every asset is `absent` |
| `output-dir` | `pnx` | where the sheet, proof and private state go (state is deleted after proving) |
| `upload-artifact` / `artifact-name` | `true` / `pnx-proof` | artifact upload |

Outputs: `verdict`, `proof`, `sheet`, `root`.

### Capturing egress

The witness attests **only what it saw**. Point `egress` at the place where the agent's
outbound bodies are visible in clear:

- an LLM gateway or proxy log (LiteLLM, Portkey, Helicone, Envoy, mitmproxy) exported as
  `.jsonl` with one `{"at": ..., "body": ...}` object per request;
- the agent's own request log or transcript directory;
- a CI sidecar that tees requests to files.

Traffic that bypasses the capture point is outside the proof. This is stated in the sheet
(`egress.bodies`, `egress.bytes`) and in the specification:
[what a PNX proof does not claim](https://croviatrust.com/registry/tacet/spec/#pnx-7-what-a-pnx-proof-does-not-claim).

## What the proof does *not* say

- Nothing about traffic the witness did not see.
- Nothing about paraphrase, translation or re-encoding the witness did not normalise.
- Nothing about assets shorter than 32 bytes (`undetectable`), and only best effort for
  assets between 32 and 46 bytes (`absent-partial`).
- The proof commits to the SHA-256 of each asset. For low-entropy assets treat the proof
  as confidential; for API keys and files this is not a concern.

## Related

- Specification: <https://croviatrust.com/registry/tacet/spec/> (TACET core + PNX profile, Internet-Draft `draft-crovia-tacet-00`, 47 conformance tests)
- CLI and reference implementation: [`crovia-tacet` on PyPI](https://pypi.org/project/crovia-tacet/) · [source](https://github.com/croviatrust/countersign/tree/main/tacet)
- Crovia Seal: <https://croviatrust.com/registry/seal/>
- Crovia Trust: <https://croviatrust.com> · info@croviatrust.com

Apache-2.0. Specification text CC0.
