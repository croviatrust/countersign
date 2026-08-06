# Countersign

**Independent witnessing for AI agent evidence.**
Self-signed audit logs prove nothing in a dispute — whoever holds the key and
the storage can rewrite history. Countersign adds the missing party: an
independent witness that countersigns and timestamps your evidence digests in
an append-only Merkle log, and lets anyone verify a single entry **offline**.

Think *Certificate Transparency, but for what AI agents did*.

## The problem

AI agents now send emails, issue refunds, deploy code, and modify records. A
new generation of tools (receipt SDKs, MCP gateways, compliance exporters)
produces hash-chained, signed logs of those actions. All of them share one
structural weakness: **the operator signs their own evidence with their own
key on their own storage.** In a dispute — a chargeback, an incident
postmortem, a regulatory audit, a lawsuit — self-attestation is weak:
the operator could have regenerated the whole chain yesterday and backdated
it. Tamper-*evident* is not tamper-*proof of time*.

Certificate Transparency solved the same problem for TLS certificates with
public append-only logs. Agent evidence has no equivalent. Countersign is
that layer.

## What it does

- **Witness**: append the SHA-256 digest of any evidence artifact (a receipt,
  a JSONL stream, an audit packet, a whole file) to an append-only Merkle log
  (RFC 6962/9162 hashing, the Certificate Transparency construction).
- **Countersign**: every append produces a fresh Ed25519-signed tree head.
- **Prove**: export a self-contained proof bundle for any entry.
- **Verify offline**: anyone with the witness public key verifies the bundle
  with no network, no access to the log, no trust in the operator.

Only digests enter the log — the evidence itself never leaves your machine,
so a public witness is privacy-safe by construction.

## Install

```bash
pip install -e ".[dev]"    # from a clone; PyPI release pending
```

Requires Python ≥ 3.10. Single runtime dependency: `cryptography`.
The `dev` extra adds `pytest`, `ruff`, and `mypy`; CI runs all three:

```bash
ruff check .
mypy
pytest -q
```

## 60-second tour

```bash
# 1. Create a witness log (keypair + empty Merkle tree with signed genesis)
countersign init --log ./witness-log

# 2. Witness evidence — a file, a raw digest, or every line of a JSONL stream
countersign witness --log ./witness-log ./audit_packet.json
countersign witness --log ./witness-log --jsonl ./agent_receipts.jsonl
countersign witness --log ./witness-log --digest 3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855c

# 3. Export an offline-verifiable proof for one piece of evidence
countersign prove --log ./witness-log --digest 3b0c…855c --out proof.json

# 4. Anyone, anywhere, verifies it offline against the pinned public key
countersign verify proof.json --pubkey <witness-public-key-hex>

# 5. Audit the whole log: signatures, roots, append-only history
countersign audit --log ./witness-log
```

Or run the full scripted demo (operator → witness → auditor → tamper attempt):

```bash
python examples/demo.py
```

## Works with what you already have

Countersign is deliberately **format-agnostic**: it witnesses digests, so it
composes with — rather than competes with — the evidence producers you
already use:

| You produce evidence with… | How to witness it |
|---|---|
| Agent Receipts / obsigna, Provedex, RootSign, AEVS | `countersign witness --jsonl receipts.jsonl` |
| Fuze / agenttrace audit packets | `countersign witness packet.json` |
| OpenTelemetry GenAI JSONL exports | `countersign witness --jsonl traces.jsonl` |
| Anything else (PDF report, tarball, DB dump) | `countersign witness <file>` |

Your evidence stays self-signed *and* becomes independently witnessed. The
combination is what holds up: your signature proves authorship, the witness
proves time and immutability.

## Why this matters for compliance

EU AI Act Article 12 requires automatic event recording for high-risk AI
systems; Articles 19/26 require keeping those logs. The regulation does not
say "tamper-proof" — but logs that can be silently altered have near-zero
evidentiary value in front of an auditor or court. Financial services
(SEC/FINRA) and healthcare (HIPAA) retention rules raise the same bar today.
An independent witness answers the question every self-signed log cannot:
*"prove this log wasn't rewritten after the incident."*

## Status

v0.1 — working core (Merkle log, signed tree heads, inclusion + consistency
proofs, offline verifier, CLI, adapters), exhaustive property tests. Not yet
audited; do not treat proofs as legal evidence without reading `SECURITY.md`.

Roadmap highlights (see `ROADMAP.md`): public hosted witness with REST API,
external anchoring (RFC 3161 / Bitcoin via OpenTimestamps), multi-witness
cosigning, MCP server so agents can self-witness, per-format adapters.

## Documentation

- [`SPEC.md`](SPEC.md) — the witness protocol, formats, and verification rules
- [`SECURITY.md`](SECURITY.md) — threat model, what this does and does not prove
- [`ROADMAP.md`](ROADMAP.md) — where this is going
- [`examples/`](examples/) — reproducible demo

## License

Apache-2.0. The protocol specification is open; independent implementations
are explicitly welcome.
