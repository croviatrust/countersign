# Roadmap

Every item is tied to a product hypothesis (H#, see `BUSINESS.md` §validation).

## v0.1 — local witness (done, this repo)
Core Merkle log, signed tree heads, inclusion + consistency proofs, offline
verifier, CLI, file/JSONL/digest adapters, exhaustive tests, demo.
*Hypothesis H1: developers producing agent evidence want independent
witnessing enough to run one command.*

## v0.2 — hosted public witness (1–2 weeks)
- FastAPI service exposing the SPEC §7 endpoints; deploy on the existing
  Crovia server (zero new infra cost).
- Public key pinned in the repo and at the existing trust-root endpoint.
- Rate-limited free tier; abuse controls (digest-only, so risk is low).
- Frozen cross-language test vectors.
*Hypothesis H2: a free public witness converts README readers into users.*

## v0.3 — anchoring and ecosystem adapters (2–4 weeks)
- `countersign anchor`: periodic anchoring of the latest STH via
  OpenTimestamps (Bitcoin) — infrastructure already runs in the Crovia
  substrate — and optional RFC 3161 TSA.
- Named adapters + docs for Agent Receipts/obsigna, Provedex, RootSign,
  Fuze, OTel GenAI JSONL: one-command witnessing per format, with tests.
- MCP server (`countersign-mcp`): agents witness their own evidence
  mid-session; works in Claude Code, Cursor, any MCP client.
*Hypothesis H3: receipt-SDK authors will link to or integrate a neutral
witness rather than build their own.*

## v0.4 — private witnessed logs (paid tier begins)
- Multi-tenant hosted witness: private logs, SLA, retention guarantees,
  export to auditor-ready bundle, org keys.
- `countersign verify --all` batch verification for auditors.
*Hypothesis H4: a team that witnesses in CI/prod will pay 49–199 €/mo for
private logs + retention + SLA.*

## v0.5 — multi-witness and standardization
- Cosigning: one digest, N independent witnesses, k-of-n verification.
- Witness gossip / cross-witnessing of STHs (CT-style).
- Submit the protocol as an Internet-Draft (the Crovia Seal IETF draft
  workflow is already built); align terminology with ISO/IEC 24970 and
  prEN 18229-1 as they stabilize.
*Hypothesis H5: neutrality + multiple witnesses turn the format into the
default interchange for witnessed agent evidence.*

## Explicit non-goals
- Generating or interpreting evidence content (that's the producers' job).
- A dashboard-first product. CLI/API first; UI only when paying users ask.
- Blockchain tokens of any kind.
