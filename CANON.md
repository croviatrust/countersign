# Crovia Canon

The single source of truth for every public surface of Crovia Trust.
If a page, README, package description, data file or API disagrees with
this document, the surface is wrong, not the canon. `canon/canon.json` is
the machine-readable twin of this file; `tools/audit_surfaces.py` checks
the live surfaces against it.

Last revised: 2026-09-19.

---

## 1. Identity

| Field | Value |
|---|---|
| Legal / brand name | **Crovia Trust** |
| Short name | Crovia |
| Domain | `croviatrust.com` (canonical). `registry.croviatrust.com` is a mirror and must serve byte-identical HTML. |
| Seal trust root host | `seal.croviatrust.com` |
| Contact | `info@croviatrust.com` (general), `trust@croviatrust.com` (trust root / key matters) |
| GitHub | `github.com/croviatrust` |
| Git author for all commits | `Crovia Trust <info@croviatrust.com>` |
| One-line description | Crovia records what AI providers disclose about training data, and the absence of it, as signed, Bitcoin-anchored facts. |
| Posture | Observation, not accusation. Crovia records facts about public surfaces; it does not infer intent, allege wrongdoing, or enforce compliance. |
| Sibling product | **Causari** (`causari.dev`, `github.com/croviatrust/causari`): code-provenance tool for AI agents. Causari is the reference production issuer of Crovia Seal. Never describe Causari as part of the Crovia ledger. |

## 2. Products and their canonical names

| Product | Canonical name | What it is | Status word allowed in public copy |
|---|---|---|---|
| The ledger | **Crovia Substrate** (AXIOM ledger) | Append-only log of Ed25519-signed observation envelopes, Merkle-sealed hourly, batch-anchored to Bitcoin via OpenTimestamps. | `live` |
| Absence records | **LACUNA** | A signed statement that, over a defined observation window, no contemporaneous disclosure satisfying a published predicate was found on the monitored surfaces of a target. | `observatory (v0)` until TACET ships. Never `certificate` unless a signed artifact exists for that target. |
| Receipt standard | **Crovia Seal** | Tamper-evident receipt for AI outputs. IETF `draft-crovia-seal-01`. | `standard (Internet-Draft)` |
| Silence proofs | **TACET** | Transparency log for AI training disclosure in which non-inclusion (silence) is a first-class, portable, offline-verifiable proof. | `in development` until the reference passes conformance and the first epoch is anchored. |
| Witnessing | **Countersign** | Independent CT-style witnessing of Crovia epoch heads and surface snapshots. | `v0.1` |
| Code provenance | **Causari** | Sibling product; not part of the ledger. | `live` |

Names retired from public copy: "Hubble", "Global AI Training Omissions" (as a product name), "CROVIA Core Engine — payout layer", "Oracle scanner", "Wedge", "Diamond Archive", "CEP Terminal", "Proof of Non-Training" (unless re-specified).

## 3. Crovia Seal — the one and only format

There is exactly one thing called a Crovia Seal.

| Field | Canonical value |
|---|---|
| `seal_version` | `crovia.seal.v1` |
| `seal_id` | `cs_YYYY_` + 26 base32 chars |
| Signature object | `{"alg":"ed25519","canon":"csc-1","domain":"CROVIA-SEAL-v1","payload_hash_alg":"sha256","sig_hex":"<128 hex>"}` |
| Timestamp | `timestamp.emitted_at` (RFC 3339, ms) + `timestamp.nonce` |
| Canonicalization | CSC-1 (strict RFC 8785 subset, no floats) |
| Spec | `crovia-seal/SPEC.md` v0.5, `draft-crovia-seal-01` |
| Reference | `crovia-seal/reference/python` (`crovia_seal`), `crovia-seal/reference/typescript` |
| Public verifier | `https://croviatrust.com/registry/seal/verify/` |
| Issuer trust root | `https://seal.croviatrust.com/trust-root.json` (+ `trust-root.sig.json`) |
| Production issuers | `urn:crovia:seal-issuer:causari` (Causari), `urn:crovia:seal-issuer:crovia-trust` (seal-svc, once conformant) |

Consequences (each is a defect until fixed):

- `seal.croviatrust.com/v1/sign` must emit `crovia.seal.v1`. The current `crovia-seal-v1` / `sl_<sha1>` / `"Ed25519:<hex>"` output is non-conformant and must be replaced by `crovia_seal.emit_seal`.
- The PyPI / npm packages `crovia-seal` 0.1.0 and `@crovia/seal` 0.1.0 implement `crovia.receipt.v1`, a different object. They are renamed **`crovia-receipt`** / **`@crovia/receipt`** and their docs must not use the word Seal for the object they produce. The PyPI name `crovia-seal` is reserved for the reference implementation (0.5.x), so that `pip install crovia-seal` followed by `from crovia_seal import verify_seal` works as `VERIFICATION.md` promises.
- Substrate batch seals must carry `schema: crovia.substrate.batch.v1`, not `crovia.seal.v1`.
- Any documentation that says "3 lines of Python" must show `verify_seal` from the reference package.

## 4. Headline numbers — definitions

Every number shown on the home page or in `llms.txt` must have (a) a definition below, (b) a public data file it is read from, (c) a `PROOF` link that recomputes it from the public ledger.

| Label | Definition | Source file | Current status |
|---|---|---|---|
| Signed observations | Count of envelopes in the AXIOM ledger. | `_home_pulse.json → ledger.n_envelopes_total` | valid |
| Bitcoin-confirmed anchors | Count of OTS anchors with status `bitcoin` whose `merkle_root` equals the substrate `latest_seal.merkle_root` at stamping time. Re-anchors of an unchanged root do not count. | `substrate/ots_anchors.json` | invalid until the OTS job stamps the substrate root |
| Days of documented silence | Sum over targets of days between consecutive *negative, anchored* observations of that target. Silence does not accrue after the last observation. | `silence_index.json` | invalid: currently `first_seen → now` |
| LACUNA records | Count of `AX.LAC` envelopes whose `target_id` is an AI model (not an internal collector, path, or test id). | `_home_pulse.json → ledger.by_axiom_type.AX.LAC` | invalid: currently counts collector heartbeats |

Until a number is valid, the surface must show the honest state (e.g. "observation paused since 2026-06-01"), not the number.

## 5. Public endpoints (the complete list)

Anything not listed here is not advertised anywhere (pages, `llms.txt`, `ai-plugin.json`, `openapi.yaml`, READMEs).

### Pages (`croviatrust.com`)
`/`, `/whitepaper.html`, `/proof.html`, `/registry/`, `/registry/explore/`, `/registry/verify/`, `/registry/compliance/`, `/registry/lacuna/`, `/registry/api/`, `/registry/seal/`, `/registry/seal/spec/`, `/registry/seal/threat-model/`, `/registry/seal/verify/`, `/registry/seal/log/`, `/registry/provenance/`, `/registry/embed/silence.html`, `/llms.txt`, `/llms-full.txt`, `/robots.txt`, `/sitemap.xml`, `/.well-known/ai-plugin.json`, `/.well-known/openapi.yaml`.

Retired paths must return **301** to the paths above and must not appear in any probe, sitemap or link: `/check.html`, `/how-to-read.html`, `/absence-clock.html`, `/alive.html`, `/observatory/`, `/registry/{cep,chains,enterprise,forensics,omissions,outreach,ranking,substrate,tpa,v,diamond,lineage,risk,pont}/`.

### Data (`/registry/data/`)
`_home_pulse.json`, `silence_index.json`, `lineage_graph.json`, `observatory/feed.json`, `pipeline_status.json`, `transparency_index.json`, `seal/public_log.jsonl`, `seal/transparency_log.json`, `substrate/{collectors,latest_seal,ots_anchors,quality_report,recent,trust_root,diamond,lacuna_candidates}.json`, `_smoke.json`.

Files returning 403 (`global_ranking.json`, `forensic_dossiers.json`, `forensic_report.json`, `sonar_chains.json`, `tpa_latest.json`, `tpa_summary.json`) are private and must be removed from `/registry/api/`, `llms.txt` and `openapi.yaml`.

Large files (`substrate/chains.json`, `consensus.json`, `predecessors_map.json`, `target_index.json`, `tpa_cep.json`, `search_targets.json`) are not to be fetched by any page on load; they are replaced by per-day content-addressed shards (TACET §7).

### APIs
- `POST https://croviatrust.com/api/anchor` — body `{"receipt": <crovia.receipt.v1>}`; response includes `anchor_id`. A `GET /api/anchor/<id>` must exist before this endpoint is advertised again.
- `https://croviatrust.com/mcp` — MCP Streamable HTTP; tools `crovia_pulse`, `lookup_model`, `get_lacuna` (argument name: `model`), `crovia_vs_causari`.
- `https://seal.croviatrust.com/{trust-root.json,trust-root.sig.json,health,v1/stats,v1/sign,v1/seal/{id}}`.

## 6. Repositories and their single role

| Repo | Role | State |
|---|---|---|
| `crovia-seal` | The Seal standard: spec, drafts, reference impls, conformance, verifier, proxy/tlog integrations. | active |
| `crovia-core-engine` | Crovia Substrate: collectors, observer, sealer, anchoring, public index builders, ops. The 2025 royalty/payout engine moves to `legacy/`. | active, needs CI |
| `countersign` | Witness protocol and home of TACET (verifiable map, epoch sheets, silence proofs). | active |
| `crovia-evidence-lab` | Public data plane: datasets, leaderboards, reproducible capsules. | active |
| `causari` | Sibling product. | active |
| `crovia-core`, `crovia-wedge`, `awesome-*` forks, `causari-audit-demo` | archived (read-only, README pointer to the canon). | to archive |

Every active repo has: a README whose first paragraph is the one-line description from §1 plus the repo's role from this table; a `CI` badge that is green; the canonical Seal format from §3 wherever a Seal is mentioned; no links to retired paths from §5.

## 7. Wording rules

- "Crovia Seal" only for `crovia.seal.v1` objects. Receipts are "Crovia Receipts".
- "LACUNA certificate" only for a signed, downloadable artifact. Otherwise "LACUNA record" / "LACUNA candidate".
- "Bitcoin-anchored" only for data whose Merkle root is in an OTS anchor with status `bitcoin`.
- Never "hid", "refused", "violated". Use "no contemporaneous disclosure was observed on monitored surfaces between … and …".
- Silence figures always carry the last observation date.
