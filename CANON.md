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
| Silence proofs | **TACET** | Transparency log for AI training disclosure in which non-inclusion (silence) is a first-class, portable, offline-verifiable proof. | `live` since 2026-09-19T18:00Z (hourly epochs, Bitcoin-anchored); spec `v0.1-draft`, reference `0.3.x` (adds the PNX egress profile). |
| Witnessing | **Countersign** | Independent CT-style witnessing of Crovia epoch heads and surface snapshots. | `v0.1` |
| Code provenance | **Causari** | Sibling product; not part of the ledger. | `live` |

Names retired from public copy: "Hubble", "Global AI Training Omissions" (as a product name), "CROVIA Core Engine — payout layer", "Oracle scanner", "Wedge", "Diamond Archive", "CEP Terminal", "Crovia Continuity Index" and any A–F vendor grade, "Proof of Non-Training" (unless re-specified).

## 3. Crovia Seal — the one and only format

There is exactly one thing called a Crovia Seal.

| Field | Canonical value |
|---|---|
| `seal_version` | `crovia.seal.v1` |
| `seal_id` | `cs_YYYY_` + 26 base32 chars |
| Signature object | `{"alg":"ed25519","canon":"csc-1","domain":"CROVIA-SEAL-v1","payload_hash_alg":"sha256","sig_hex":"<128 hex>"}` |
| Timestamp | `timestamp.emitted_at` (RFC 3339, ms) + `timestamp.nonce` |
| Canonicalization | CSC-1 (strict RFC 8785 subset, no floats) |
| Spec | `crovia-seal/SPEC.md` v0.5, `draft-crovia-seal-01` ([datatracker](https://datatracker.ietf.org/doc/draft-crovia-seal/)) |
| Spec page (cited by the draft) | `https://croviatrust.com/registry/seal/spec/` — static render of `SPEC.md` (sha256 in `canon.json` → `seal.spec_sha256`), draft mirrored as `.txt/.xml/.html`, all 44 conformance files under `/registry/seal/spec/vectors/v1/` with `manifest.json`. Built by `tools/build_seal_spec.py --seal-repo <crovia-seal>`; never edit `index.html` by hand. |
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
| Hourly epochs | Count of TACET epoch sheets since genesis 2026-09-19T18:00Z; the number confirmed in Bitcoin is shown alongside. | `tacet/latest.json → epochs`, `anchored_epochs` | valid |
| Models observed | Distinct target ids with at least one signed TACET snapshot. | `tacet/targets.json → count` | valid |
| Signed observations of absence | TACET snapshots whose predicate result is `false`. They count toward silence only once their epoch is anchored. | `tacet/latest.json → negative_snapshots_total` | valid |
| Bitcoin-confirmed ledger roots | Distinct substrate `merkle_root`s with a confirmed Bitcoin timestamp. Re-anchors of an unchanged root do not count. | `_home_pulse.json → anchors.distinct_roots` (from `substrate/ots_anchors.json`) | valid |
| Signed observations (archive) | Count of envelopes in the AXIOM ledger, January–June 2026. | `_home_pulse.json → ledger.n_envelopes_total` | valid; shown only in the "2026 archive" section |
| Days of documented silence (archive) | Sum over targets of days between consecutive *negative, anchored* observations. Does not accrue after the last observation (2026-06-01). | `_home_pulse.json → silence.total_days` (Phase 0 post-processor) | valid; shown only in the "2026 archive" section with the pause date |
| LACUNA records | Retired as a home-page number. LACUNA candidates are TACET targets with `negative_anchored_epochs > 0`; a certificate is a level-2 silence proof. | `tacet/targets.json` | replaced by TACET |

Until a number is valid, the surface must show the honest state (e.g. "observation paused since 2026-06-01"), not the number.

## 5. Public endpoints (the complete list)

Anything not listed here is not advertised anywhere (pages, `llms.txt`, `ai-plugin.json`, `openapi.yaml`, READMEs).

### Pages (`croviatrust.com`)
`/`, `/whitepaper.html`, `/whitepaper-v2-2026-03.html` (superseded, noindex), `/proof.html`, `/registry/`, `/registry/tacet/`, `/registry/explore/`, `/registry/verify/`, `/registry/compliance/`, `/registry/lacuna/`, `/registry/api/`, `/registry/seal/`, `/registry/seal/spec/`, `/registry/seal/threat-model/`, `/registry/seal/verify/`, `/registry/seal/log/`, `/registry/provenance/`, `/registry/embed/silence.html`, `/llms.txt`, `/llms-full.txt`, `/robots.txt`, `/sitemap.xml`, `/.well-known/ai-plugin.json`, `/.well-known/openapi.yaml`.

Retired paths must return **301** to the paths above and must not appear in any probe, sitemap or link: `/check.html`, `/how-to-read.html`, `/absence-clock.html`, `/alive.html`, `/observatory/`, `/registry/{cep,chains,enterprise,forensics,omissions,outreach,ranking,substrate,tpa,v,diamond,lineage,risk,pont,cci,e}/`. The exact destination of each is recorded in `canon/canon.json` → `retired_path_targets` (it mirrors the nginx map in production, e.g. `/registry/tpa/` → `/registry/verify/?mode=passport`, `/registry/substrate/` → `/registry/explore/?mode=graph`); a legacy page stays reachable only with `?legacy=1`.

### Data (`/registry/data/`)
`_home_pulse.json`, `silence_index.json`, `lineage_graph.json`, `observatory/feed.json`, `pipeline_status.json`, `transparency_index.json`, `seal/public_log.jsonl`, `seal/transparency_log.json`, `substrate/{collectors,latest_seal,ots_anchors,quality_report,recent,trust_root,diamond,lacuna_candidates}.json`, `_smoke.json`.

**Access policy (decided 2026-09-19).** Every observation file under `/registry/data/` is public, CC-BY-4.0, and fetchable directly with any client (a per-IP rate limit of 15 req/min applies; no referer gate, no API key). This includes `global_ranking.json`, `tpa_latest.json`, `tpa_summary.json`, `sonar_chains.json` and everything under `tacet/`. Exactly two files are professional-tier products and return 403 without a key: `forensic_dossiers.json` and `forensic_report.json`. Paid services are attestations about a *specific party*, never access to the data: per-organisation forensic dossiers, TPA certification reports, witnessed TACET silence proofs (k/n, customer as witness), hosted Seal issuance. The rule of thumb: **evidence is free; being certified costs.**

### TACET (`/registry/data/tacet/`)
`trust_root.json`, `latest.json`, `index.json`, `targets.json`, `sheets/{epoch}.json`, `snapshots/{epoch}.jsonl`, `changes/{epoch}.json`, `values/{key_hex}.json`, `ots/{epoch}.ots`, `proofs/index.json`, `proofs/{slug}.seal.json`, `badges/{name}.json` (shields.io endpoint badges for epochs, models, negative, latest — the only badges any README may show for live figures). Map id `urn:crovia:tacet:map:disclosure`, genesis 2026-09-19T18:00:00Z, hourly epochs. Silence figures shown anywhere on the site come from level-2 proofs and always carry `observed_to`. Two verifiers exist and must agree byte-for-byte on every printed figure: `tacet-operator verify` (Python) and `/registry/seal/verify/?url=<proof>` (browser, `site/registry/seal/verify/{tacet-verify,ots-verify}.js`). Both perform the SPEC §8.6 anchor check — parse the `.ots`, match its merkle root to the Bitcoin block header — without a Bitcoin node or `ots` client; both run against `tacet/conformance/vectors/v1` in CI. Never write that the browser "skips the Bitcoin step".

Large files (`substrate/chains.json`, `consensus.json`, `predecessors_map.json`, `target_index.json`, `tpa_cep.json`, `search_targets.json`) are not to be fetched by any page on load; they are replaced by per-day content-addressed shards (TACET §7).

### APIs
- `POST https://croviatrust.com/api/anchor` — body `{"receipt": <crovia.receipt.v1>}`; response includes `anchor_id`. A `GET /api/anchor/<id>` must exist before this endpoint is advertised again.
- `https://croviatrust.com/mcp` — MCP Streamable HTTP; tools `crovia_pulse`, `lookup_model`, `get_lacuna` (argument name: `model`), `crovia_vs_causari`.
- `https://seal.croviatrust.com/{trust-root.json,trust-root.sig.json,health,v1/stats,v1/sign,v1/seal/{id}}`.

## 6. Repositories and their single role

| Repo | Role | State |
|---|---|---|
| `crovia-seal` | The Seal standard: spec, drafts, reference impls, conformance, verifier, proxy/tlog integrations. | active |
| `crovia-core-engine` | Crovia Substrate: collectors, observer, sealer, anchoring, public index builders, ops (`ops/phase0`). The 2025 royalty/payout engine moves to `legacy/`. | active, CI on push |
| `countersign` | Witness protocol and home of TACET (verifiable map, epoch sheets, silence proofs). | active |
| `crovia-evidence-lab` | Public data plane: hourly exports (`open/`, `snapshots/`), weekly leaderboard, frozen 2026-H1 experiments. | active, hourly sync |
| `causari` | Sibling product. | active |
| `crovia-core`, `crovia-wedge`, `awesome-*` forks, `causari-audit-demo` | archived (read-only, README pointer to the canon). | to archive |

Every active repo has: a README whose first paragraph is the one-line description from §1 plus the repo's role from this table; a `CI` badge that is green; the canonical Seal format from §3 wherever a Seal is mentioned; no links to retired paths from §5.

## 7. Wording rules

- "Crovia Seal" only for `crovia.seal.v1` objects. Receipts are "Crovia Receipts".
- "LACUNA certificate" only for a signed, downloadable artifact. Otherwise "LACUNA record" / "LACUNA candidate".
- "Bitcoin-anchored" only for data whose Merkle root is in an OTS anchor with status `bitcoin`.
- Never "hid", "refused", "violated". Use "no contemporaneous disclosure was observed on monitored surfaces between … and …".
- Silence figures always carry the last observation date.
