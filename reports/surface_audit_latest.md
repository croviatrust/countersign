# Crovia surface audit

- Generated: 2026-09-19T17:46:35+00:00
- Base: https://croviatrust.com
- Canon revision: 2026-09-19 (crovia.canon.v1)
- Requests made: 104
- Findings: 49

| Severity | Count |
|---|---|
| critical | 0 |
| high | 3 |
| medium | 3 |
| low | 11 |
| info | 32 |

## High (3)

- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/lacuna_candidates.json — all candidates from one dead collector (expected: candidates from live collectors, observed: collector=autonomous_observer, newest last_seen=2026-06-01T14:46:23.413105+00:00 (110 days ago))
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/ots_anchors.json — repeated anchoring of unchanged root (expected: each anchor stamps a new root, observed: 38 consecutive anchors share one merkle_root)
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/ots_anchors.json — anchoring stalled (expected: newest anchor <= 3 days old, observed: newest anchor_date 2026-09-08 is 11.7 days old)

## Medium (3)

- **[mirror_parity]** https://registry.croviatrust.com/ — mirror body differs from canonical domain (expected: sha256 c8e51f4daf6d5be4… (35551 bytes), observed: sha256 a97197772e3429cf… (35184 bytes))
- **[mirror_parity]** https://registry.croviatrust.com/lacuna/ — mirror body differs from canonical domain (expected: sha256 52fbd1a8ab9e622f… (10580 bytes), observed: sha256 4f8d2a0d629dfa40… (9732 bytes))
- **[mirror_parity]** https://registry.croviatrust.com/seal/ — mirror body differs from canonical domain (expected: sha256 cae6b0e61aa6a9bb… (26971 bytes), observed: sha256 a63d32ba107c6404… (25926 bytes))

## Low (11)

- **[links]** https://croviatrust.com/absence-clock.html — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/observatory/ — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/registry/cep/ — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/registry/enterprise — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/registry/forensics — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/registry/omissions — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/registry/outreach — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/registry/ranking — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[links]** https://croviatrust.com/registry/substrate/ — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/seal/)
- **[links]** https://croviatrust.com/registry/tpa — link points to a retired path (expected: no links to retired paths, observed: linked from https://croviatrust.com/registry/)
- **[repos]** repo:causari — README does not state canonical role (expected: README contains 'Sibling product: code provenance for AI' or the identity one-liner, observed: <p align="center">)

## Info (32)

- **[data_files]** https://croviatrust.com/registry/data/search_targets.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/730088)
- **[data_files]** https://croviatrust.com/registry/data/substrate/chains.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/43306967)
- **[data_files]** https://croviatrust.com/registry/data/substrate/consensus.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/21555091)
- **[data_files]** https://croviatrust.com/registry/data/substrate/predecessors_map.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/64237174)
- **[data_files]** https://croviatrust.com/registry/data/substrate/target_index.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/11454608)
- **[data_files]** https://croviatrust.com/registry/data/tpa_cep.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/1741038)
- **[headline_numbers]** https://croviatrust.com/registry/data/_home_pulse.json — LACUNA reconciliation (expected: LACUNA count backed by recent model-target candidates, observed: pulse AX.LAC=0; candidates total=1363, model-target=1363, model-target seen in last 7d=0, newest last_seen=2026-06-01T14:46:23.413105+00:00)
- **[headline_numbers]** https://croviatrust.com/registry/data/_home_pulse.json — top_silent streak consistent with observations (expected: streak bounded by observation window, observed: anthropic/claude-3-opus: reported 134 days, computed last_seen-first_seen = 134 days, last_seen 2026-06-01)
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/ots_anchors.json — anchor reconciliation (expected: bitcoin_confirmed=106 counts distinct roots, observed: anchors=108, distinct merkle_root=41, longest identical-root run=38, newest anchor_date=2026-09-08 (11.7 days old))
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/trust_root.json — envelope counts consistent (expected: counts within 2%, observed: pulse n_envelopes_total=497047, trust_root ledger_envelope_count=497047 (0.00% apart))
- **[mcp]** https://croviatrust.com/mcp — MCP tool set matches canon (expected: ["crovia_pulse", "crovia_vs_causari", "get_lacuna", "lookup_model"], observed: ["crovia_pulse", "crovia_vs_causari", "get_lacuna", "lookup_model"])
- **[mcp]** https://croviatrust.com/mcp — MCP crovia_pulse response (expected: crovia_pulse answers, observed: {   "as_of": "2026-09-19T17:48:01Z",   "models_in_silence_window": 2192,   "median_silence_days": 98,   "longest_current_silence": {     "model": "anthropic/claude-3-opus",     "days": 134   },   "le…)
- **[mcp]** https://croviatrust.com/mcp — featured model confirmed by MCP lookup (expected: lookup_model consistent with pulse, observed: lookup_model(anthropic/claude-3-opus) -> disclosure_status='silence_recorded', lacuna=[{"model": "anthropic/claude-3-opus", "absence_streak_days": 134, "days_monitor…)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: global_ranking.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: forensic_dossiers.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: forensic_report.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: sonar_chains.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: tpa_latest.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: tpa_summary.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/data/forensic_dossiers.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[private_files]** https://croviatrust.com/registry/data/forensic_report.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[private_files]** https://croviatrust.com/registry/data/global_ranking.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[private_files]** https://croviatrust.com/registry/data/sonar_chains.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[private_files]** https://croviatrust.com/registry/data/tpa_latest.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[private_files]** https://croviatrust.com/registry/data/tpa_summary.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[repos]** repo:countersign — README states canonical role (expected: README states canonical role or one-liner, observed: present)
- **[repos]** repo:crovia-core-engine — README states canonical role (expected: README states canonical role or one-liner, observed: present)
- **[repos]** repo:crovia-evidence-lab — README states canonical role (expected: README states canonical role or one-liner, observed: present)
- **[repos]** repo:crovia-seal — README states canonical role (expected: README states canonical role or one-liner, observed: present)
- **[seal_format]** https://croviatrust.com/registry/data/seal/public_log.jsonl — issuer breakdown (expected: production issuers present, observed: 11 seals; issuers: urn:crovia:seal-issuer:conformance (10), urn:crovia:seal-issuer:crovia-trust (1))
- **[seal_format]** https://seal.croviatrust.com/health — seal service endpoint ok (expected: HTTP 200 JSON, observed: {"status": "ok", "issuer": "urn:crovia:seal-issuer:crovia-trust", "seal_version": "crovia.seal.v1", "total_seals": 1})
- **[seal_format]** https://seal.croviatrust.com/v1/stats — seal service endpoint ok (expected: HTTP 200 JSON, observed: {"seal_version": "crovia.seal.v1", "issuer": "urn:crovia:seal-issuer:crovia-trust", "issuer_pubkey_hex": "b6149a4278a9e66fc08dba86929a0ff0f6c50d610701f597a8e390c67a28d949", "total_seals": 1, "legacy_…)

## Pages

| Path | Status | Final URL | Size | Title |
|---|---|---|---|---|
| `/` | 200 | https://croviatrust.com/ | 27669 | Crovia — We record what AI won't say · The flight recorder … |
| `/whitepaper.html` | 200 | https://croviatrust.com/whitepaper.html | 39997 | Crovia Whitepaper — Evidence Infrastructure for AI Training… |
| `/proof.html` | 200 | https://croviatrust.com/proof.html | 11946 | Verify Crovia — live cryptographic proof, in your browser |
| `/registry/` | 200 | https://croviatrust.com/registry/ | 35551 | Crovia Registry — AI Training Provenance Database \| 186,000… |
| `/registry/explore/` | 200 | https://croviatrust.com/registry/explore/ | 61733 | Crovia Evidence Explorer — query the signed AI continuity l… |
| `/registry/verify/` | 200 | https://croviatrust.com/registry/verify/ | 69556 | Crovia Passport — CROVIA Registry |
| `/registry/compliance/` | 200 | https://croviatrust.com/registry/compliance/ | 27054 | Crovia Compliance Hub — global ranking, risk index, sonar r… |
| `/registry/lacuna/` | 200 | https://croviatrust.com/registry/lacuna/ | 10580 | LACUNA — Loss-of-Auditability Certificates · Crovia |
| `/registry/api/` | 200 | https://croviatrust.com/registry/api/ | 26449 | Crovia API · JSON endpoints |
| `/registry/seal/` | 200 | https://croviatrust.com/registry/seal/ | 26971 | Crovia Seal &mdash; The Open Provenance Receipt for AI Outp… |
| `/registry/seal/spec/` | 200 | https://croviatrust.com/registry/seal/spec/ | 6276 | Crovia Seal Specification (v0.5) &mdash; SPEC.md |
| `/registry/seal/threat-model/` | 200 | https://croviatrust.com/registry/seal/threat-model/ | 6095 | Crovia Seal Threat Model &mdash; THREAT_MODEL.md |
| `/registry/seal/verify/` | 200 | https://croviatrust.com/registry/seal/verify/ | 19839 | Verify a Crovia Seal &mdash; in your browser, offline |
| `/registry/seal/log/` | 200 | https://croviatrust.com/registry/seal/log/ | 15651 | Seal Transparency Log · Crovia |
| `/registry/provenance/` | 200 | https://croviatrust.com/registry/provenance/ | 10418 | Provenance Graph — CROVIA Registry |
| `/registry/embed/silence.html` | 200 | https://croviatrust.com/registry/embed/silence.html | 4579 | Crovia Silence Index — embed |
| `/llms.txt` | 200 | https://croviatrust.com/llms.txt | 3861 |  |
| `/llms-full.txt` | 200 | https://croviatrust.com/llms-full.txt | 4922 |  |
| `/robots.txt` | 200 | https://croviatrust.com/robots.txt | 1803 |  |
| `/sitemap.xml` | 200 | https://croviatrust.com/sitemap.xml | 241441 |  |
| `/.well-known/ai-plugin.json` | 200 | https://croviatrust.com/.well-known/ai-plugin.json | 2273 |  |
| `/.well-known/openapi.yaml` | 200 | https://croviatrust.com/.well-known/openapi.yaml | 10140 |  |
