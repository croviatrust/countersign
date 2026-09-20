# Crovia surface audit

- Generated: 2026-09-20T11:24:22+00:00
- Base: https://croviatrust.com
- Canon revision: 2026-09-19 (crovia.canon.v1)
- Requests made: 112
- Findings: 33

| Severity | Count |
|---|---|
| critical | 0 |
| high | 0 |
| medium | 0 |
| low | 2 |
| info | 31 |

## Low (2)

- **[repos]** repo:causari — README does not state canonical role (expected: README contains 'Sibling product: code provenance for AI' or the identity one-liner, observed: <p align="center">)
- **[repos]** repo:countersign — README does not state canonical role (expected: README contains 'Witness protocol and home of TACET' or the identity one-liner, observed: <p align="center">)

## Info (31)

- **[data_files]** https://croviatrust.com/registry/data/search_targets.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/730088)
- **[data_files]** https://croviatrust.com/registry/data/substrate/chains.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/43520478)
- **[data_files]** https://croviatrust.com/registry/data/substrate/consensus.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/21579122)
- **[data_files]** https://croviatrust.com/registry/data/substrate/predecessors_map.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/64641814)
- **[data_files]** https://croviatrust.com/registry/data/substrate/target_index.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/11468463)
- **[data_files]** https://croviatrust.com/registry/data/tpa_cep.json — heavy file present; not downloaded (expected: reachable (Range probe only), observed: HTTP 206, bytes 0-0/1741156)
- **[headline_numbers]** https://croviatrust.com/registry/data/_home_pulse.json — LACUNA reconciliation (expected: LACUNA count backed by recent model-target candidates, observed: pulse AX.LAC=0; candidates total=1550, model-target=1550, model-target seen in last 7d=845, newest last_seen=2026-09-20T10:06:39+00:00)
- **[headline_numbers]** https://croviatrust.com/registry/data/_home_pulse.json — top_silent streak consistent with observations (expected: streak bounded by observation window, observed: anthropic/claude-3-opus: reported 134 days, computed last_seen-first_seen = 134 days, last_seen 2026-06-01)
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/lacuna_candidates.json — LACUNA candidates are live (expected: live candidates present, observed: 845 non-stale candidates from ['tacet'])
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/ots_anchors.json — anchor reconciliation (expected: bitcoin_confirmed=110 counts distinct roots, observed: anchors=112, distinct merkle_root=45, longest identical-root run=38, newest anchor_date=2026-09-20 (0.5 days old))
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/ots_anchors.json — legacy re-anchoring visible in history only (expected: history acknowledged, observed: historical identical-root run of 38 before 2026-09-19; last 14 days: 7 anchors, 7 distinct roots)
- **[headline_numbers]** https://croviatrust.com/registry/data/substrate/trust_root.json — envelope counts consistent (expected: counts within 2%, observed: pulse n_envelopes_total=499748, trust_root ledger_envelope_count=499748 (0.00% apart))
- **[mcp]** https://croviatrust.com/mcp — MCP tool set matches canon (expected: ["crovia_status", "crovia_vs_causari", "explain", "get_silence_proof", "lookup_model", "search_models", "silence_report", "verify_seal"], observed: ["crovia_status", "crovia_vs_causari", "explain", "get_silence_proof", "lookup_model", "search_models", "silence_report", "verify_seal"])
- **[mcp]** https://croviatrust.com/mcp — MCP crovia_status response (expected: crovia_status answers, observed: {   "as_of": "2026-09-20T11:17:40Z",   "tacet": {     "map_id": "urn:crovia:tacet:map:disclosure",     "epochs_closed": 18,     "epochs_anchored_in_bitcoin": 13,     "models_on_map": 1322,     "snaps…)
- **[mcp]** https://croviatrust.com/mcp — featured model confirmed by MCP lookup (expected: lookup_model consistent with pulse, observed: lookup_model(anthropic/claude-3-opus) -> verdict='archive_only', figures=present)
- **[mirror_parity]** https://registry.croviatrust.com/ — mirror serves the same origin file (expected: same origin body, observed: identical after removing Cloudflare email obfuscation)
- **[mirror_parity]** https://registry.croviatrust.com/lacuna/ — mirror serves the same origin file (expected: same origin body, observed: identical after removing Cloudflare email obfuscation)
- **[mirror_parity]** https://registry.croviatrust.com/seal/ — mirror serves the same origin file (expected: same origin body, observed: identical after removing Cloudflare email obfuscation)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: forensic_dossiers.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/api/ — private file listed as professional, not linked (expected: forensic_report.json not linked, observed: named as a professional-tier product, no link)
- **[private_files]** https://croviatrust.com/registry/data/forensic_dossiers.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[private_files]** https://croviatrust.com/registry/data/forensic_report.json — private file is not served (expected: HTTP 403/404, observed: HTTP 403)
- **[repos]** repo:crovia-core-engine — README states canonical role (expected: README states canonical role or one-liner, observed: present)
- **[repos]** repo:crovia-evidence-lab — README states canonical role (expected: README states canonical role or one-liner, observed: present)
- **[repos]** repo:crovia-seal — README states canonical role (expected: README states canonical role or one-liner, observed: present)
- **[seal_format]** https://croviatrust.com/registry/data/seal/public_log.jsonl — issuer breakdown (expected: production issuers present, observed: 11 seals; issuers: urn:crovia:seal-issuer:conformance (10), urn:crovia:seal-issuer:crovia-trust (1))
- **[seal_format]** https://croviatrust.com/registry/seal/spec/ — spec page readable without scripts (expected: normative text inline in HTML, observed: section 3.3 present)
- **[seal_format]** https://croviatrust.com/registry/seal/spec/SPEC.md — SPEC.md bytes match canon (expected: sha256 ed125588b40c88a7…, observed: match)
- **[seal_format]** https://croviatrust.com/registry/seal/spec/vectors/v1/manifest.json — conformance vectors published (expected: vector bytes match manifest sha256, observed: 44 files listed, 3 probed)
- **[seal_format]** https://seal.croviatrust.com/health — seal service endpoint ok (expected: HTTP 200 JSON, observed: {"status": "ok", "issuer": "urn:crovia:seal-issuer:crovia-trust", "seal_version": "crovia.seal.v1", "total_seals": 1})
- **[seal_format]** https://seal.croviatrust.com/v1/stats — seal service endpoint ok (expected: HTTP 200 JSON, observed: {"seal_version": "crovia.seal.v1", "issuer": "urn:crovia:seal-issuer:crovia-trust", "issuer_pubkey_hex": "b6149a4278a9e66fc08dba86929a0ff0f6c50d610701f597a8e390c67a28d949", "total_seals": 1, "legacy_…)

## Pages

| Path | Status | Final URL | Size | Title |
|---|---|---|---|---|
| `/` | 200 | https://croviatrust.com/ | 34387 | Crovia — Silence you can verify · TACET, the public log of … |
| `/whitepaper.html` | 200 | https://croviatrust.com/whitepaper.html | 30745 | Crovia Whitepaper v3 — TACET: Verifiable Silence for AI Tra… |
| `/whitepaper-v2-2026-03.html` | 200 | https://croviatrust.com/whitepaper-v2-2026-03.html | 39497 | Crovia Whitepaper — Evidence Infrastructure for AI Training… |
| `/proof.html` | 200 | https://croviatrust.com/proof.html | 13661 | Verify Crovia — live cryptographic proof, in your browser |
| `/registry/` | 200 | https://croviatrust.com/registry/ | 17539 | Crovia Registry — everything observed, signed and anchored |
| `/registry/explore/` | 200 | https://croviatrust.com/registry/explore/ | 61947 | Crovia Evidence Explorer — query the signed AI continuity l… |
| `/registry/verify/` | 200 | https://croviatrust.com/registry/verify/ | 70058 | Crovia Passport — CROVIA Registry |
| `/registry/compliance/` | 200 | https://croviatrust.com/registry/compliance/ | 27406 | Crovia Compliance Hub — global ranking, risk index, sonar r… |
| `/registry/tacet/` | 200 | https://croviatrust.com/registry/tacet/ | 27016 | TACET — Verifiable silence for AI training disclosure · Cro… |
| `/registry/tacet/spec/` | 200 | https://croviatrust.com/registry/tacet/spec/ | 66806 | TACET Specification — verifiable silence proofs, PNX profil… |
| `/registry/lacuna/` | 200 | https://croviatrust.com/registry/lacuna/ | 16859 | LACUNA — Loss-of-Auditability Certificates · Crovia |
| `/registry/api/` | 200 | https://croviatrust.com/registry/api/ | 28819 | Crovia API · JSON endpoints |
| `/registry/seal/` | 200 | https://croviatrust.com/registry/seal/ | 27764 | Crovia Seal &mdash; The Open Provenance Receipt for AI Outp… |
| `/registry/seal/spec/` | 200 | https://croviatrust.com/registry/seal/spec/ | 47620 | Crovia Seal Specification — crovia.seal.v1, canonical text,… |
| `/registry/seal/threat-model/` | 200 | https://croviatrust.com/registry/seal/threat-model/ | 6954 | Crovia Seal Threat Model &mdash; THREAT_MODEL.md |
| `/registry/seal/verify/` | 200 | https://croviatrust.com/registry/seal/verify/ | 17506 | Verify a Crovia Seal &mdash; in your browser, offline |
| `/registry/seal/log/` | 200 | https://croviatrust.com/registry/seal/log/ | 15773 | Seal Transparency Log · Crovia |
| `/registry/provenance/` | 200 | https://croviatrust.com/registry/provenance/ | 10786 | Provenance Graph — CROVIA Registry |
| `/registry/embed/silence.html` | 200 | https://croviatrust.com/registry/embed/silence.html | 4579 | Crovia Silence Index — embed |
| `/llms.txt` | 200 | https://croviatrust.com/llms.txt | 7019 |  |
| `/llms-full.txt` | 200 | https://croviatrust.com/llms-full.txt | 9179 |  |
| `/robots.txt` | 200 | https://croviatrust.com/robots.txt | 1803 |  |
| `/sitemap.xml` | 200 | https://croviatrust.com/sitemap.xml | 302359 |  |
| `/.well-known/ai-plugin.json` | 200 | https://croviatrust.com/.well-known/ai-plugin.json | 2443 |  |
| `/.well-known/openapi.yaml` | 200 | https://croviatrust.com/.well-known/openapi.yaml | 13558 |  |
| `/m/` | 200 | https://croviatrust.com/m/ | 419592 | Model records — training-data disclosure, model by model · … |
| `/m/Qwen/Qwen3-32B/` | 200 | https://croviatrust.com/m/Qwen/Qwen3-32B/ | 14308 | Qwen/Qwen3-32B — training-data disclosure on the model card… |
| `/report/` | 200 | https://croviatrust.com/report/ | 8805 | Crovia Silence Report — weekly, verifiable, from published … |
| `/feed.xml` | 200 | https://croviatrust.com/feed.xml | 13747 |  |
| `/press/` | 200 | https://croviatrust.com/press/ | 23022 | Crovia press kit — boilerplate, one-liners, logos, facts, n… |
