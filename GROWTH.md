# Crovia growth plan — September 2026

Written by the operating agent for Tarik / Crovia Trust. Everything here is
either already live, buildable by the agent alone, or needs exactly one click
from a human, and says which. No outreach, no cold PRs, no spam: growth has to
come from artifacts other people *want* to embed, cite, run or verify.

## 0. Where we are (verified 2026-09-20)

Shipped since the last update (all live, all pushed, CI green):

- `draft-crovia-tacet-00` (TACET core + PNX profile) written in xml2rfc v3,
  rendered, mirrored with SPEC.md, PNX.md and the 47-test vectors at
  `/registry/tacet/spec/`; every surface links the hosted spec.
- `tacet-pnx` CLI in `crovia-tacet` 0.4.0 (PyPI): keygen / witness / prove /
  verify, sealed delivery as `crovia.seal.v1`, exit codes 0/1/2.
- `croviatrust/pnx-action` v1.0.0 on GitHub: composite action, job-summary
  table, artifact upload, three green self-tests (clean run, leaking run,
  sealed delivery).
- MCP server 2.0 (`com.croviatrust/crovia`) in the official MCP Registry;
  weekly Silence Report + RSS + Zenodo + Bluesky; legacy grades retired;
  press kit `/press/` + `press.json`; security.txt, webmanifest, favicon,
  Organization/Dataset JSON-LD everywhere; `og-tacet.png`, `og-press.png`.

Earlier (2026-09-19 night):

- Surface audit: 0 critical / 0 high / 0 medium. Every public page uses one
  shell, one canon, observation-bounded numbers, no grades.
- TACET live since 18:00Z, epochs hourly, anchors every 2 h, pure-Python and
  in-browser verification of Bitcoin anchors without a node.
- 1,362 per-model records regenerated hourly (`/m/<org>/<model>/`), each
  with a working badge, JSON-LD and a verify path; `/m/` index; sitemap 1,387
  URLs; IndexNow + Google pinged.
- Repos: `countersign` (TACET), `crovia-seal`, `crovia-core-engine` (Phase 0
  ops) with CI green, CITATION, SECURITY, releases.

## 1. The thesis that makes Crovia a category, not a project

**Verifiable absence.** Everyone can prove what happened. Nobody can prove,
to a third party and without trust, what did *not* happen. Crovia's whole
stack — salted fingerprints, sparse Merkle non-inclusion, signed sheets, drand
opening, Bitcoin closing, offline verifiers — is a general machine for
negatives. Today it points at one surface (model cards, training-data
disclosure). The same machine pointed at the problem every CISO has this year
is the explosion:

### PNX — Proof of Non-Exfiltration (agents)

An egress witness sits where an agent's outbound bytes are visible in clear
(Causari's `re proxy`, a corporate egress proxy, a CI sidecar). It commits
fingerprints of everything that left to a sparse Merkle map and signs the run
sheet; the root goes into a TACET epoch. Afterwards the company proves, to an
auditor who sees neither the traffic nor the secrets, that none of its
protected assets (API keys, customer records, source files) appeared in any
outbound byte during a Bitcoin-bounded window. If one did, the same object is a
signed, anchored record of the exposure.

Status: **spec draft + reference implementation + tests shipped tonight**
(`tacet/PNX.md`, `tacet/reference/python/tacet/egress.py`). Guarantee: any
shared substring ≥ 47 bytes is always detected (winnowing); shorter assets are
reported honestly, never counted as clean.

Why this is the lever:
- It is the first artifact about agents a CISO can hand to an auditor that is
  not a vendor log. EU AI Act, DORA, GDPR art. 33 all ask for exactly this
  kind of evidence and today accept screenshots.
- It gives Causari and Crovia one sentence: *Causari records what your agents
  did. Crovia proves what they did not do.* Causari becomes the natural witness;
  Crovia becomes the evidence layer. Neither has to change its scope.
- It is verifiable offline with the verifiers that already exist. No new trust.

## 2. What the agent builds next, in order

| # | Artifact | Why it spreads | Human click needed |
|---|---|---|---|
| 1 | **Self-witnessed operator.** *(next)* The TACET operator's own outbound HTTP (HF, drand, mempool) goes through the egress witness with its own private keys as protected assets. A public PNX proof every hour: "Crovia's operator never leaked its signing keys." Page `/registry/tacet/agents/`. | A live, self-demonstrating, verifiable demo nobody else has. Screenshots itself. | none |
| 2 | **PNX conformance vectors + browser verifier.** *(next)* Extend `run_conformance*.py/.cjs` and `tacet-verify.js` to `crovia.pnx.v1`. | Two independent verifiers agreeing byte-for-byte is what standards people look for. | none |
| 3 | ~~`tacet-egress` sidecar~~ **done as `tacet-pnx witness`** (files, directories, `.jsonl` gateway logs). A CONNECT/MITM proxy mode is deferred: it needs a CA in the agent's trust store, which is the customer's decision, not a default. (Python, stdlib + `cryptography`): an HTTP CONNECT/forward proxy that fingerprints request bodies and writes the run sheet; `--assets secrets.txt` produces the proof at exit. | One command turns any agent run into a proof. Works with Cursor, Claude Code, Aider via `HTTPS_PROXY`. | none |
| 4 | ~~GitHub Action~~ **done: `croviatrust/pnx-action` v1.0.0**: wraps a job step in the sidecar, uploads the sheet, posts the proof as a check. | Every PR of every adopter carries a Crovia-verified receipt with a link back. Marketplace listing = discovery without outreach. | publish to Marketplace (1 click) |
| 5 | ~~Internet-Draft~~ **done: `draft-crovia-tacet-00`** at `/registry/tacet/spec/` (TACET + PNX profile), xml2rfc source in `countersign/ietf/`. | Second I-D beside `draft-crovia-seal`; puts Crovia on datatracker for "verifiable absence". | submit on datatracker (2 clicks) |
| 6 | **Paper**: "Verifiable Silence: proving absence for AI disclosure and agent egress" (PDF on site, Zenodo DOI). | Citable object; arXiv later with an endorser. | Zenodo token or 1 upload |
| 7 | ~~MCP server~~ **done: `com.croviatrust/crovia` 2.0.0 in the official registry** (`verify_seal`, `model_record`, `silence_proof`, `pnx_verify`) + `server.json` for the official MCP registry. | Agents are the new search engine; a tool call is a citation. | registry login (1 click) |
| 8 | ~~Weekly Silence Report~~ **done** (`/report/`, `/feed.xml`, Zenodo weekly, Bluesky); HF dataset mirror still open — **Weekly Silence Report** page + Atom/JSON feeds + HF dataset mirror of epoch sheets under the Crovia account. | Feeds get aggregated; a dataset on HF is a permanent inbound link, not spam. | HF write token |
| 9 | **Per-org pages `/m/<org>/`** and per-model OG cards. | Long-tail search; shareable cards per model. | none |

Items 1–3 and 9 need nothing from Tarik and start immediately. 4–8 are built
end-to-end by the agent and stop at the one click that must be a human's.

## 3. What is public, what is paid (decision)

- **Public, CC-BY-4.0, forever:** every observation, sheet, snapshot, proof,
  anchor, model record, badge, the specs, the reference code (Apache-2.0).
  Verification never requires an account or a Crovia server.
- **Paid (professional):** *witnessing on request* — a named PNX witness run
  for a customer's agent fleet with SLA, countersigned by ≥ 2 independent
  witnesses; *certificates* — LACUNA / PNX level-2 proofs for a named window
  with an engagement letter; *forensic dossiers*. Never the ability to verify,
  never the data. The public log is the product's proof; the service is the
  time of a witness.

## 4. What the agent will not do

- Open PRs on other people's repos, post to HN/Reddit/HF forums, or DM anyone.
  Drafts for Show HN and a LinkedIn/X thread will be prepared as text for
  Tarik to post when he chooses.
- Quote a figure without its observation bound, anywhere.
- Touch Causari's repository. Integration is proposed as a spec (`tacet/PNX.md`
  §8) that Causari can implement in its own time.

## 5. Open asks (one-click list for Tarik)

1. ~~PyPI / npm Trusted Publishing~~ done 2026-09-20: `crovia-tacet` 0.3.0,
   `crovia-tacet-operator` 0.3.0, `crovia-seal` 0.6.0 on PyPI; `@crovia/seal`
   0.6.0 on npm with provenance. Every install snippet on the site and in the
   READMEs is now registry-only.
2. ~~Social previews~~ done 2026-09-20.
3. **Submit `draft-crovia-tacet-00` on datatracker** (2 clicks): upload
   `tacet/standards/draft-crovia-tacet-00.xml` at
   https://datatracker.ietf.org/submit/ — the .txt/.html renders are next to it
   and mirrored at https://croviatrust.com/registry/tacet/spec/.
4. **Publish `pnx-action` to the Marketplace** (1 click): on
   https://github.com/croviatrust/pnx-action/releases/tag/v1.0.0 press
   "Edit", tick "Publish this Action to the GitHub Marketplace", choose the
   categories *Security* and *Continuous integration*. `action.yml` already has
   the branding block the Marketplace requires.
5. HF write token, when convenient: dataset mirror of the epoch sheets under
   the Crovia account (item 8, last piece).
