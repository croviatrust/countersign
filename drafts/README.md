# Drafts to apply across the Crovia repositories and the site

Everything here is written against `CANON.md`. The five READMEs share the
same first paragraph (one-liner + repo role) and the same closing
`## Crovia surfaces` block (`_shared/SURFACES.md`). `tools/audit_surfaces.py`
checks the live repositories and pages for the same markers.

## Apply

```bash
# in each clone, on a branch, as Crovia Trust <info@croviatrust.com>
cp drafts/crovia-seal/README.md            <crovia-seal>/README.md
cp drafts/crovia-core-engine/README.md     <crovia-core-engine>/README.md
cp drafts/countersign/README.md            <countersign>/README.md
cp drafts/crovia-evidence-lab/README.md    <crovia-evidence-lab>/README.md
cp drafts/site/llms.txt                    <site root>/llms.txt

# move TACET and the canon into countersign (no new repository)
git -C <countersign> checkout -b tacet
cp -r tacet CANON.md canon tools <countersign>/
git -C <countersign> add -A && git -C <countersign> commit -m "tacet: spec, reference, conformance; canon and surface audit"
```

Accompanying changes each README assumes (do them in the same PR, or the
README is ahead of the repo):

| Repo | Change |
|---|---|
| crovia-seal | `sdk/` → `receipt/`; packages renamed `crovia-receipt` / `@crovia/receipt`; reference published as `crovia-seal` 0.5.x on PyPI; `integrations/seal-svc` emits `crovia.seal.v1` via `crovia_seal.emit_seal`; drop `crovia-seal-v1` strings; README badge points to `draft-crovia-seal-01`. |
| crovia-core-engine | Add `.github/workflows/ci.yml` (pytest, ignore `croviapro`/`schemas` imports or move those tests to the private repo); move 2025 royalty engine to `legacy/`; remove `dist/*.whl` from git; remove `crovia-automation/github_issues_sent.jsonl`; add `ops/phase0/`; `ops/DEPLOY.md` describing git-pull deployment. |
| countersign | Add `tacet/`, `CANON.md`, `canon/`, `tools/`; CI running `tacet/conformance/run_conformance.py` and pytest. |
| crovia-evidence-lab | Add `capsules/` for the four headline figures; adopt the silence definition. |
| site | Replace `llms.txt`; apply `ops/phase0` (cron, nginx 301 map, LACUNA banner); update `/registry/api/` to list only canon files; `ai-plugin.json`/`openapi.yaml` without private files; `registry.croviatrust.com` serving the same root. |
| GitHub | Archive `crovia-core`, `crovia-wedge`, `causari-audit-demo`, `awesome-*` forks with a README pointer to the canon. |

Order that keeps every surface consistent at each step:

1. Site: Phase 0 post-processors + nginx 301 + `llms.txt` (numbers become true; retired paths stop leaking).
2. crovia-seal: seal-svc conformance + package renames (one Seal format everywhere).
3. countersign: TACET + canon land; CI green.
4. crovia-core-engine: CI, `legacy/`, deploy from git.
5. READMEs on all four repos in one pass; archive the rest.
6. Run `python3 tools/audit_surfaces.py --gate`: zero critical/high.
