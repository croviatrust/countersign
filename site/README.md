# croviatrust.com — site sources

The public pages of croviatrust.com, versioned here so that every surface the
[canon](../CANON.md) governs has exactly one source. Static HTML + one shared
stylesheet and one shared shell script; no build step.

```
index.html                 home — every headline number is read live from a public file
whitepaper.html            v3.0 (September 2026): Verifiable Silence
whitepaper-v2-2026-03.html superseded March 2026 paper, kept for the record (noindex)
proof.html                 in-browser signature check for the 2026 archive ledger
llms.txt, llms-full.txt    context for language models — no figures are quoted
.well-known/               ai-plugin.json, crovia.json (schema.org), openapi.yaml, mcp.json
assets/crovia.css          the design system (edit only this file to change the look)
assets/crovia-shell.js     top bar, "More" menu, status pill (reads tacet/latest.json), proof popover
registry/                  /registry/… pages: hub, tacet, lacuna, seal/*, explore, verify, compliance,
                           provenance, api, embed/*
```

Mapping on the server (`CroviaTrust-1`):

| here | there |
|---|---|
| `index.html`, `*.html`, `llms*.txt`, `.well-known/`, `assets/` | `/var/www/crovia/…` |
| `registry/**` | `/var/www/registry/…` |

`sitemap.xml` is not here: it is generated daily on the server by
`/opt/crovia/scripts/seo_sitemap_indexnow.py` from the canon page list plus the
per-model pages.

## Deploy

```bash
site/deploy.sh                  # everything
site/deploy.sh registry/tacet   # one subtree
```

`deploy.sh` streams a tar over SSH, installs each file atomically and keeps a
copy of every file it replaces under `/opt/crovia/site-backups/<stamp>/`.
It needs `CROVIA_SSH` (a command that opens an SSH session to the host) and
`sudo` on the host.

Shared assets are referenced with a `?v=` query; bump it in every page when
`crovia.css` or `crovia-shell.js` changes (Cloudflare caches them for an hour).

## Rules

- Every number shown must be read from a public file listed in `CANON.md §4`
  and open a proof popover naming that file. No hardcoded figures.
- Retired paths (`CANON.md §5`) never appear in a link.
- Every page uses the shared top bar (`.cv-topbar`) and `crovia-shell.js`.
- Wording rules in `CANON.md §7`: observation facts only, never intent.
