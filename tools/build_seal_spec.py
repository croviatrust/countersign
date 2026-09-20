#!/usr/bin/env python3
"""Build the static Crovia Seal specification page from SPEC.md.

The page is cited by the Internet-Draft (draft-crovia-seal) as the place where
the canonical text and the test vectors live, so it must be readable without
JavaScript, must carry the vectors it promises, and must be reproducible from
the repository. This tool renders SPEC.md to HTML at build time, mirrors the
conformance vectors and the Internet-Draft files next to it, and records the
SHA-256 of the exact SPEC.md bytes that were rendered.

    python3 tools/build_seal_spec.py --seal-repo /path/to/crovia-seal

Outputs under site/registry/seal/spec/:
    index.html                 the page (spec text inline, TOC, vectors, related)
    SPEC.md                    the source that was rendered
    vectors/v1/...             every conformance vector, byte-identical
    draft-crovia-seal-NN.*     the Internet-Draft (.txt/.xml/.html)
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import sys
from pathlib import Path

try:
    import markdown  # python-markdown
except ImportError:  # pragma: no cover
    sys.exit("pip install markdown")

SITE = "https://croviatrust.com"
SHELL_V = "20260919g"
DATATRACKER = "https://datatracker.ietf.org/doc/draft-crovia-seal/"
REPO = "https://github.com/croviatrust/crovia-seal"


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def render_spec(md_text: str) -> tuple[str, list[tuple[int, str, str]]]:
    conv = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                             extension_configs={"toc": {"toc_depth": "2-3", "permalink": False}})
    body = conv.convert(md_text)
    toc: list[tuple[int, str, str]] = []
    for m in re.finditer(r'<h([23]) id="([^"]+)">(.*?)</h\1>', body, flags=re.DOTALL):
        level, hid, text = int(m.group(1)), m.group(2), re.sub(r"<[^>]+>", "", m.group(3))
        toc.append((level, hid, html.unescape(text)))
    return body, toc


def spec_meta(md_text: str) -> dict:
    meta = {}
    for key in ("Version", "Status", "Authors", "Date"):
        m = re.search(rf"\*\*{key}:\*\*\s*(.+)", md_text)
        if m:
            meta[key.lower()] = m.group(1).strip()
    return meta


def vector_rows(vdir: Path, base_url: str) -> tuple[str, str, dict]:
    seals = sorted(p for p in vdir.glob("seal_*.json"))
    what = {
        "genesis": "first Seal of a chain (prev_hash = null)", "chained": "second link, prev_hash set",
        "image": "image output kind", "audio": "audio output kind", "multimodal": "mixed input/output kinds",
        "with_checks": "embedded analytical checks", "with_anchor": "transparency-log anchor",
        "empty_params": "empty generator params", "long_chain": "long issuer chain", "utf8_content": "non-ASCII content, CSC-1 escapes",
    }
    rows = []
    for s in seals:
        stem = s.name[:-5]
        tag = stem.split("_", 2)[-1]
        verify = f"/registry/seal/verify/?url={html.escape(base_url + s.name, quote=True).replace('&', '%26')}"
        rows.append(
            f'<tr><td class="f"><a href="{base_url}{s.name}">{html.escape(s.name)}</a></td>'
            f'<td class="d">{html.escape(what.get(tag, tag.replace("_", " ")))}</td>'
            f'<td class="t"><a href="{base_url}{stem}.payload.hex">payload</a> · <a href="{base_url}{stem}.signature.hex">signature</a></td>'
            f'<td class="t"><a class="sp-verify" href="{verify}">verify in browser</a></td></tr>')
    inv_index = json.loads((vdir / "invalid" / "index.json").read_text())
    inv_rows = []
    for c in inv_index.get("invalid_cases", []):
        f = c["file"]
        note = vdir / "invalid" / f.replace(".json", ".note.md")
        note_html = f' · <a href="{base_url}invalid/{note.name}">why</a>' if note.exists() else ""
        verify = f"/registry/seal/verify/?url={html.escape(base_url + 'invalid/' + f, quote=True).replace('&', '%26')}"
        inv_rows.append(f'<tr><td class="f"><a href="{base_url}invalid/{f}">{html.escape(f)}</a></td>'
                        f'<td class="d">MUST fail with <code>{html.escape(c["expected_error"])}</code>{note_html}</td>'
                        f'<td class="t"><a class="sp-verify" href="{verify}">watch it fail</a></td></tr>')
    canon = json.loads((vdir / "canonical_cases.json").read_text())
    info = {
        "seals": len(seals), "invalid": len(inv_rows), "canonical": len(canon.get("cases", [])),
        "issuer_id": (vdir / "issuer.id.txt").read_text().strip(),
        "issuer_pub": (vdir / "issuer.public.hex").read_text().strip(),
        "files": sum(1 for p in vdir.rglob("*") if p.is_file()),
    }
    return "".join(rows), "".join(inv_rows), info


def build(seal_repo: Path, out_dir: Path) -> None:
    spec_src = seal_repo / "SPEC.md"
    md_text = spec_src.read_text(encoding="utf-8")
    spec_hash = sha256_file(spec_src)
    meta = spec_meta(md_text)
    body, toc = render_spec(md_text)

    # mirror source, vectors and the latest Internet-Draft files
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(spec_src, out_dir / "SPEC.md")
    vsrc = seal_repo / "conformance" / "vectors" / "v1"
    vdst = out_dir / "vectors" / "v1"
    if vdst.exists():
        shutil.rmtree(vdst)
    shutil.copytree(vsrc, vdst)
    manifest = {"vectors": "crovia.seal.v1", "source": f"{REPO}/tree/main/conformance/vectors/v1",
                "files": [{"path": str(p.relative_to(vdst)), "bytes": p.stat().st_size, "sha256": sha256_file(p)}
                          for p in sorted(vdst.rglob("*")) if p.is_file()]}
    (vdst / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    drafts = sorted(seal_repo.glob("standards/draft-crovia-seal-*.txt"))
    latest = drafts[-1].stem if drafts else None
    for ext in (".txt", ".xml", ".html"):
        f = seal_repo / "standards" / f"{latest}{ext}"
        if latest and f.exists():
            shutil.copyfile(f, out_dir / f.name)
    ref_version = re.search(r'^version\s*=\s*"([^"]+)"', (seal_repo / "reference" / "python" / "pyproject.toml").read_text(), re.MULTILINE).group(1)

    vec_base = "/registry/seal/spec/vectors/v1/"
    seal_rows, inv_rows, vinfo = vector_rows(vsrc, vec_base)
    total_tests = vinfo["seals"] + vinfo["canonical"] + vinfo["invalid"]  # matches run_conformance.py: one test per seal

    toc_html = "".join(
        f'<a class="l{lvl}" href="#{html.escape(hid, quote=True)}">{html.escape(text)}</a>' for lvl, hid, text in toc)
    toc_html += '<a class="l2 x" href="#vectors">Test vectors</a><a class="l2 x" href="#related">Draft, code, related</a>'

    jsonld = json.dumps({
        "@context": "https://schema.org", "@type": "TechArticle",
        "headline": "Crovia Seal Specification", "alternativeHeadline": f"crovia.seal.v1 · v{meta.get('version', '0.5').split()[0]}",
        "url": f"{SITE}/registry/seal/spec/", "author": {"@type": "Organization", "name": "Crovia Trust", "url": SITE},
        "license": "https://creativecommons.org/publicdomain/zero/1.0/", "inLanguage": "en",
        "isBasedOn": DATATRACKER, "encodingFormat": "text/html",
        "identifier": f"sha256:{spec_hash}", "dateModified": meta.get("date", ""),
    }, ensure_ascii=False)

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Crovia Seal Specification — crovia.seal.v1, canonical text, test vectors</title>
<meta name="description" content="The canonical text of the Crovia Seal protocol (crovia.seal.v1, v{html.escape(meta.get('version', '0.5'))}), the Internet-Draft draft-crovia-seal, and the normative conformance vectors — {total_tests} tests every implementation must pass. Public domain (CC0).">
<link rel="canonical" href="{SITE}/registry/seal/spec/">
<link rel="icon" type="image/png" href="{SITE}/logo.png">
<link rel="alternate" type="text/markdown" href="{SITE}/registry/seal/spec/SPEC.md">
<meta property="og:title" content="Crovia Seal Specification">
<meta property="og:description" content="Canonical text, Internet-Draft and {total_tests} conformance tests for crovia.seal.v1. Frozen, public domain, verifiable in the browser.">
<meta property="og:type" content="article">
<meta property="og:url" content="{SITE}/registry/seal/spec/">
<meta property="og:image" content="{SITE}/og-seal.png?v=20260919">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{SITE}/og-seal.png?v=20260919">
<link rel="stylesheet" href="{SITE}/assets/crovia.css?v=20260919c">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Fraunces:opsz,wght@9..144,300;9..144,400;9..144,500&display=swap" rel="stylesheet">
<script type="application/ld+json">{jsonld.replace('</', '<\\/')}</script>
<style>
  .sp-wrap{{max-width:1200px;margin:0 auto;padding:0 24px}}
  .sp-hero{{padding:64px 0 26px}}
  .sp-eyebrow{{font:500 11px var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--accent)}}
  .sp-hero h1{{font:300 clamp(34px,4.6vw,52px)/1.05 'Fraunces',var(--sans);letter-spacing:-.02em;margin:14px 0 14px;color:#fff}}
  .sp-hero h1 em{{font-style:italic;color:var(--accent)}}
  .sp-lead{{font-size:16px;color:var(--text-soft);max-width:780px;line-height:1.6}}
  .sp-lead a{{color:var(--accent)}}
  .sp-strip{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-top:30px}}
  .sp-stat{{background:var(--bg-card);padding:16px 18px;display:block}}
  .sp-stat .n{{font:600 19px var(--mono);color:#fff;line-height:1.15;letter-spacing:-.02em;overflow-wrap:anywhere}}
  .sp-stat .l{{font:400 11px var(--mono);color:var(--text-muted);margin-top:8px;letter-spacing:.04em}}
  a.sp-stat:hover{{background:var(--bg-card-hi)}}
  .sp-cols{{display:grid;grid-template-columns:250px minmax(0,1fr);gap:36px;margin-top:44px;align-items:start}}
  .sp-toc{{position:sticky;top:84px;max-height:calc(100vh - 100px);overflow:auto;padding-right:6px}}
  .sp-toc .k{{font:600 10px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--text-faint);margin-bottom:10px}}
  .sp-toc a{{display:block;font:400 12.5px/1.45 var(--sans);color:var(--text-muted);padding:4px 0 4px 10px;border-left:1px solid var(--border);text-decoration:none}}
  .sp-toc a.l3{{padding-left:22px;font-size:12px;color:var(--text-faint)}}
  .sp-toc a.x{{margin-top:8px;color:var(--accent)}}
  .sp-toc a:hover,.sp-toc a.on{{color:#fff;border-left-color:var(--accent)}}
  .sp-toc details summary{{display:none}}
  article.sp-doc{{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:44px 52px;font:400 15px/1.7 var(--sans);color:var(--text)}}
  .sp-doc h1{{font:400 30px/1.2 'Fraunces',var(--sans);color:#fff;margin:0 0 18px;padding-bottom:12px;border-bottom:1px solid var(--border)}}
  .sp-doc h2{{font:400 24px/1.2 'Fraunces',var(--sans);color:#fff;margin:40px 0 12px;scroll-margin-top:90px}}
  .sp-doc h3{{font:600 16.5px var(--sans);color:var(--accent);margin:26px 0 10px;scroll-margin-top:90px}}
  .sp-doc h4{{font:600 12px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--text-muted);margin:20px 0 8px}}
  .sp-doc p{{margin:0 0 14px}}
  .sp-doc a{{color:var(--accent)}}
  .sp-doc code{{background:#070b12;border:1px solid var(--border);border-radius:4px;padding:1px 6px;font:500 12.5px var(--mono);color:#85e3ff}}
  .sp-doc pre{{background:#070b12;border:1px solid var(--border);border-radius:8px;padding:14px 16px;overflow-x:auto;margin:14px 0;font:500 12.5px/1.55 var(--mono)}}
  .sp-doc pre code{{background:transparent;border:0;padding:0;color:var(--text)}}
  .sp-doc ul,.sp-doc ol{{padding-left:26px;margin:0 0 14px}}
  .sp-doc li{{margin-bottom:6px}}
  .sp-doc blockquote{{border-left:3px solid var(--accent);padding-left:16px;margin:16px 0;color:var(--text-muted)}}
  .sp-doc hr{{border:0;border-top:1px solid var(--border);margin:30px 0}}
  .sp-doc strong{{color:#fff}}
  .sp-doc table{{width:100%;border-collapse:collapse;margin:14px 0;font:500 12.5px var(--mono)}}
  .sp-doc th,.sp-doc td{{padding:8px 10px;border:1px solid var(--border);text-align:left;vertical-align:top}}
  .sp-doc th{{background:#070b12;color:var(--accent);font:600 10.5px var(--mono);letter-spacing:.08em;text-transform:uppercase}}
  .sp-head{{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:12px;margin:60px 0 16px}}
  .sp-head h2{{font:700 24px/1.15 var(--sans);letter-spacing:-.02em;scroll-margin-top:90px}}
  .sp-head .meta{{font:400 11.5px var(--mono);color:var(--text-muted)}}
  .sp-files{{width:100%;border-collapse:collapse;font-size:13px}}
  .sp-files th{{text-align:left;font:500 10.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--text-faint);padding:8px 10px;border-bottom:1px solid var(--border)}}
  .sp-files td{{padding:10px;border-bottom:1px solid var(--border);vertical-align:top}}
  .sp-files td.f{{font:500 12.5px var(--mono);white-space:nowrap}}
  .sp-files td.f a,.sp-files td.t a{{color:var(--accent)}}
  .sp-files td.d{{color:var(--text-soft)}}
  .sp-files td.d code{{font:500 12px var(--mono);color:#85e3ff}}
  .sp-files td.t{{font:500 11.5px var(--mono);color:var(--text-faint);white-space:nowrap}}
  .sp-verify{{border:1px solid var(--border);border-radius:999px;padding:3px 10px;text-decoration:none}}
  .sp-verify:hover{{border-color:var(--accent)}}
  .sp-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}
  .sp-card{{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px 22px}}
  .sp-card .k{{font:600 10px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin-bottom:10px}}
  .sp-card h3{{font:600 16px/1.25 var(--sans);color:#fff;margin-bottom:8px}}
  .sp-card p{{font-size:13.5px;color:var(--text-soft);line-height:1.55}}
  .sp-card p a{{color:var(--accent)}}
  .sp-card pre{{margin-top:12px;background:#070b12;border:1px solid var(--border);border-radius:8px;padding:12px 14px;font:12px/1.6 var(--mono);color:var(--text);overflow-x:auto}}
  .sp-card .mono{{font:500 11.5px var(--mono);color:var(--text-muted);word-break:break-all}}
  .sp-end{{margin:26px 0 72px;font-size:12.5px;color:var(--text-faint)}}
  .sp-end a{{color:var(--accent)}}
  @media (max-width:900px){{
    .sp-cols{{grid-template-columns:1fr}}
    .sp-toc{{position:static;max-height:none}}
    .sp-toc details summary{{display:block;cursor:pointer;font:600 12px var(--mono);color:var(--accent);letter-spacing:.1em;text-transform:uppercase;padding:10px 0}}
    .sp-toc .k{{display:none}}
    article.sp-doc{{padding:26px 20px}}
    .sp-files td.t:last-child{{white-space:normal}}
  }}
  @media print{{.cv-topbar,.sp-toc,.cv-foot{{display:none}}article.sp-doc{{border:0;padding:0}}}}
</style>
</head>
<body>
<nav class="cv-topbar">
  <div class="cv-topbar-inner">
    <a href="{SITE}/" class="cv-brand-link"><img src="{SITE}/logo.png" alt="" class="cv-brand-mark"><span class="cv-brand-name">CROVIA</span></a>
    <button class="cv-nav-burger" data-cv-burger aria-label="Menu"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M3 12h18M3 18h18"/></svg></button>
    <div class="cv-nav-links" id="cv-nav-links"></div>
    <div class="cv-nav-status" id="cv-nav-status"><span class="dot"></span><span data-cv-status>connecting</span></div>
  </div>
</nav>
<main class="sp-wrap">
  <section class="sp-hero">
    <div class="sp-eyebrow">Specification · crovia.seal.v1 · v{html.escape(meta.get('version', '0.5').split()[0])} · frozen · CC0</div>
    <h1>The Crovia Seal <em>Protocol</em></h1>
    <p class="sp-lead">The canonical text of the Seal format, rendered from <a href="/registry/seal/spec/SPEC.md">SPEC.md</a> and served without scripts. This is the document the Internet-Draft <a href="{DATATRACKER}" rel="noopener">draft-crovia-seal</a> points to: the same bytes, the same section numbers, and below the text the <a href="#vectors">normative test vectors</a> an implementation must reproduce and reject. The text is frozen except for additive fields; profiles such as TACET extend it, they do not change it.</p>
    <div class="sp-strip">
      <div class="sp-stat"><div class="n">v{html.escape(meta.get('version', '0.5').split()[0])}</div><div class="l">{html.escape(meta.get('status', 'frozen except for additive fields'))}</div></div>
      <a class="sp-stat" href="{DATATRACKER}" rel="noopener"><div class="n">{html.escape(latest or 'draft-crovia-seal')}</div><div class="l">Internet-Draft · IETF datatracker ↗</div></a>
      <a class="sp-stat" href="#vectors"><div class="n">{total_tests} tests</div><div class="l">{vinfo['seals']} seals · {vinfo['canonical']} CSC-1 cases · {vinfo['invalid']} invalid</div></a>
      <a class="sp-stat" href="{REPO}" rel="noopener"><div class="n">{html.escape(ref_version)}</div><div class="l">reference · PyPI crovia-seal · npm @crovia/seal ↗</div></a>
      <a class="sp-stat" href="/registry/seal/spec/SPEC.md"><div class="n">{spec_hash[:12]}…</div><div class="l">SHA-256 of SPEC.md as rendered</div></a>
    </div>
  </section>

  <div class="sp-cols">
    <nav class="sp-toc" aria-label="Contents"><details open><summary>Contents</summary><div class="k">Contents</div>{toc_html}</details></nav>
    <article class="sp-doc" id="spec">
{body}
    </article>
  </div>

  <div class="sp-head"><h2 id="vectors">Test vectors</h2><div class="meta">normative · <a href="/registry/seal/spec/vectors/v1/manifest.json" style="color:var(--accent)">manifest.json</a> with the SHA-256 of every file · byte-identical to the repository</div></div>
  <p class="sp-lead" style="margin-bottom:18px">Every conformant implementation MUST reproduce the payload bytes and signature of each valid Seal below and MUST reject every file under <code>invalid/</code> with the stated error. The issuer is a published demo key (<span class="mono">{html.escape(vinfo['issuer_id'])}</span>, pubkey <span class="mono">{html.escape(vinfo['issuer_pub'][:16])}…</span>) so that anyone can regenerate the vectors; it must never sign anything else.</p>
  <table class="sp-files">
    <thead><tr><th>valid seal</th><th>what it exercises</th><th>expected bytes</th><th></th></tr></thead>
    <tbody>{seal_rows}</tbody>
  </table>
  <div class="sp-head" style="margin-top:36px"><h2 style="font-size:18px">Must fail</h2><div class="meta">fail closed · <a href="/registry/seal/spec/vectors/v1/invalid/index.json" style="color:var(--accent)">index.json</a></div></div>
  <table class="sp-files">
    <thead><tr><th>file</th><th>expected outcome</th><th></th></tr></thead>
    <tbody>{inv_rows}</tbody>
  </table>
  <div class="sp-grid" style="margin-top:22px">
    <div class="sp-card"><div class="k">Canonicalization</div><h3>{vinfo['canonical']} CSC-1 cases</h3><p><a href="/registry/seal/spec/vectors/v1/canonical_cases.json">canonical_cases.json</a>: JSON values and the exact UTF-8 bytes CSC-1 must produce, including the cases that must fail (floats, duplicate keys, non-string keys).</p></div>
    <div class="sp-card"><div class="k">Run the suite</div><h3>One command, {total_tests} checks</h3><pre>git clone {REPO}
cd crovia-seal && python3 conformance/run_conformance.py
# ALL {total_tests} TESTS PASSED</pre></div>
  </div>

  <div class="sp-head"><h2 id="related">Draft, code, related</h2><div class="meta">everything the draft refers to, in one place</div></div>
  <div class="sp-grid">
    <div class="sp-card"><div class="k">Internet-Draft</div><h3>{html.escape(latest or 'draft-crovia-seal')}</h3><p>Independent Submission, Informational. <a href="{DATATRACKER}" rel="noopener">Datatracker ↗</a> · mirrored here: <a href="/registry/seal/spec/{latest}.txt">.txt</a> · <a href="/registry/seal/spec/{latest}.xml">.xml</a> · <a href="/registry/seal/spec/{latest}.html">.html</a>. The draft is not modified; this page is its companion.</p></div>
    <div class="sp-card"><div class="k">Reference implementation</div><h3>crovia-seal {html.escape(ref_version)}</h3><p>Python and TypeScript, Apache-2.0: canonicalization, signing, chain and verification, both passing the {total_tests} tests above. <a href="{REPO}" rel="noopener">github.com/croviatrust/crovia-seal ↗</a> · <a href="https://pypi.org/project/crovia-seal/" rel="noopener">PyPI</a> · <a href="https://www.npmjs.com/package/@crovia/seal" rel="noopener">npm</a></p><pre>pip install crovia-seal        # PyPI, Python ≥ 3.10
npm install @crovia/seal       # npm, ESM, provenance attested</pre></div>
    <div class="sp-card"><div class="k">Verify</div><h3>In your browser, offline</h3><p>Paste any Seal — or open a vector with the links above. CSC-1 bytes, Ed25519 signature and chain links are checked locally; nothing is uploaded. <a href="/registry/seal/verify/">Open the verifier</a>.</p></div>
    <div class="sp-card"><div class="k">Companions</div><h3>Threat model, log, trust root</h3><p><a href="/registry/seal/threat-model/">Threat model</a> · <a href="/registry/seal/log/">Transparency log</a> · <a href="/trust-root.json">Issuer trust root</a> · <a href="/registry/seal/">Seal overview</a> · <a href="https://github.com/croviatrust/countersign/blob/main/tacet/SPEC.md" rel="noopener">TACET, the first profile that wraps Seals ↗</a></p></div>
  </div>
  <p class="sp-end">Specification text dedicated to the public domain under CC0 1.0. Built from SPEC.md <span class="mono">sha256:{spec_hash}</span>. Corrections: <a href="{REPO}/issues" rel="noopener">open an issue</a> or write to <a href="mailto:info@croviatrust.com">info@croviatrust.com</a>.</p>
</main>
<footer class="cv-foot">
  <div class="cv-foot-inner">
    <div class="cv-foot-links">
      <a href="/registry/tacet/">TACET</a>
      <a href="/registry/lacuna/">LACUNA</a>
      <a href="/registry/seal/">Seal</a>
      <a href="/registry/seal/verify/">Verify</a>
      <a href="/m/">Model records</a>
      <a href="/registry/api/">Data &amp; API</a>
      <a href="mailto:info@croviatrust.com">Contact</a>
    </div>
    <div class="cv-foot-meta">&copy; 2026 Crovia Trust · observation facts only · all observation data CC-BY-4.0</div>
  </div>
</footer>
<script src="{SITE}/assets/crovia-shell.js?v={SHELL_V}" defer></script>
<script>
(function(){{
  var d=document.querySelector('.sp-toc details'); if(d&&window.matchMedia('(max-width:900px)').matches)d.removeAttribute('open');
  var links=[].slice.call(document.querySelectorAll('.sp-toc a[href^="#"]'));
  var heads=links.map(function(a){{return document.getElementById(a.getAttribute('href').slice(1));}});
  function on(){{var y=window.scrollY+120,cur=-1;heads.forEach(function(h,i){{if(h&&h.offsetTop<=y)cur=i;}});links.forEach(function(a,i){{a.classList.toggle('on',i===cur);}});}}
  window.addEventListener('scroll',on,{{passive:true}});on();
}})();
</script>
</body>
</html>
"""
    (out_dir / "index.html").write_text(page, encoding="utf-8")
    print(f"spec page: {len(toc)} headings, {vinfo['files']} vector files, {total_tests} tests, draft {latest}, SPEC.md sha256:{spec_hash[:16]}…")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seal-repo", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "site" / "registry" / "seal" / "spec")
    a = ap.parse_args()
    build(a.seal_repo.resolve(), a.out.resolve())
