#!/usr/bin/env python3
"""Build the static TACET specification page from tacet/SPEC.md and tacet/PNX.md.

The page is the companion of the Internet-Draft draft-crovia-tacet: the
canonical text of the core protocol and of the PNX profile rendered without
JavaScript, the conformance vectors mirrored byte-for-byte with a manifest, the
draft files (.txt/.xml/.html) next to it, and the SHA-256 of the exact source
bytes that were rendered.

    python3 tools/build_tacet_spec.py

Outputs under site/registry/tacet/spec/:
    index.html                 the page (SPEC.md and PNX.md inline, TOC, vectors, related)
    SPEC.md, PNX.md            the sources that were rendered
    vectors/v1/...             every conformance vector, byte-identical, plus manifest.json
    draft-crovia-tacet-NN.*    the Internet-Draft (.txt/.xml/.html)
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
DRAFT = "draft-crovia-tacet"
DATATRACKER = f"https://datatracker.ietf.org/doc/{DRAFT}/"
REPO = "https://github.com/croviatrust/countersign"
BASE = "/registry/tacet/spec/"

# one line per vector file; keys are file stems
WHAT = {
    "map_001_primitives": "sparse Merkle map: empty leaf, empty root, inclusion and non-inclusion paths",
    "sheets_001_chain": "epoch sheets chained by prev_sheet_hash, drand round below, Bitcoin anchor above",
    "snapshots_001_negative": "negative surface snapshots and the per-epoch snapshot hash they bind to",
    "silence_001_level1": "silence proof, strength level 1 (sheets only)",
    "silence_002_level2": "silence proof, strength level 2 (sheets + witnesses)",
    "silence_003_level3": "silence proof, strength level 3 (sheets + witnesses + negative snapshots)",
    "silence_004_before_disclosure": "silence that ends at a disclosure: paths after the disclosure epoch MUST fail",
    "ots_001_live_anchors": "live OpenTimestamps proofs: merkle root matched to the Bitcoin block header (SPEC §8.6)",
    "wrapped_001_level3": "level-3 proof wrapped in an unmodified crovia.seal.v1 with its query",
    "invalid_001": "MUST fail: tampered root, tampered delta, missing sheet, overstated silence, key/target mismatch, insufficient witnesses",
    "wrapped_002_invalid": "MUST fail: the same six faults, delivered inside a Seal",
}


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def render_md(md_text: str, id_prefix: str) -> tuple[str, list[tuple[int, str, str]]]:
    conv = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"],
                             extension_configs={"toc": {"toc_depth": "2-3", "permalink": False}})
    body = conv.convert(md_text)
    # keep the two documents' heading ids disjoint
    body = re.sub(r'<h([1-4]) id="([^"]+)">', lambda m: f'<h{m.group(1)} id="{id_prefix}-{m.group(2)}">', body)
    toc: list[tuple[int, str, str]] = []
    for m in re.finditer(r'<h([23]) id="([^"]+)">(.*?)</h\1>', body, flags=re.DOTALL):
        level, hid, text = int(m.group(1)), m.group(2), re.sub(r"<[^>]+>", "", m.group(3))
        toc.append((level, hid, html.unescape(text)))
    return body, toc


def spec_meta(md_text: str) -> dict:
    meta = {}
    for key in ("Version", "Status", "License", "Editor"):
        m = re.search(rf"\*\*{key}:\*\*\s*([^·\n]+)", md_text)
        if m:
            meta[key.lower()] = m.group(1).strip()
    return meta


def pnx_meta(md_text: str) -> dict:
    m = re.search(r"profile `([^`]+)` · status: ([^·]+) · (\d{4}-\d{2}-\d{2})", md_text)
    return {"profile": m.group(1), "status": m.group(2).strip(), "date": m.group(3)} if m else {}


def count_tests(runner: Path) -> int | None:
    """Run the conformance suite and take the count from its summary line; None if it does not pass cleanly."""
    import subprocess
    try:
        out = subprocess.run([sys.executable, str(runner)], capture_output=True, text=True, timeout=180, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        return None
    m = re.search(r"(\d+) passed, (\d+) failed", out)
    return int(m.group(1)) if m and m.group(2) == "0" else None


def vector_rows(vsrc: Path) -> tuple[str, int]:
    rows = []
    files = sorted(p for p in vsrc.glob("*.json") if p.name != "index.json")
    for p in files:
        stem = p.name[:-5]
        must_fail = "invalid" in stem
        rows.append(
            f'<tr><td class="f"><a href="{BASE}vectors/v1/{p.name}">{html.escape(p.name)}</a></td>'
            f'<td class="d">{"<strong>MUST fail</strong> · " if must_fail else ""}{html.escape(WHAT.get(stem, stem.replace("_", " ")))}</td>'
            f'<td class="t">{p.stat().st_size:,} B · <span title="sha256">{sha256_file(p)[:12]}…</span></td></tr>')
    return "".join(rows), len(files)


def build(root: Path, out_dir: Path) -> None:
    tacet = root / "tacet"
    spec_src, pnx_src = tacet / "SPEC.md", tacet / "PNX.md"
    spec_md, pnx_md = spec_src.read_text(encoding="utf-8"), pnx_src.read_text(encoding="utf-8")
    spec_hash, pnx_hash = sha256_file(spec_src), sha256_file(pnx_src)
    smeta, pmeta = spec_meta(spec_md), pnx_meta(pnx_md)
    spec_body, spec_toc = render_md(spec_md, "tacet")
    pnx_body, pnx_toc = render_md(pnx_md, "pnx")

    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(spec_src, out_dir / "SPEC.md")
    shutil.copyfile(pnx_src, out_dir / "PNX.md")
    vsrc = tacet / "conformance" / "vectors" / "v1"
    vdst = out_dir / "vectors" / "v1"
    if vdst.exists():
        shutil.rmtree(vdst)
    shutil.copytree(vsrc, vdst)
    manifest = {"vectors": "crovia.tacet.vectors.v1", "source": f"{REPO}/tree/main/tacet/conformance/vectors/v1",
                "files": [{"path": str(p.relative_to(vdst)), "bytes": p.stat().st_size, "sha256": sha256_file(p)}
                          for p in sorted(vdst.rglob("*")) if p.is_file()]}
    (vdst / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")

    drafts = sorted((tacet / "standards").glob(f"{DRAFT}-*.txt"))
    latest = drafts[-1].stem if drafts else f"{DRAFT}-00"
    for ext in (".txt", ".xml", ".html"):
        f = tacet / "standards" / f"{latest}{ext}"
        if f.exists():
            shutil.copyfile(f, out_dir / f.name)

    ref_version = re.search(r'^version\s*=\s*"([^"]+)"', (tacet / "reference" / "python" / "pyproject.toml").read_text(), re.MULTILINE).group(1)
    rows, nvec = vector_rows(vsrc)
    total_tests = count_tests(tacet / "conformance" / "run_conformance.py")
    tests_label = f"{total_tests} tests" if total_tests else f"{nvec} vector files"

    def toc_block(title: str, hid: str, toc: list[tuple[int, str, str]]) -> str:
        return (f'<a class="l2 h" href="#{hid}">{html.escape(title)}</a>'
                + "".join(f'<a class="l{lvl}" href="#{html.escape(h, quote=True)}">{html.escape(t)}</a>' for lvl, h, t in toc))

    toc_html = toc_block("Part I · TACET core", "tacet", spec_toc) + toc_block("Part II · PNX profile", "pnx", pnx_toc)
    toc_html += '<a class="l2 x" href="#vectors">Test vectors</a><a class="l2 x" href="#related">Draft, code, related</a>'

    version = smeta.get("version", "0.1-draft")
    jsonld = json.dumps([{
        "@context": "https://schema.org", "@type": "TechArticle",
        "headline": "TACET Specification — verifiable silence proofs, with the PNX profile",
        "alternativeHeadline": f"TACET {version} · {pmeta.get('profile', 'crovia.pnx.v1')} {pmeta.get('status', 'draft')}",
        "url": f"{SITE}{BASE}", "author": {"@type": "Organization", "name": "Crovia Trust", "url": SITE},
        "license": "https://creativecommons.org/publicdomain/zero/1.0/", "inLanguage": "en",
        "isBasedOn": DATATRACKER, "encodingFormat": "text/html",
        "identifier": [f"sha256:{spec_hash}", f"sha256:{pnx_hash}"], "dateModified": pmeta.get("date", ""),
        "about": [{"@type": "DefinedTerm", "name": "TACET", "description": "Verifiable silence proofs: offline-checkable evidence that a key stayed absent from a sparse Merkle transparency map across a contiguous range of anchored epochs."},
                  {"@type": "DefinedTerm", "name": "PNX", "description": "Proof of Non-Exfiltration: a TACET profile proving that none of a set of protected assets appeared in an AI agent's egress during a run."}],
    }, {
        "@context": "https://schema.org", "@type": "SoftwareSourceCode",
        "name": "crovia-tacet", "version": ref_version, "codeRepository": REPO, "programmingLanguage": "Python",
        "license": "https://www.apache.org/licenses/LICENSE-2.0", "url": "https://pypi.org/project/crovia-tacet/",
        "author": {"@type": "Organization", "name": "Crovia Trust", "url": SITE},
    }], ensure_ascii=False)

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TACET Specification — verifiable silence proofs, PNX profile, test vectors</title>
<meta name="description" content="The canonical text of TACET ({html.escape(version)}): silence proofs over a sparse Merkle transparency map with drand-opened, Bitcoin-closed epochs, and the PNX profile (Proof of Non-Exfiltration) for AI agents. Internet-Draft {html.escape(latest)} and {tests_label} every implementation must pass. Public domain (CC0).">
<link rel="canonical" href="{SITE}{BASE}">
<link rel="icon" type="image/png" href="{SITE}/logo.png">
<link rel="alternate" type="text/markdown" href="{SITE}{BASE}SPEC.md">
<link rel="alternate" type="text/plain" title="Internet-Draft" href="{SITE}{BASE}{latest}.txt">
<meta property="og:title" content="TACET Specification — verifiable silence, PNX profile">
<meta property="og:description" content="Canonical text, Internet-Draft {html.escape(latest)} and {tests_label} for TACET and PNX. Frozen text, public domain, offline-verifiable proofs.">
<meta property="og:type" content="article">
<meta property="og:url" content="{SITE}{BASE}">
<meta property="og:image" content="{SITE}/og-tacet.png?v=20260919">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{SITE}/og-tacet.png?v=20260919">
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
  .sp-cols{{display:grid;grid-template-columns:260px minmax(0,1fr);gap:36px;margin-top:44px;align-items:start}}
  .sp-toc{{position:sticky;top:84px;max-height:calc(100vh - 100px);overflow:auto;padding-right:6px}}
  .sp-toc .k{{font:600 10px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--text-faint);margin-bottom:10px}}
  .sp-toc a{{display:block;font:400 12.5px/1.45 var(--sans);color:var(--text-muted);padding:4px 0 4px 10px;border-left:1px solid var(--border);text-decoration:none}}
  .sp-toc a.l3{{padding-left:22px;font-size:12px;color:var(--text-faint)}}
  .sp-toc a.h{{margin-top:14px;font:600 10.5px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:#fff}}
  .sp-toc a.x{{margin-top:8px;color:var(--accent)}}
  .sp-toc a:hover,.sp-toc a.on{{color:#fff;border-left-color:var(--accent)}}
  .sp-toc details summary{{display:none}}
  .sp-part{{display:flex;align-items:baseline;gap:14px;margin:0 0 14px;scroll-margin-top:90px}}
  .sp-part:not(:first-child){{margin-top:48px}}
  .sp-part .k{{font:600 10.5px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--accent)}}
  .sp-part .m{{font:400 11.5px var(--mono);color:var(--text-muted)}}
  .sp-part .m a{{color:var(--accent)}}
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
  .sp-head .meta a{{color:var(--accent)}}
  .sp-files{{width:100%;border-collapse:collapse;font-size:13px}}
  .sp-files th{{text-align:left;font:500 10.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--text-faint);padding:8px 10px;border-bottom:1px solid var(--border)}}
  .sp-files td{{padding:10px;border-bottom:1px solid var(--border);vertical-align:top}}
  .sp-files td.f{{font:500 12.5px var(--mono);white-space:nowrap}}
  .sp-files td.f a{{color:var(--accent)}}
  .sp-files td.d{{color:var(--text-soft)}}
  .sp-files td.d strong{{color:#ffb4a2}}
  .sp-files td.t{{font:500 11.5px var(--mono);color:var(--text-faint);white-space:nowrap}}
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
  .mono{{font:500 11.5px var(--mono);color:var(--text-muted);word-break:break-all}}
  @media (max-width:900px){{
    .sp-cols{{grid-template-columns:1fr}}
    .sp-toc{{position:static;max-height:none}}
    .sp-toc details summary{{display:block;cursor:pointer;font:600 12px var(--mono);color:var(--accent);letter-spacing:.1em;text-transform:uppercase;padding:10px 0}}
    .sp-toc .k{{display:none}}
    article.sp-doc{{padding:26px 20px}}
    .sp-files td.f,.sp-files td.t{{white-space:normal}}
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
    <div class="sp-eyebrow">Specification · TACET {html.escape(version)} · PNX {html.escape(pmeta.get('profile', 'crovia.pnx.v1'))} · CC0</div>
    <h1>TACET: <em>verifiable silence</em>, and the PNX profile</h1>
    <p class="sp-lead">Transparency logs prove presence. TACET proves <em>absence over time</em>: that a key stayed empty in a sparse Merkle map across a contiguous range of epochs, each opened by a drand round and closed by a Bitcoin block, with a negative surface observation bound to every counted epoch. The proof is delivered as an unmodified <a href="/registry/seal/spec/">crovia.seal.v1</a>. This page renders <a href="{BASE}SPEC.md">SPEC.md</a> (the core protocol) and <a href="{BASE}PNX.md">PNX.md</a> (Proof of Non-Exfiltration for AI agents) without scripts; it is the document the Internet-Draft <a href="{DATATRACKER}" rel="noopener">{html.escape(latest)}</a> points to, and below the text sit the <a href="#vectors">conformance vectors</a> every implementation must reproduce and reject.</p>
    <div class="sp-strip">
      <div class="sp-stat"><div class="n">{html.escape(version)}</div><div class="l">{html.escape(smeta.get('status', 'working draft'))} · text CC0, code Apache-2.0</div></div>
      <a class="sp-stat" href="{DATATRACKER}" rel="noopener"><div class="n">{html.escape(latest)}</div><div class="l">Internet-Draft · IETF datatracker ↗</div></a>
      <a class="sp-stat" href="#vectors"><div class="n">{html.escape(tests_label)}</div><div class="l">{nvec} vector files · Python and JS runners</div></a>
      <a class="sp-stat" href="{REPO}" rel="noopener"><div class="n">{html.escape(ref_version)}</div><div class="l">reference · PyPI crovia-tacet · crovia-tacet-operator ↗</div></a>
      <a class="sp-stat" href="{BASE}SPEC.md"><div class="n">{spec_hash[:12]}…</div><div class="l">SHA-256 of SPEC.md as rendered</div></a>
    </div>
  </section>

  <div class="sp-cols">
    <nav class="sp-toc" aria-label="Contents"><details open><summary>Contents</summary><div class="k">Contents</div>{toc_html}</details></nav>
    <div>
      <div class="sp-part" id="tacet"><span class="k">Part I · core protocol</span><span class="m">source <a href="{BASE}SPEC.md">SPEC.md</a> · sha256 {spec_hash[:16]}…</span></div>
      <article class="sp-doc" id="spec">
{spec_body}
      </article>
      <div class="sp-part" id="pnx"><span class="k">Part II · PNX profile · {html.escape(pmeta.get('profile', 'crovia.pnx.v1'))}</span><span class="m">source <a href="{BASE}PNX.md">PNX.md</a> · sha256 {pnx_hash[:16]}… · {html.escape(pmeta.get('date', ''))}</span></div>
      <article class="sp-doc" id="pnx-spec">
{pnx_body}
      </article>
    </div>
  </div>

  <div class="sp-head"><h2 id="vectors">Test vectors</h2><div class="meta">normative · <a href="{BASE}vectors/v1/manifest.json">manifest.json</a> with the SHA-256 of every file · byte-identical to the repository</div></div>
  <p class="sp-lead" style="margin-bottom:18px">A conformant verifier MUST accept every valid proof below with the stated strength level, MUST reproduce the map roots and sheet hashes, and MUST reject each case in the <code>invalid</code> files with the stated reason. The live OpenTimestamps vectors let a verifier prove it matches a Bitcoin block header without running a node. Regenerate with <code>tacet/conformance/generate_vectors.py</code>; the output is deterministic.</p>
  <table class="sp-files">
    <thead><tr><th>vector</th><th>what it exercises</th><th>bytes · sha256</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="sp-grid" style="margin-top:22px">
    <div class="sp-card"><div class="k">Run the suite</div><h3>Python and JavaScript</h3><pre>git clone {REPO} && cd countersign
pip install crovia-seal -e tacet/reference/python
python3 tacet/conformance/run_conformance.py      # {total_tests or '…'} passed, 0 failed
node tacet/conformance/run_conformance_js.cjs</pre></div>
    <div class="sp-card"><div class="k">Live data</div><h3>The same objects, in production</h3><p>The observatory at <a href="/registry/tacet/">/registry/tacet/</a> publishes hourly epoch sheets, <a href="/registry/data/tacet/latest.json">latest.json</a>, the <a href="/registry/data/tacet/trust_root.json">trust root</a> and one silence proof per observed model, each a <code>crovia.seal.v1</code> you can drop into the <a href="/registry/seal/verify/">browser verifier</a>.</p></div>
  </div>

  <div class="sp-head"><h2 id="related">Draft, code, related</h2><div class="meta">everything the draft refers to, in one place</div></div>
  <div class="sp-grid">
    <div class="sp-card"><div class="k">Internet-Draft</div><h3>{html.escape(latest)}</h3><p>Independent Submission, Informational. <a href="{DATATRACKER}" rel="noopener">Datatracker ↗</a> · mirrored here: <a href="{BASE}{latest}.txt">.txt</a> · <a href="{BASE}{latest}.xml">.xml</a> · <a href="{BASE}{latest}.html">.html</a>. Sections 1–9 are the core protocol, section 10 is the PNX profile. The draft is not modified; this page is its companion.</p></div>
    <div class="sp-card"><div class="k">Reference implementation</div><h3>crovia-tacet {html.escape(ref_version)}</h3><p>Python, Apache-2.0: sparse Merkle map, epoch sheets, silence proofs at three strength levels, PNX egress fingerprinting and run sheets, OpenTimestamps verification without a node. <a href="{REPO}/tree/main/tacet" rel="noopener">countersign/tacet ↗</a> · <a href="https://pypi.org/project/crovia-tacet/" rel="noopener">PyPI</a></p><pre>pip install crovia-tacet            # verifier + primitives, Python ≥ 3.10
pip install crovia-tacet-operator   # run an observatory of your own</pre></div>
    <div class="sp-card"><div class="k">Built on</div><h3>Crovia Seal</h3><p>Every TACET proof travels as an unmodified <code>crovia.seal.v1</code>. The Seal text, its Internet-Draft and its vectors: <a href="/registry/seal/spec/">/registry/seal/spec/</a>. Anchors: <a href="https://opentimestamps.org" rel="noopener">OpenTimestamps</a> above, <a href="https://drand.love" rel="noopener">drand</a> below.</p></div>
    <div class="sp-card"><div class="k">Companions</div><h3>Observatory, report, API</h3><p><a href="/registry/tacet/">TACET live</a> · <a href="/report/">Weekly Silence Report</a> · <a href="/m/">Model records</a> · <a href="/registry/api/">Data &amp; API</a> · <a href="/registry/seal/threat-model/">Seal threat model</a> · <a href="/llms.txt">llms.txt</a></p></div>
  </div>
  <p class="sp-end">Specification text dedicated to the public domain under CC0 1.0. Built from SPEC.md <span class="mono">sha256:{spec_hash}</span> and PNX.md <span class="mono">sha256:{pnx_hash}</span>. Corrections: <a href="{REPO}/issues" rel="noopener">open an issue</a> or write to <a href="mailto:info@croviatrust.com">info@croviatrust.com</a>.</p>
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
    print(f"tacet spec page: {len(spec_toc)}+{len(pnx_toc)} headings, {nvec} vectors, {tests_label}, draft {latest}, "
          f"SPEC.md sha256:{spec_hash[:16]}… PNX.md sha256:{pnx_hash[:16]}…")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "site" / "registry" / "tacet" / "spec")
    a = ap.parse_args()
    build(a.root.resolve(), a.out.resolve())
