#!/usr/bin/env python3
"""Publish the TACET public log as a Hugging Face dataset.

The public directory (/var/www/registry/data/tacet) already holds every
signed observation, every epoch sheet, the map changes, the Bitcoin anchors
and the featured proofs. This script copies those files into a dataset
layout, adds three flat tables the Hub's viewer can show (observations
sharded by day, epochs, targets) and a dataset card with the live counts, then uploads the
folder to the Hub. Unchanged files are not re-uploaded (the Hub compares
hashes), so it is safe to run every hour.

    python3 hf_publish_tacet.py --public /var/www/registry/data/tacet --out /tmp/hf-tacet --dry-run
    HF_TOKEN=... python3 hf_publish_tacet.py --public /var/www/registry/data/tacet --out /tmp/hf-tacet

The token comes from HF_TOKEN in the environment (the server sources
/etc/crovia/hf.env); it is never read from a file by this script and never
printed. Needs huggingface_hub for the upload only; --dry-run runs without it.

Nothing here is a new claim: every row is a byte-for-byte copy of what
croviatrust.com serves, and every proof verifies with `tacet-operator
verify` against the trust root shipped in the same folder.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

REPO_ID = "CroviaTrust/tacet-disclosure-ledger"
ORG_CARD_REPO = "CroviaTrust/README"
SURVIVAL_LATEST_URL = "https://causari.dev/reports/survival/latest.json"
PUBLIC_BASE_URL = "https://croviatrust.com/registry/data/tacet"
COPIED_DIRS = ("sheets", "changes", "snapshots", "ots", "proofs")
COPIED_FILES = ("trust_root.json", "latest.json", "index.json", "targets.json")


def _read_json(p: Path, default: Any = None) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if default is not None:
            return default
        raise


def _write_jsonl(p: Path, rows: Iterable[Dict[str, Any]]) -> int:
    n = 0
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
            n += 1
    tmp.replace(p)
    return n


def sync_tree(src: Path, dst: Path) -> None:
    """Mirror src into dst: copy new or changed files, remove files that no longer exist upstream."""
    dst.mkdir(parents=True, exist_ok=True)
    wanted = set()
    for f in src.iterdir():
        # `ots upgrade` leaves <epoch>.ots.bak next to the proof; not part of the record.
        if not f.is_file() or f.name.endswith((".bak", ".tmp")):
            continue
        wanted.add(f.name)
        t = dst / f.name
        if not t.exists() or t.stat().st_size != f.stat().st_size or t.read_bytes() != f.read_bytes():
            shutil.copy2(f, t)
    for f in dst.iterdir():
        if f.is_file() and f.name not in wanted:
            f.unlink()


def epoch_rows(public: Path, latest: int) -> List[Dict[str, Any]]:
    rows = []
    for e in range(latest + 1):
        s = _read_json(public / "sheets" / f"{e}.json", {})
        if not s:
            continue
        closed = s.get("closed") or {}
        opened = s.get("opened") or {}
        snaps_file = public / "snapshots" / f"{e}.jsonl"
        n_snaps = sum(1 for line in snaps_file.read_text(encoding="utf-8").splitlines() if line.strip()) if snaps_file.exists() else 0
        rows.append({
            "epoch": e,
            "epoch_start": s.get("epoch_start"),
            "epoch_end": s.get("epoch_end"),
            "beacon_round": opened.get("round"),
            "map_root": s.get("root"),
            "map_size": s.get("size"),
            "snapshots_root": s.get("snapshots_root"),
            "prev_sheet_hash": s.get("prev_sheet_hash"),
            "snapshots": n_snaps,
            "anchor_status": closed.get("status"),
            "block_height": closed.get("block_height"),
            "block_time": closed.get("block_time"),
            "ots_url": f"{PUBLIC_BASE_URL}/ots/{e}.ots" if (public / "ots" / f"{e}.ots").exists() else None,
            "sheet_url": f"{PUBLIC_BASE_URL}/sheets/{e}.json",
        })
    return rows


def observation_shards(public: Path, epochs: List[Dict[str, Any]], out: Path) -> int:
    """Write observations/<YYYY-MM-DD>.jsonl, one shard per UTC day of epoch start.

    The Hub's viewer (the `datasets` JSON builder) fails on a split that
    contains an empty shard, and an hour with no observations is an empty
    snapshots/<epoch>.jsonl. The per-epoch files stay as the raw record; the
    day shards hold the same lines, unmodified, and only non-empty days are
    written. A day that has ended never changes again.
    """
    out.mkdir(parents=True, exist_ok=True)
    by_day: Dict[str, List[str]] = {}
    for e in epochs:
        f = public / "snapshots" / f"{e['epoch']}.jsonl"
        if not f.exists() or not e.get("epoch_start"):
            continue
        lines = [ln for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            by_day.setdefault(str(e["epoch_start"])[:10], []).extend(lines)
    for day, lines in by_day.items():
        p = out / f"{day}.jsonl"
        body = "\n".join(lines) + "\n"
        if not p.exists() or p.read_text(encoding="utf-8") != body:
            tmp = p.with_suffix(".jsonl.tmp")
            tmp.write_text(body, encoding="utf-8")
            tmp.replace(p)
    for f in out.iterdir():
        if f.is_file() and f.stem not in by_day:
            f.unlink()
    return sum(len(v) for v in by_day.values())


def target_rows(public: Path) -> List[Dict[str, Any]]:
    t = _read_json(public / "targets.json", {"targets": []})
    rows = t.get("targets") if isinstance(t, dict) else t
    keep = ("target_id", "first_seen", "last_seen", "observations", "negative", "negative_anchored_epochs",
            "last_result", "last_surface")
    return [{k: r.get(k) for k in keep} for r in rows]


def counts(public: Path, epochs: List[Dict[str, Any]], targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    latest = _read_json(public / "latest.json", {})
    idx = _read_json(public / "proofs" / "index.json", {"proofs": []})
    return {
        "latest_epoch": latest.get("latest_epoch"),
        "epochs": len(epochs),
        "anchored": sum(1 for e in epochs if e["anchor_status"] == "bitcoin"),
        "observations": sum(e["snapshots"] for e in epochs),
        "negative": latest.get("negative_snapshots_total"),
        "targets": len(targets),
        "map_size": latest.get("map_size"),
        "proofs": len(idx.get("proofs", [])),
        "genesis": epochs[0]["epoch_start"] if epochs else None,
        "state": (latest.get("status") or {}).get("state"),
        "generated_at": latest.get("generated_at"),
    }


def card(c: Dict[str, Any]) -> str:
    n = lambda k: f"{c[k]:,}" if isinstance(c.get(k), int) else "—"  # noqa: E731
    return f"""---
pretty_name: TACET disclosure ledger
license: cc-by-4.0
language:
  - en
tags:
  - transparency
  - ai-governance
  - model-cards
  - training-data
  - verifiable
  - bitcoin-anchored
  - crovia
size_categories:
  - 10K<n<100K
configs:
  - config_name: observations
    data_files: observations/*.jsonl
    default: true
  - config_name: epochs
    data_files: epochs.jsonl
  - config_name: targets
    data_files: targets.jsonl
---

# TACET disclosure ledger

Every hour, Crovia fetches the public model card of a rotating set of
Hugging Face models, runs one published predicate over the bytes — *does
this card disclose its training data?* — and signs what it saw. The hour
is opened by a public randomness beacon (drand) and closed by a Bitcoin
anchor (OpenTimestamps). This dataset is that log, byte for byte, as served
at [croviatrust.com/registry/data/tacet](https://croviatrust.com/registry/data/tacet/latest.json).

| | |
|---|---|
| Observing since | {c.get('genesis') or '—'} |
| Epochs (hours) | {n('epochs')} — {n('anchored')} anchored in Bitcoin |
| Signed observations | {n('observations')} — {n('negative')} found no disclosure |
| Models in the target list | {n('targets')} — {n('map_size')} have a slot in the map |
| Featured silence proofs | {n('proofs')} |
| Log state at build | `{c.get('state') or '—'}` ({c.get('generated_at') or '—'}) |

## What a row says, and what it does not

An observation says: *at this time, this observer fetched this URL, got
these bytes (hash and length), and the predicate returned this result.*
`result: false` means **no training-data disclosure was found on that
surface in that hour** — not that the provider disclosed nothing anywhere,
not fraud, not bad faith, not a quality grade. Hours not observed do not
count toward anything. See the
[TACET specification](https://croviatrust.com/registry/tacet/spec/)
and the [LACUNA page](https://croviatrust.com/registry/lacuna/).

## Tables

- **observations** (`observations/<YYYY-MM-DD>.jsonl`): one signed row per
  fetch — `target_id`, `surface_url`, `fetched_at`, `http_status`,
  `body_sha256`, `body_len`, `predicate` (id, version, code hash), `result`,
  `beacon_round`, `observer` (id, Ed25519 key), `signature`. Sharded by the
  UTC day the epoch opened; the same lines, unmodified, live in
  `snapshots/<epoch>.jsonl`, the per-hour file whose rows are the leaves of
  the sheet's `snapshots_root` (RFC 6962 Merkle root). Hours with no
  observations have an empty snapshots file and no line here.
- **epochs** (`epochs.jsonl`): one row per hour — map root and size,
  snapshots root and chain, drand round, snapshots counted, anchor status and
  Bitcoin block.
- **targets** (`targets.jsonl`): one row per model — first and last seen,
  observations, negatives, anchored negative epochs, last result.

## Files for verification

- `sheets/<epoch>.json` — the signed epoch sheet.
- `changes/<epoch>.json` — map changes of the hour (slot key, value hash).
- `ots/<epoch>.ots` — the OpenTimestamps proof of the sheet hash.
- `proofs/<slug>.seal.json` — featured level-2 silence proofs, wrapped as
  `crovia.seal.v1`; `proofs/index.json` lists them.
- `trust_root.json` — operator and observer public keys, beacon and anchor
  parameters. Verify against it, not against this card.

```bash
pip install crovia-tacet-operator
tacet-operator verify proofs/mistralai__Mistral-7B-v0.1.seal.json \
  --operator-pubkey "$(python3 -c 'import json;print(json.load(open("trust_root.json"))["operator"]["pubkey"]["key_hex"])')"
```

The verifier checks signatures, chaining, non-inclusion paths, snapshot
hashes and witnesses from the files alone; drand rounds and Bitcoin anchors
are checked against public relays unless `--offline`.

## Provenance and licence

Produced by Crovia Trust's TACET operator (`crovia-tacet-operator`,
Apache-2.0, [source](https://github.com/croviatrust/countersign/tree/main/tacet)).
Data CC-BY-4.0. Cite as *Crovia Trust, TACET disclosure ledger,
Hugging Face dataset, {dt.date.today().isoformat()}*; the DOI-bearing weekly
Silence Report is at [croviatrust.com/report/](https://croviatrust.com/report/).

Corrections are made by revision, never by rewriting a published epoch: a
sheet, once anchored, is a fact about the past.
"""


def survival_latest() -> Dict[str, Any]:
    """Headline facts of the latest Survival Report (counts only; rates need the report's own context)."""
    import urllib.request

    try:
        req = urllib.request.Request(SURVIVAL_LATEST_URL, headers={"User-Agent": "crovia-hf-publisher/1 (+https://croviatrust.com)"})
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 — the card must build without it
        return {}
    agg = d.get("aggregate") or {}
    return {
        "title": d.get("title"),
        "date": d.get("date"),
        "url": d.get("url") or "https://causari.dev/reports/survival/",
        "repositories": agg.get("repositories"),
        "ai_tagged_commits": agg.get("ai_tagged_commits"),
        "method": (d.get("method") or {}).get("version"),
        "doi": d.get("doi"),
    }


def _esc(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def org_card(c: Dict[str, Any], epochs: List[Dict[str, Any]], public: Path, survival: Dict[str, Any]) -> str:
    """The organisation card: the live state of the ledger, rendered from the same files as the dataset.

    Hugging Face renders README.md of the Space named README on the organisation
    page, with HTML and Tailwind classes allowed (see the spaCy and Amazon cards).
    Every number on it is a value in a public file; nothing is typed by hand.
    """
    n = lambda k: f"{c[k]:,}" if isinstance(c.get(k), int) else "—"  # noqa: E731
    anchored = [e for e in epochs if e["anchor_status"] == "bitcoin" and e.get("block_height")]
    last_block = max((e["block_height"] for e in anchored), default=None)
    idx = _read_json(public / "proofs" / "index.json", {"proofs": []})
    proofs = sorted(idx.get("proofs", []), key=lambda p: (-float(p.get("silence_days") or 0), (p.get("target_id") or "").lower()))
    featured, more = proofs[:8], max(0, len(proofs) - 8)
    dataset = f"https://huggingface.co/datasets/{REPO_ID}"
    more_html = (f'<p class="text-xs text-gray-500 mt-2">and {more} more in <a class="underline" '
                 f'href="{dataset}/blob/main/proofs/index.json">proofs/index.json</a></p>') if more else ""
    updated = (c.get("generated_at") or "")[:16].replace("T", " ") + " UTC" if c.get("generated_at") else "—"

    rows = "".join(
        f'<tr><td class="py-1.5 pr-4 cv-mono">{_esc(p["target_id"])}</td>'
        f'<td class="py-1.5 pr-4 text-right cv-mono">{int(p.get("observed_epochs") or 0):,}</td>'
        f'<td class="py-1.5 pr-4 text-right cv-mono">{_esc(p.get("silence_days") or "—")}</td>'
        f'<td class="py-1.5 text-right"><a class="underline" href="{dataset}/blob/main/proofs/{_esc(p["slug"])}.seal.json">proof</a></td></tr>'
        for p in featured
    )
    surv = ""
    if survival.get("title"):
        bits = [_esc(survival["title"])]
        if survival.get("date"):
            bits.append(_esc(survival["date"]))
        if isinstance(survival.get("repositories"), int):
            bits.append(f'{survival["repositories"]:,} repositories')
        if isinstance(survival.get("ai_tagged_commits"), int):
            bits.append(f'{survival["ai_tagged_commits"]:,} AI-tagged commits')
        if survival.get("method"):
            bits.append(f'method {_esc(survival["method"])}')
        surv = (f'<p class="text-sm mt-3"><span class="cv-label">Latest</span><br>'
                f'<a class="underline" href="{_esc(survival["url"])}">{" · ".join(bits)}</a></p>')

    head, body = _card_template(c, n, dataset, updated, last_block, rows, surv, proofs, more_html)
    return head + "\n".join(line for line in body.splitlines() if line.strip()) + "\n"


def _card_template(c, n, dataset, updated, last_block, rows, surv, proofs, more_html):  # noqa: ANN001
    head = """---
title: README
emoji: 🔐
colorFrom: gray
colorTo: gray
sdk: static
pinned: false
---

"""
    body = f"""<style>
  .cv-dark {{ background: #0b0b0d; color: #f4f4f2; border-radius: 14px; }}
  .cv-dark a {{ color: #f4f4f2; }}
  .cv-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .cv-num {{ font-size: 1.7rem; line-height: 1.05; font-weight: 600; letter-spacing: -0.02em; }}
  .cv-tile {{ border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 16px; }}
  .cv-label {{ font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.12em; color: #6b7280; }}
  .cv-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; margin-right: 6px; vertical-align: middle; }}
  .cv-btn {{ display: inline-block; border: 1px solid #f4f4f2; border-radius: 6px; padding: 7px 13px; font-size: 0.85rem; text-decoration: none; }}
  .cv-btn-solid {{ background: #f4f4f2; color: #0b0b0d !important; }}
  .cv-h {{ font-size: 2rem; line-height: 1.1; font-weight: 700; letter-spacing: -0.03em; }}
  .cv-card table {{ width: 100%; font-size: 0.85rem; border-collapse: collapse; }}
  .cv-card th {{ text-align: left; font-weight: 500; }}
  .cv-card tr {{ border-top: 1px solid #f0f0f0; }}
  .cv-pre {{ background: #0b0b0d; color: #f4f4f2; border-radius: 8px; padding: 12px 14px; font-size: 0.78rem; white-space: pre-wrap; word-break: break-word; }}
</style>

<div class="cv-card">

<div class="cv-dark p-6 md:p-8 mb-5">
  <div class="cv-mono text-sm opacity-70 mb-3">∴ Crovia Trust</div>
  <div class="cv-h mb-3">Crovia proves what did not happen.</div>
  <p class="text-base opacity-90 max-w-3xl">Every hour, Crovia fetches the public model cards of AI models on this Hub, asks one published
  question — <em>does this card disclose its training data?</em> — and signs what it saw. The hour is opened by a public randomness beacon
  (drand) and closed by a Bitcoin anchor. Anyone can verify the record without an account and without a Crovia server.</p>
  <div class="mt-5 flex flex-wrap gap-2">
    <a class="cv-btn cv-btn-solid" href="{dataset}">Open the ledger</a>
    <a class="cv-btn" href="https://croviatrust.com/registry/tacet/spec/">Read the specification</a>
    <a class="cv-btn" href="https://croviatrust.com">croviatrust.com</a>
  </div>
</div>

<p class="cv-label mb-2"><span class="cv-dot"></span>Live from the log · updated {_esc(updated)} · <a class="underline" href="{PUBLIC_BASE_URL}/latest.json">latest.json</a></p>

<div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-6">
  <div class="cv-tile"><div class="cv-num cv-mono">{n('latest_epoch')}</div><div class="cv-label mt-1">current epoch · since {_esc((c.get('genesis') or '')[:10] or '—')}</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">{n('observations')}</div><div class="cv-label mt-1">signed observations</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">{n('anchored')}</div><div class="cv-label mt-1">hours anchored in Bitcoin{f' · last block {last_block:,}' if last_block else ''}</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">{n('targets')}</div><div class="cv-label mt-1">models in the target list</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">{n('negative')}</div><div class="cv-label mt-1">observations that found no disclosure</div></div>
  <div class="cv-tile"><div class="cv-num cv-mono">{n('proofs')}</div><div class="cv-label mt-1">featured silence proofs</div></div>
</div>

<div class="grid md:grid-cols-2 gap-6 mb-6">
  <div>
    <div class="cv-label mb-1">Dataset · updated hourly</div>
    <h3 class="text-lg font-semibold mb-2"><a class="underline" href="{dataset}">TACET disclosure ledger</a></h3>
    <p class="text-sm">Every observation since {_esc((c.get('genesis') or '')[:10] or '—')}, byte for byte as served at croviatrust.com: the
    signed rows, the hourly epoch sheets, the map changes, the OpenTimestamps anchors and the featured proofs. Three tables in the viewer
    (<em>observations</em>, <em>epochs</em>, <em>targets</em>), CC-BY-4.0.</p>
    <p class="text-sm mt-3"><span class="cv-label">Verify a proof yourself</span></p>
<pre class="cv-pre cv-mono">pip install crovia-tacet-operator
tacet-operator verify proofs/&lt;slug&gt;.seal.json \\
  --operator-pubkey &lt;operator key from trust_root.json&gt;</pre>
    <p class="text-xs text-gray-500 mt-1">Checks signatures, chaining, non-inclusion paths, snapshot hashes; drand rounds and Bitcoin blocks against public relays.</p>
  </div>
  <div>
    <div class="cv-label mb-1">Weekly report · open method</div>
    <h3 class="text-lg font-semibold mb-2"><a class="underline" href="https://causari.dev">Survival Report (causari)</a></h3>
    <p class="text-sm">How much AI-tagged code is still at HEAD, repository by repository, against the same repository's untagged code of the
    same age. Built with <code>causari</code>, one open-source Rust binary, no cloud: counts, not grades, and every number in the report
    can be recomputed with the command the report prints and verified offline.</p>
    {surv}
<pre class="cv-pre cv-mono mt-3">npx causari audit &lt;owner/repo&gt;
pipx run causari audit &lt;owner/repo&gt;</pre>
  </div>
</div>

<div class="mb-6">
  <div class="cv-label mb-1">Featured proofs · {len(proofs)} model cards, silence documented hour by hour</div>
  <p class="text-sm mb-2">A <em>silence</em> is a run of anchored hours in which every observation of a model card found no training-data
  disclosure on that surface. It is a statement about a web page over time — not about fraud, bad faith, or what the provider disclosed elsewhere.</p>
  <table>
    <thead><tr><th class="pb-1">Model card</th><th class="pb-1 text-right">Hours observed</th><th class="pb-1 text-right">Silence (days)</th><th class="pb-1 text-right">Proof</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  {more_html}
</div>

<div class="text-xs text-gray-500 border-t pt-3">
  <a class="underline" href="https://croviatrust.com/registry/tacet/spec/">TACET specification</a> (Internet-Draft <span class="cv-mono">draft-crovia-tacet</span>) ·
  <a class="underline" href="https://croviatrust.com/registry/lacuna/">LACUNA</a> ·
  <a class="underline" href="https://croviatrust.com/registry/seal/">Crovia Seal</a> ·
  <a class="underline" href="https://github.com/croviatrust">github.com/croviatrust</a> ·
  <a class="underline" href="https://causari.dev">causari.dev</a> ·
  <a class="underline" href="mailto:info@croviatrust.com">info@croviatrust.com</a><br>
  Data CC-BY-4.0, code Apache-2.0. Hours not observed count toward nothing. Corrections are made by revision, never by rewriting an anchored epoch.
  This card is regenerated hourly by the same script that publishes the dataset.
</div>
</div>
"""
    return head, body


def upload_org_card(readme: Path, repo_id: str, message: str) -> str:
    """Write README.md of the organisation card Space; remove the static-Space template files if present."""
    token = os.environ.get("HF_TOKEN")
    if not token:
        raise SystemExit("HF_TOKEN is not set (source /etc/crovia/hf.env)")
    from huggingface_hub import CommitOperationAdd, CommitOperationDelete, HfApi

    api = HfApi(token=token)
    api.create_repo(repo_id, repo_type="space", space_sdk="static", exist_ok=True)
    present = set(api.list_repo_files(repo_id, repo_type="space"))
    if "README.md" in present:
        current = Path(api.hf_hub_download(repo_id, "README.md", repo_type="space")).read_bytes()
        if current == readme.read_bytes() and not ({"index.html", "style.css"} & present):
            return "unchanged"
    ops: List[Any] = [CommitOperationAdd(path_in_repo="README.md", path_or_fileobj=str(readme))]
    # The Hub shows index.html instead of the card while the template files exist.
    ops += [CommitOperationDelete(path_in_repo=f) for f in ("index.html", "style.css") if f in present]
    info = api.create_commit(repo_id=repo_id, repo_type="space", operations=ops, commit_message=message)
    return getattr(info, "commit_url", str(info))


def build(public: Path, out: Path) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    for d in COPIED_DIRS:
        if (public / d).is_dir():
            sync_tree(public / d, out / d)
    for f in COPIED_FILES:
        if (public / f).exists():
            shutil.copy2(public / f, out / f)
    latest = int(_read_json(public / "latest.json")["latest_epoch"])
    epochs = epoch_rows(public, latest)
    targets = target_rows(public)
    observation_shards(public, epochs, out / "observations")
    _write_jsonl(out / "epochs.jsonl", epochs)
    _write_jsonl(out / "targets.jsonl", targets)
    c = counts(public, epochs, targets)
    (out / "README.md").write_text(card(c), encoding="utf-8")
    (out / ".gitattributes").write_text("*.ots filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8")
    c["_epochs"] = epochs
    return c


def card_path(out: Path) -> Path:
    # Outside the dataset folder, so upload_folder never ships it.
    return out.with_name(out.name + "-org-card") / "README.md"


def build_org_card(public: Path, out: Path, c: Dict[str, Any]) -> Path:
    p = card_path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(org_card(c, c["_epochs"], public, survival_latest()), encoding="utf-8")
    return p


def upload(out: Path, repo_id: str, message: str) -> str:
    token = os.environ.get("HF_TOKEN")
    if not token:
        raise SystemExit("HF_TOKEN is not set (source /etc/crovia/hf.env)")
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    api.create_repo(repo_id, repo_type="dataset", exist_ok=True)
    info = api.upload_folder(repo_id=repo_id, repo_type="dataset", folder_path=str(out),
                             commit_message=message, delete_patterns=["observations/*", "snapshots/*", "sheets/*", "changes/*", "ots/*", "proofs/*"])
    return getattr(info, "commit_url", str(info))


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--public", type=Path, default=Path(os.environ.get("TACET_PUBLIC", "/var/www/registry/data/tacet")))
    ap.add_argument("--out", type=Path, default=Path("/opt/crovia/tacet/hf-dataset"))
    ap.add_argument("--repo", default=REPO_ID)
    ap.add_argument("--card-repo", default=ORG_CARD_REPO, help="Space that holds the organisation card")
    ap.add_argument("--no-card", action="store_true", help="do not render or upload the organisation card")
    ap.add_argument("--dry-run", action="store_true", help="build the folder and the card, do not upload")
    a = ap.parse_args(argv)
    c = build(a.public, a.out)
    print(f"hf_publish_tacet: built {a.out}: epoch {c['latest_epoch']}, {c['epochs']} epochs "
          f"({c['anchored']} anchored), {c['observations']} observations, {c['targets']} targets, {c['proofs']} proofs")
    card_file = None if a.no_card else build_org_card(a.public, a.out, c)
    if card_file:
        print(f"hf_publish_tacet: built organisation card {card_file}")
    if a.dry_run:
        return 0
    msg = f"epoch {c['latest_epoch']}: {c['observations']} observations, {c['anchored']} anchored epochs"
    url = upload(a.out, a.repo, msg)
    print(f"hf_publish_tacet: uploaded to {a.repo} ({url})")
    if card_file:
        r = upload_org_card(card_file, a.card_repo, msg)
        print(f"hf_publish_tacet: organisation card {a.card_repo} {r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
