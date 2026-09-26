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
    return c


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
    ap.add_argument("--dry-run", action="store_true", help="build the folder, do not upload")
    a = ap.parse_args(argv)
    c = build(a.public, a.out)
    print(f"hf_publish_tacet: built {a.out}: epoch {c['latest_epoch']}, {c['epochs']} epochs "
          f"({c['anchored']} anchored), {c['observations']} observations, {c['targets']} targets, {c['proofs']} proofs")
    if a.dry_run:
        return 0
    url = upload(a.out, a.repo, f"epoch {c['latest_epoch']}: {c['observations']} observations, {c['anchored']} anchored epochs")
    print(f"hf_publish_tacet: uploaded to {a.repo} ({url})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
