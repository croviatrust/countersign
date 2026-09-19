"""Discovery files for /registry/data/tacet/ (SPEC §12)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List

from tacet.keys import SigningKey

from . import drand as drand_mod
from .config import DRAND_CHAIN_HASH, EPOCH_SECONDS, GENESIS, MAP_ID, PUBLIC_BASE_URL, Settings
from .predicates import REGISTRY, load as load_predicate
from .prove import build as build_proof, negative_epochs, slug
from .state import State, _write_json
from .targets import FEATURED_DEFAULT


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def trust_root(settings: Settings, keys: Dict[str, SigningKey], drand_info: Dict[str, Any] | None = None) -> Dict[str, Any]:
    preds = []
    for pid in REGISTRY:
        _, version, code_hash = load_predicate(pid)
        preds.append({"id": pid, "version": version, "code_hash": "sha256:" + code_hash.hex(),
                      "source_url": f"https://github.com/croviatrust/countersign/blob/main/tacet/operator/tacet_operator/predicates/{REGISTRY[pid]}.py"})
    tr = {
        "trust_root_version": "crovia.tacet.trust_root.v1",
        "map_id": MAP_ID,
        "genesis": GENESIS.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "epoch_seconds": EPOCH_SECONDS,
        "operator": {"id": keys["operator"].id, "pubkey": keys["operator"].pubkey_json()},
        "observers": [{"id": keys["observer"].id, "pubkey": keys["observer"].pubkey_json()}],
        "proof_issuer": {"id": keys["issuer"].id, "pubkey": keys["issuer"].pubkey_json()},
        "beacon": {"kind": "drand", "chain_hash": DRAND_CHAIN_HASH, "tolerance_seconds": 1800,
                   **({k: drand_info[k] for k in ("public_key", "period", "genesis_time", "scheme") if k in drand_info} if drand_info else {})},
        "anchor": {"kind": "ots", "proof_url_template": f"{PUBLIC_BASE_URL}/ots/{{epoch}}.ots"},
        "predicates": preds,
        "layout": {
            "sheet": f"{PUBLIC_BASE_URL}/sheets/{{epoch}}.json",
            "snapshots": f"{PUBLIC_BASE_URL}/snapshots/{{epoch}}.jsonl",
            "changes": f"{PUBLIC_BASE_URL}/changes/{{epoch}}.json",
            "values": f"{PUBLIC_BASE_URL}/values/{{key_hex}}.json",
            "proofs": f"{PUBLIC_BASE_URL}/proofs/{{slug}}.seal.json",
            "latest": f"{PUBLIC_BASE_URL}/latest.json",
        },
        "spec": "https://github.com/croviatrust/countersign/blob/main/tacet/SPEC.md",
        "generated_at": _now(),
    }
    _write_json(settings.paths.public / "trust_root.json", tr)
    return tr


def index(settings: Settings) -> Dict[str, Any]:
    st = State(settings.paths)
    last = st.latest_epoch()
    rows: List[Dict[str, Any]] = []
    anchored = 0
    total_snaps = total_neg = 0
    if last is not None:
        for e in range(0, last + 1):
            s = st.load_sheet(e)
            if s is None:
                continue
            snaps = st.load_snapshots(e)
            neg = sum(1 for x in snaps if x["result"] is False)
            total_snaps += len(snaps)
            total_neg += neg
            if s["closed"]["status"] == "bitcoin":
                anchored += 1
            rows.append({"epoch": e, "epoch_start": s["epoch_start"], "epoch_end": s["epoch_end"], "size": s["size"],
                         "snapshots": len(snaps), "negative": neg, "root": s["root"],
                         "sheet_hash": s["closed"]["anchored_digest"], "closed": s["closed"]["status"],
                         "block_height": s["closed"].get("block_height"), "beacon_round": s["opened"]["round"]})
    out = {"index_version": "crovia.tacet.index.v1", "map_id": MAP_ID, "epochs": rows, "generated_at": _now()}
    _write_json(settings.paths.public / "index.json", out)
    latest = {
        "latest_version": "crovia.tacet.latest.v1", "map_id": MAP_ID,
        "latest_epoch": last, "epochs": len(rows), "anchored_epochs": anchored,
        "map_size": rows[-1]["size"] if rows else 0,
        "snapshots_total": total_snaps, "negative_snapshots_total": total_neg,
        "latest_sheet": rows[-1] if rows else None,
        "generated_at": _now(),
    }
    _write_json(settings.paths.public / "latest.json", latest)
    return latest


def featured_proofs(settings: Settings, keys: Dict[str, SigningKey], targets: List[str] | None = None) -> List[Dict[str, Any]]:
    """Regenerate level-2 proofs for featured targets that have at least one negative snapshot."""
    st = State(settings.paths)
    last = st.latest_epoch()
    if last is None:
        return []
    out: List[Dict[str, Any]] = []
    for t in targets or settings.featured or FEATURED_DEFAULT:
        negs = negative_epochs(st, t, 0, last)
        if not negs:
            continue
        bundle = build_proof(settings, keys["issuer"], t, from_epoch=0, to_epoch=last)
        path = settings.paths.proofs / f"{slug(t)}.seal.json"
        _write_json(path, bundle)
        sil = bundle["proof"]["silence"]
        out.append({"target_id": t, "slug": slug(t), "url": f"{PUBLIC_BASE_URL}/proofs/{slug(t)}.seal.json",
                    "strength": bundle["proof"]["strength"], "from_epoch": 0, "to_epoch": last,
                    "observed_epochs": sil["observed_epochs"], "silence_days": sil["silence_days"],
                    "observed_from": sil["observed_from"], "observed_to": sil["observed_to"],
                    "seal_id": bundle["seal"]["seal_id"], "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    out.sort(key=lambda r: -float(r["silence_days"]))
    _write_json(settings.paths.public / "proofs" / "index.json",
                {"proofs_version": "crovia.tacet.proofs_index.v1", "map_id": MAP_ID, "proofs": out, "generated_at": _now()})
    return out


def observed_targets(settings: Settings) -> Dict[str, Any]:
    """Per-target summary across all epochs: last result, negative epochs, first/last seen."""
    st = State(settings.paths)
    last = st.latest_epoch()
    summary: Dict[str, Dict[str, Any]] = {}
    if last is not None:
        for e in range(0, last + 1):
            sheet = st.load_sheet(e)
            anchored = bool(sheet and sheet["closed"]["status"] == "bitcoin")
            for s in st.load_snapshots(e):
                r = summary.setdefault(s["target_id"], {"target_id": s["target_id"], "observations": 0, "negative": 0,
                                                        "negative_anchored_epochs": 0, "first_seen": s["fetched_at"],
                                                        "last_seen": s["fetched_at"], "last_result": None, "last_surface": None})
                r["observations"] += 1
                r["last_seen"] = s["fetched_at"]
                r["last_result"] = s["result"]
                r["last_surface"] = s["surface_url"]
                if s["result"] is False:
                    r["negative"] += 1
                    if anchored:
                        r["negative_anchored_epochs"] += 1
    rows = sorted(summary.values(), key=lambda r: (-r["negative_anchored_epochs"], -r["negative"], r["target_id"]))
    out = {"targets_version": "crovia.tacet.targets.v1", "map_id": MAP_ID, "count": len(rows), "targets": rows, "generated_at": _now()}
    _write_json(settings.paths.public / "targets.json", out)
    return out


def badges(settings: Settings, latest: Dict[str, Any], targets: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """shields.io endpoint badges (https://shields.io/badges/endpoint-badge) under public/badges/.

    Figures follow CANON §4: epochs and anchored epochs from latest.json, models from
    targets.json, negative snapshots from latest.json. Colour never encodes a judgement.
    """
    blue = "1ec5ff"
    epochs, anchored = latest.get("epochs", 0), latest.get("anchored_epochs", 0)
    out = {
        "epochs": {"label": "TACET epochs", "message": f"{epochs:,} ({anchored:,} in Bitcoin)", "color": blue},
        "models": {"label": "models observed", "message": f"{targets.get('count', 0):,}", "color": blue},
        "negative": {"label": "signed observations of absence", "message": f"{latest.get('negative_snapshots_total', 0):,}", "color": blue},
        "latest": {"label": "latest epoch", "message": (latest.get("latest_sheet") or {}).get("epoch_end", "none")[:16] + "Z", "color": blue},
    }
    (settings.paths.public / "badges").mkdir(parents=True, exist_ok=True)
    for name, badge in out.items():
        _write_json(settings.paths.public / "badges" / f"{name}.json", {"schemaVersion": 1, "cacheSeconds": 300, **badge})
    return out


def publish_all(settings: Settings, keys: Dict[str, SigningKey], *, with_proofs: bool = False) -> Dict[str, Any]:
    try:
        info = drand_mod.fetch_info()
    except Exception:  # noqa: BLE001
        info = None
    trust_root(settings, keys, info)
    latest = index(settings)
    targets = observed_targets(settings)
    badges(settings, latest, targets)
    if with_proofs:
        featured_proofs(settings, keys)
    return latest
