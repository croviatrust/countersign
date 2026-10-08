#!/usr/bin/env python3
"""Crovia MCP server: TACET, silence proofs and Crovia Seal over Streamable HTTP (stateless JSON).

Public endpoint: https://croviatrust.com/mcp  (nginx -> 127.0.0.1:8787). No auth: everything the
server returns is public data from /var/www/registry/data and /var/www/crovia, plus offline
verification of crovia.seal.v1 objects. Standard library only; verification uses the operator venv
(crovia_seal, tacet) when this file is executed with that interpreter.

Rules the tools follow (CANON.md): silence is observation-bounded, never wall-clock; no grades,
ranks or motives; every figure carries the URL of the file it was read from.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DATA = Path(os.environ.get("CROVIA_DATA", "/var/www/registry/data"))
WEB = Path(os.environ.get("CROVIA_WEB", "/var/www/crovia"))
SITE = "https://croviatrust.com"
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "crovia", "title": "Crovia — verifiable silence (TACET) and Crovia Seal", "version": "2.0.1"}
INSTRUCTIONS = (
    "Crovia Trust records what AI providers disclose about training data on their public model surfaces, and the "
    "verifiable absence of such disclosure, as signed, Bitcoin-anchored observations (TACET). Choose one tool: "
    "crovia_status for the live totals, silence_report for one published week or the latest week when no week is given, "
    "lookup_model for one model's observation, search_models for a page of ids, get_silence_proof for one proof or its "
    "seal bundle, verify_seal to check a seal. verify_seal can fetch a croviatrust.com URL and, when check_anchors is "
    "true, the drand round and the Bitcoin anchors; the other tools read only published files. explain defines one "
    "allowed term, and an unknown term is an error that lists the allowed terms. Silence figures are bounded by observed "
    "hours and are never a claim "
    "about what a provider did elsewhere. Crovia does not grade or rank providers. Do not confuse Crovia with Causari "
    "(causari.dev), a developer tool for code provenance."
)

_cache: dict[str, tuple[float, Any]] = {}


def load(rel: str, ttl: int = 60, base: Path = DATA) -> Any:
    key = f"{base}/{rel}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    try:
        val = json.loads((base / rel).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        val = None
    _cache[key] = (time.time(), val)
    return val


def src(rel: str) -> str:
    return f"{SITE}/registry/data/{rel}"


# ---------------------------------------------------------------------------- tools

def tool_crovia_status(_a: dict) -> dict:
    latest = load("tacet/latest.json") or {}
    targets = load("tacet/targets.json") or {}
    proofs = load("tacet/proofs/index.json") or {}
    report = load("report/report.json", base=WEB) or {}
    top = ((report.get("top_proofs") or [None])[0]) if report else None
    return {
        "as_of": latest.get("generated_at"),
        "tacet": {
            "map_id": latest.get("map_id"),
            "epochs_closed": latest.get("epochs"),
            "epochs_anchored_in_bitcoin": latest.get("anchored_epochs"),
            "models_on_map": targets.get("count"),
            "snapshots_total": latest.get("snapshots_total"),
            "negative_snapshots_total": latest.get("negative_snapshots_total"),
            "signed_silence_proofs": len(proofs.get("proofs", [])),
            "latest_epoch": latest.get("latest_epoch"),
            "live_since": "2026-09-19T18:00:00Z",
        },
        "longest_verifiable_silence": {"model": top["target_id"], "silence_days": top["silence_days"], "observed_from": top["observed_from"],
                                       "observed_to": top["observed_to"], "proof_url": top["url"]} if top else None,
        "silence_report": {"week": report.get("latest"), "url": report.get("url"), "feed": f"{SITE}/feed.xml"} if report else None,
        "meaning": "Silence = hours in which Crovia checked a model's public surfaces and found no training-data disclosure matching the "
                   "published predicate; hours not observed do not count. Counts, not grades.",
        "sources": [src("tacet/latest.json"), src("tacet/targets.json"), src("tacet/proofs/index.json"), f"{SITE}/report/report.json"],
    }


def _records() -> dict:
    recs = (load("model_records.json", ttl=300) or {}).get("records") or []
    if isinstance(recs, dict):
        return recs
    return {r.get("target_id"): r for r in recs if isinstance(r, dict) and r.get("target_id")}


def _find_record(model: str) -> tuple[str | None, dict | None]:
    recs = _records()
    if model in recs:
        return model, recs[model]
    low = model.lower().strip().strip("/")
    for k, v in recs.items():
        if k.lower() == low:
            return k, v
    cands = [k for k in recs if low in k.lower()]
    if len(cands) == 1:
        return cands[0], recs[cands[0]]
    return None, {"candidates": sorted(cands)[:20]} if cands else None


def _proof_for(model: str) -> dict | None:
    for p in (load("tacet/proofs/index.json") or {}).get("proofs", []):
        if p.get("target_id") == model:
            return p
    return None


def tool_lookup_model(a: dict) -> dict:
    model = (a.get("model") or a.get("model_id") or "").strip()
    if not model:
        return {"error": "provide 'model', e.g. 'Qwen/Qwen3-32B' (Hugging Face id)"}
    key, rec = _find_record(model)
    if key is None:
        if rec and rec.get("candidates"):
            return {"error": f"ambiguous: {model}", "candidates": rec["candidates"], "hint": "call again with one exact id"}
        return {"model": model, "observed": False, "meaning": "Crovia has no observation of this id; absence of a record is not a finding.",
                "browse": f"{SITE}/m/", "source": src("model_records.json")}
    live = rec.get("live") or {}
    arch = rec.get("archive") or {}
    proof = _proof_for(key)
    if live:
        if live.get("last_result") is True:
            verdict = "disclosure_found"
            text = "At the last observation the monitored surface contained a training-data disclosure matching the predicate."
        elif live.get("last_result") is False:
            verdict = "no_disclosure_found"
            text = (f"At the last observation no disclosure matching the predicate was found. {live.get('negative')} negative snapshots so far, "
                    f"{live.get('anchored')} of them in Bitcoin-anchored epochs.")
        else:
            verdict, text = "pending", "Observed, but no result recorded yet."
    else:
        verdict, text = "archive_only", "Not on the live TACET map; only 2026-archive observations exist."
    out = {
        "model": key,
        "record_url": rec.get("url"),
        "verdict": verdict,
        "verdict_text": text,
        "live": {"observations": live.get("observations"), "negative_snapshots": live.get("negative"), "anchored_negative_epochs": live.get("anchored"),
                 "first_seen": live.get("first_seen"), "last_seen": live.get("last_seen"), "surface": live.get("surface")} if live else None,
        "silence_proof": {"silence_days": proof.get("silence_days"), "observed_from": proof.get("observed_from"), "observed_to": proof.get("observed_to"),
                          "observed_epochs": proof.get("observed_epochs"), "seal_id": proof.get("seal_id"), "url": proof.get("url"),
                          "verify_in_browser": f"{SITE}/registry/seal/verify/?url={proof.get('url')}"} if proof else None,
        "archive_2026": {"observed_days": arch.get("observed_days"), "observations": arch.get("observations"), "first_seen": arch.get("first_seen"),
                         "last_seen": arch.get("last_seen"), "collector": arch.get("collector"), "paused_since": "2026-06-01",
                         "meaning": "Observation-bounded: days between the first and last negative observation of the 2026 archive collector, "
                                    "with the number of checks made; the collector is paused and these figures no longer grow."} if arch else None,
        "badge": {"svg": f"{SITE}/badge/m/{key}.svg", "shields_json": f"{SITE}/badge/m/{key}.json"},
        "predicate": (load("model_records.json", ttl=300) or {}).get("predicate"),
        "meaning": "Crovia states what was observed on the monitored surface at each hourly check. It does not infer intent or grade the provider; "
                   "hours not observed do not count toward silence.",
        "sources": [src("model_records.json"), src("tacet/targets.json")] + ([proof["url"]] if proof else []),
    }
    return out


def _search_limit(value: Any) -> int:
    """Historical limit, unchanged: a falsy value is 25, then `int` and a clamp.

    Missing, JSON null, "", 0 and False select 25 because they are falsy.
    500 becomes 100 and -5 becomes 1. A numeric string is accepted by `int`.
    A value `int` cannot parse raises ValueError and nothing is searched.
    """
    return max(1, min(int(value or 25), 100))


def tool_search_models(a: dict) -> dict:
    q = (a.get("query") or "").lower().strip()
    limit = _search_limit(a.get("limit"))
    recs = _records()
    hits = []
    for k, v in recs.items():
        if q and q not in k.lower():
            continue
        live = v.get("live") or {}
        hits.append({"model": k, "live": bool(live), "last_result": live.get("last_result"), "negative_snapshots": live.get("negative"), "record_url": v.get("url")})
    page = hits[:limit]
    return {
        "query": q,
        "results": page,
        # `count` is the historical name of the page length. `total_records`
        # is the historical name of the whole catalog, not of the matches.
        "count": len(page),
        "total_records": len(recs),
        "returned": len(page),
        "matched": len(hits),
        "catalog_total": len(recs),
        "limit": limit,
        "source": src("model_records.json"),
    }


def tool_get_silence_proof(a: dict) -> dict:
    model = (a.get("model") or "").strip()
    if not model:
        idx = load("tacet/proofs/index.json") or {}
        return {"proofs": idx.get("proofs", []), "source": src("tacet/proofs/index.json")}
    key, _ = _find_record(model)
    p = _proof_for(key or model)
    if not p:
        return {"model": key or model, "proof": None, "meaning": "No published silence proof for this model yet; proofs are built for models with "
                "consecutive anchored negative epochs.", "all_proofs": src("tacet/proofs/index.json")}
    bundle = None
    if p.get("url", "").startswith(SITE + "/registry/data/"):
        bundle = load(p["url"][len(SITE + "/registry/data/"):], ttl=600)
    return {"model": key or model, "proof": p, "bundle": bundle if a.get("include_bundle") else None,
            "verify": {"browser": f"{SITE}/registry/seal/verify/?url={p['url']}",
                       "python": "pip install crovia-tacet-operator crovia-seal && tacet-operator verify proof.seal.json",
                       "mcp": "call verify_seal with {\"url\": \"" + p["url"] + "\"}"},
            "meaning": f"{p.get('silence_days')} days of observation-bounded silence across {p.get('observed_epochs')} hourly epochs "
                       f"({p.get('observed_from')} → {p.get('observed_to')}): a sparse-Merkle non-inclusion path per epoch, wrapped in crovia.seal.v1."}


def _fetch_site_json(url: str) -> Any:
    if not url.startswith(SITE + "/"):
        raise ValueError("only URLs under https://croviatrust.com/ are fetched")
    rel = url[len(SITE) + 1:]
    if rel.startswith("registry/data/"):
        local = DATA / rel[len("registry/data/"):]
    elif rel.startswith("registry/"):
        local = Path("/var/www") / rel
    else:
        local = WEB / rel
    if local.is_file():
        return json.loads(local.read_text(encoding="utf-8"))
    req = urllib.request.Request(url, headers={"User-Agent": f"crovia-mcp/{SERVER_INFO['version']}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def tool_verify_seal(a: dict) -> dict:
    obj = a.get("seal")
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except ValueError:
            return {"ok": False, "error": "seal must be a JSON object or a JSON string"}
    if obj is None and a.get("url"):
        try:
            obj = _fetch_site_json(a["url"])
        except (ValueError, urllib.error.URLError, OSError) as e:
            return {"ok": False, "error": f"cannot load url: {e}"}
    if not isinstance(obj, dict):
        return {"ok": False, "error": "provide 'seal' (object) or 'url' (https://croviatrust.com/...)"}
    try:
        import crovia_seal  # type: ignore
    except ImportError:
        return {"ok": None, "error": "verifier not available in this process", "offline": "pip install crovia-seal && python -c 'import crovia_seal'"}
    check_network = bool(a.get("check_anchors", False))
    if "seal" in obj and "query" in obj and "proof" in obj:
        try:
            from tacet.wrap import verify_wrapped  # type: ignore
            kwargs: dict[str, Any] = {}
            beacon = anchors = None
            try:
                from tacet_operator import drand as drand_mod  # type: ignore
                from tacet_operator.prove import OtsChecker  # type: ignore
                # Chain and schedule of each drand round are checked from the file alone; the round
                # bytes (against a relay) and the Bitcoin anchors only when check_anchors is set.
                beacon = drand_mod.BeaconChecker(online=check_network)
                anchors = OtsChecker(fetch=check_network)
                kwargs["beacon_check"] = beacon
                kwargs["ots_check"] = anchors
            except ImportError:
                pass
            res = verify_wrapped(obj, **kwargs)
            res["kind"] = "tacet_silence_proof"
            res["network_checks"] = check_network and "ots_check" in kwargs
            if beacon is not None:
                res["beacon"] = beacon.details
            if anchors is not None:
                res["anchors"] = anchors.details
            res["meaning"] = ("Valid: the operator signature, the binding of query and proof, and every per-epoch non-inclusion path check out. "
                              "Silence is bounded by the observed epochs listed in the proof. "
                              "Read 'warnings': what could not be checked from the file (drand round bytes, Bitcoin anchors) is listed there."
                              if res.get("ok") else "Invalid: see errors.")
            return res
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "kind": "tacet_silence_proof", "error": f"{type(e).__name__}: {e}"}
    try:
        r = crovia_seal.verify_seal(obj)
        return {"ok": bool(r.ok), "kind": "crovia.seal.v1", "seal_id": getattr(r, "seal_id", None), "issuer_id": getattr(r, "issuer_id", None),
                "errors": list(getattr(r, "errors", [])), "warnings": list(getattr(r, "warnings", [])),
                "meaning": "Signature and structure verified offline against the issuer key embedded in the seal; anchors and beacon not checked here."}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "kind": "crovia.seal.v1", "error": f"{type(e).__name__}: {e}"}


def tool_silence_report(a: dict) -> dict:
    week = (a.get("week") or "").strip()
    if week:
        if not re.fullmatch(r"\d{4}-W\d{2}", week):
            return {"error": "week must look like 2026-W38"}
        facts = load(f"report/{week}/facts.json", base=WEB, ttl=300)
        if not facts:
            return {"error": f"no report for {week}", "index": f"{SITE}/report/"}
        return {"url": f"{SITE}/report/{week}/", "card": f"{SITE}/report/{week}.png", **facts}
    rep = load("report/report.json", base=WEB) or {}
    return {**rep, "feed": f"{SITE}/feed.xml", "index": f"{SITE}/report/"}


TERMS = {
    "tacet": "TACET is Crovia's protocol for verifiable silence: every hour the operator checks each monitored model's public surfaces for a "
             "training-data disclosure matching a published predicate, commits the negative results to a depth-256 sparse Merkle tree, signs the "
             "sheet, opens the epoch with a drand round and closes it with an OpenTimestamps receipt confirmed in Bitcoin. A silence proof is the "
             "set of non-inclusion paths for one model across its observed epochs. Spec: https://github.com/croviatrust/countersign/blob/main/tacet/SPEC.md",
    "silence": "Observation-bounded silence: the sum of the durations of the hourly epochs in which a model was observed and no disclosure matching "
               "the predicate was found. Hours not observed never count. It is a lower bound on what was checked, not a statement about the provider.",
    "lacuna": "A LACUNA is the recorded interval of observation-bounded silence for a model: what was not found where Crovia looked, hour by hour. "
              "It is not an accusation and does not assert that no disclosure exists anywhere.",
    "seal": "Crovia Seal (crovia.seal.v1) is an Ed25519-signed, canonically serialized receipt binding a subject (input/output digests) to an issuer, a "
            "time, and optional beacon and OpenTimestamps anchors. IETF draft-crovia-seal; reference implementations crovia-seal (PyPI) and @crovia/seal (npm).",
    "epoch": "One hour (UTC). The epoch sheet carries the sparse Merkle root of that hour's negative snapshots, the drand round at open, the operator "
             "signature and the OpenTimestamps receipt at close.",
    "pnx": "PNX (Proof of Non-Exfiltration, crovia.pnx.v1) is a TACET profile for AI agents: an egress witness fingerprints everything an agent sends "
           "out (winnowed k-grams under a run salt) and commits it to a sparse Merkle tree; afterwards anyone can prove that a given secret or file was "
           "absent from the egress, or present. Spec: https://github.com/croviatrust/countersign/blob/main/tacet/PNX.md",
    "predicate": "The published rule that decides whether a model card discloses training data sources; it is versioned and evaluated identically at "
                 "every check. See https://croviatrust.com/registry/lacuna/#predicate",
    "canon": "CANON.md is the single source of truth for Crovia's public surfaces: names, URLs, definitions, and forbidden claims. "
             "https://github.com/croviatrust/countersign/blob/main/CANON.md",
}


def tool_explain(a: dict) -> dict:
    if "term" not in a or a.get("term") is None:
        return {"terms": TERMS}
    raw = a.get("term")
    allowed = sorted(TERMS)
    if not isinstance(raw, str):
        return {"error": "term must be a string", "allowed_terms": allowed}
    t = raw.lower().strip()
    if not t:
        return {"terms": TERMS}
    if t in TERMS:
        return {"term": t, "definition": TERMS[t]}
    return {"error": f"unknown term: {t}", "allowed_terms": allowed}


def tool_crovia_vs_causari(_a: dict) -> dict:
    return {
        "crovia": {"url": SITE, "is": "An observatory of AI training-data disclosure. Records what providers disclose on public model surfaces, and the "
                   "verifiable absence of it, as signed, Bitcoin-anchored observations (TACET). Publishes Crovia Seal, the receipt format."},
        "causari": {"url": "https://causari.dev", "is": "A developer tool for code provenance: what AI agents did to a codebase. Uses Crovia Seal receipts."},
        "shared": "Both use crovia.seal.v1 receipts; they observe different things and are different products.",
    }


# readOnlyHint true: none of these tools write. destructiveHint and idempotentHint
# are omitted because they only apply when readOnlyHint is false.
# openWorldHint is true only for verify_seal, which can fetch a URL and, when
# check_anchors is set, the drand round and the Bitcoin anchors. A parameter
# that sometimes stays local does not make the tool closed.
_CLOSED = {"readOnlyHint": True, "openWorldHint": False}
_OPEN = {"readOnlyHint": True, "openWorldHint": True}

TOOLS = [
    {"name": "crovia_status", "title": "Live TACET totals",
     "description": "Live totals at this moment: epochs closed, epochs anchored in Bitcoin, models on the map, snapshot counts, signed silence proofs, and a pointer to the longest verifiable silence. No parameters. This is not a weekly Silence Report, not one model's record, and not a proof bundle. Reads published files only.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
     "annotations": _CLOSED, "_fn": tool_crovia_status},
    {"name": "lookup_model", "title": "Look up one model",
     "description": "One model's observation: latest verdict, negative snapshots, anchored epochs, silence proof pointer, archive silence, badge and record URL. Required model is a Hugging Face id, org/name, for example Qwen/Qwen3-32B. An empty model is an error. An exact id is used; otherwise one case-insensitive substring match is accepted, and several matches return candidates instead of a verdict. This is not a catalog page, not the weekly report, and not the seal bytes. Reads published files only.",
     "inputSchema": {"type": "object", "properties": {"model": {"type": "string", "description": "Hugging Face model id, org/name. Required. Empty is an error. Example: Qwen/Qwen3-32B."}}, "required": ["model"]},
     "annotations": _CLOSED, "_fn": tool_lookup_model},
    {"name": "search_models", "title": "Page of model ids",
     "description": "A page of observed model ids whose id contains query, compared case-insensitively, in catalog order, not a ranking. query omitted or empty matches the whole catalog and still returns at most limit rows. limit follows the historical rule: a missing, empty, zero or other falsy value is 25; any value int() accepts is then clamped into 1..100 (500 becomes 100, a negative becomes 1); a value int() cannot parse is an error and nothing is searched. returned and its compatibility alias count are the rows in this page. matched is how many ids match before the limit. catalog_total and its compatibility alias total_records are every record in the catalog, matching or not. limit is the limit actually applied. count is not the match count, and total_records is not the match count. This is not a verdict and not a proof. Reads published files only.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string", "description": "Substring of the model id. Omit it, or pass an empty string, to match the whole catalog. The page is still capped by limit."},
         "limit": {"type": "integer", "default": 25, "description": "Page size. Omitted, empty, 0 or any other falsy value means 25. A value int() accepts is clamped into 1..100: 500 is fetched as 100 and a negative as 1. There is no schema minimum or maximum, because those would reject the values the server clamps. A value int() cannot parse is an error and nothing is searched."},
     }},
     "annotations": _CLOSED, "_fn": tool_search_models},
    {"name": "get_silence_proof", "title": "One silence proof or its bundle",
     "description": "The published silence proof for one model: silence_days, observed window, epochs, seal id, URL, and how to verify it. model omitted or empty returns the proof index, not a bundle. include_bundle defaults to false; true attaches the crovia.seal.v1 bundle for that one model and does nothing on the index. This is not the live totals and not the weekly report. Reads published files only.",
     "inputSchema": {"type": "object", "properties": {
         "model": {"type": "string", "description": "Hugging Face model id. Omit it, or pass an empty string, to receive the proof index instead of one proof."},
         "include_bundle": {"type": "boolean", "default": False, "description": "Default false. True includes the seal bundle for the one model. Ignored when model is omitted or empty."},
     }},
     "annotations": _CLOSED, "_fn": tool_get_silence_proof},
    {"name": "verify_seal", "title": "Verify a seal or proof",
     "description": "Check a crovia.seal.v1 object or a wrapped TACET silence proof: signature, canonical bytes, bindings, and per-epoch non-inclusion paths. Pass seal as a JSON object or a JSON string, or url as an https://croviatrust.com/ address. With neither, the call is an error. Supplying url fetches that URL over the network. check_anchors defaults to false; true also checks the drand round bytes and the Bitcoin anchors over the network. A seal object with check_anchors false or omitted is checked from that object alone. This tool can reach the network, so it is not a closed-world call.",
     "inputSchema": {"type": "object", "properties": {
         "seal": {"type": ["object", "string"], "description": "The seal or wrapped proof, as a JSON object or a JSON string. Omit it when url is set."},
         "url": {"type": "string", "description": "https://croviatrust.com/ URL of a JSON seal. Any other host is rejected. Fetching it uses the network."},
         "check_anchors": {"type": "boolean", "default": False, "description": "Default false. True checks the drand round and the Bitcoin anchors over the network. False does not."},
     }},
     "annotations": _OPEN, "_fn": tool_verify_seal},
    {"name": "silence_report", "title": "Weekly Silence Report",
     "description": "One published weekly Silence Report, or the latest report index. week is an ISO week YYYY-Www, for example 2026-W38. Omit week, or pass an empty string, to receive the latest index rather than one week's facts. A week that is not YYYY-Www is an error. A week with no published file is an error and names the index. This is not the live status and not one model's proof. Reads published files only.",
     "inputSchema": {"type": "object", "properties": {"week": {"type": "string", "description": "ISO week YYYY-Www, for example 2026-W38. Omit it, or pass an empty string, for the latest report index."}}},
     "annotations": _CLOSED, "_fn": tool_silence_report},
    {"name": "explain", "title": "Definitions",
     "description": "The definition of one Crovia term. Allowed terms: tacet, silence, lacuna, seal, epoch, pnx, predicate, canon. Omit term, or pass an empty or blank string, to receive every definition. Any other value is an error listing those allowed terms, and it does not return the definitions. Use crovia_vs_causari, not explain, to tell the two products apart.",
     "inputSchema": {"type": "object", "properties": {"term": {"type": "string", "description": "One of tacet, silence, lacuna, seal, epoch, pnx, predicate, canon. Omit it, or pass an empty string, for every definition. An unknown term is an error."}}},
     "annotations": _CLOSED, "_fn": tool_explain},
    {"name": "crovia_vs_causari", "title": "Crovia vs Causari",
     "description": "Which product is which. Crovia observes training-data disclosure. Causari is the code-provenance tool. No parameters. Use this, not explain and not crovia_status, when the question is the difference between the two. Reads no catalog.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
     "annotations": _CLOSED, "_fn": tool_crovia_vs_causari},
]
TOOL_BY_NAME = {t["name"]: t for t in TOOLS}

RESOURCES = [
    {"uri": "crovia://llms.txt", "name": "llms.txt", "title": "Crovia for language models", "mimeType": "text/plain", "description": "Short orientation: what Crovia is, what it publishes, where the files are.", "_path": WEB / "llms.txt"},
    {"uri": "crovia://llms-full.txt", "name": "llms-full.txt", "title": "Crovia, full context", "mimeType": "text/plain", "description": "Complete context for language models.", "_path": WEB / "llms-full.txt"},
    {"uri": "crovia://canon.json", "name": "canon.json", "title": "Canon (machine-readable)", "mimeType": "application/json", "description": "Names, URLs, data files, retired paths, forbidden claims.", "_path": Path("/var/www/registry/canon/canon.json")},
    {"uri": "crovia://tacet/latest.json", "name": "tacet/latest.json", "title": "TACET latest", "mimeType": "application/json", "description": "Latest epoch sheet summary and totals.", "_path": DATA / "tacet/latest.json"},
    {"uri": "crovia://report.json", "name": "report.json", "title": "Silence Report facts", "mimeType": "application/json", "description": "Current and last closed week.", "_path": WEB / "report/report.json"},
]
RESOURCE_BY_URI = {r["uri"]: r for r in RESOURCES}


# ---------------------------------------------------------------------------- JSON-RPC

def rpc(req: dict) -> dict | None:
    mid, method, params = req.get("id"), req.get("method"), req.get("params") or {}
    if method == "initialize":
        want = params.get("protocolVersion")
        proto = want if want in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": proto, "capabilities": {"tools": {"listChanged": False}, "resources": {"subscribe": False, "listChanged": False}},
                                                          "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS}}
    if method and method.startswith("notifications/"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        shown = ("name", "title", "description", "inputSchema", "annotations")
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [{k: t[k] for k in shown} for t in TOOLS]}}
    if method == "tools/call":
        tool = TOOL_BY_NAME.get(params.get("name"))
        if not tool:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool: {params.get('name')}"}}
        try:
            result = tool["_fn"](params.get("arguments") or {})
            is_err = isinstance(result, dict) and "error" in result and len(result) <= 3
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}],
                                                              "structuredContent": result if isinstance(result, dict) else None, "isError": bool(is_err)}}
        except Exception as e:  # noqa: BLE001
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": f"error: {type(e).__name__}: {e}"}], "isError": True}}
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"resources": [{k: r[k] for k in ("uri", "name", "title", "mimeType", "description")} for r in RESOURCES]}}
    if method == "resources/read":
        r = RESOURCE_BY_URI.get(params.get("uri"))
        if not r:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32002, "message": f"unknown resource: {params.get('uri')}"}}
        try:
            text = r["_path"].read_text(encoding="utf-8")
        except OSError as e:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": f"cannot read resource: {e}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": {"contents": [{"uri": r["uri"], "mimeType": r["mimeType"], "text": text}]}}
    if method in ("prompts/list",):
        return {"jsonrpc": "2.0", "id": mid, "result": {"prompts": []}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version")

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204); self._cors(); self.end_headers()

    def do_DELETE(self) -> None:
        self.send_response(204); self._cors(); self.end_headers()

    def do_GET(self) -> None:
        if "text/event-stream" in (self.headers.get("Accept") or "") and "application/json" not in (self.headers.get("Accept") or ""):
            self._send(405, b'{"error":"server-initiated streams are not offered; POST JSON-RPC to this endpoint"}')
            return
        body = json.dumps({"service": "crovia-mcp", "version": SERVER_INFO["version"], "transport": "streamable-http", "endpoint": f"{SITE}/mcp",
                           "protocolVersions": list(SUPPORTED_PROTOCOLS), "tools": [t["name"] for t in TOOLS], "resources": [r["uri"] for r in RESOURCES],
                           "docs": f"{SITE}/llms.txt", "registry": "io.github.croviatrust/crovia"}).encode()
        self._send(200, body)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            req = json.loads(raw or b"{}")
        except (ValueError, OSError):
            self._send(400, b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}')
            return
        batch = isinstance(req, list)
        responses = [r for r in (rpc(x) for x in (req if batch else [req])) if r is not None]
        if not responses:
            self.send_response(202); self._cors(); self.end_headers()
            return
        self._send(200, json.dumps(responses if batch else responses[0], ensure_ascii=False).encode())

    def log_message(self, *a: Any) -> None:
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8787"))
    print(f"crovia-mcp {SERVER_INFO['version']} on 127.0.0.1:{port}", file=sys.stderr)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
