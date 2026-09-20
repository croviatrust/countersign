"""PNX on disk: witness state, key files, and delivery as an unmodified crovia.seal.v1.

``egress.py`` holds the protocol (fingerprinting, run sheets, proofs,
verification). This module holds what a tool needs around it: persisting the
witness map between "the run ended" and "somebody asked for a proof", reading
and writing witness keys, and wrapping a PNX proof in a Seal so that any
``crovia.seal.v1`` verifier can check the outer object.

The state file never leaves the perimeter: it contains the salt and the
fingerprint set, from which nothing about the traffic can be recovered, but
from which anyone could compute a proof. The run sheet and the proof are the
public objects.
"""
from __future__ import annotations

import base64
import json
import os
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import canonicalize
from .egress import PRESENT, PROFILE, EgressWitness, PnxVerifyResult, verify_pnx
from .hashing import prefixed, sha256
from .keys import SigningKey
from .smt import SparseMerkleMap

STATE_VERSION = "crovia.pnx.state.v1"
KEY_VERSION = "crovia.pnx.key.v1"
GENERATOR_ID = "crovia/tacet-pnx"


# --------------------------------------------------------------------------- keys

def save_key(key: SigningKey, path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    seed = key._private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    obj = {"key_version": KEY_VERSION, "id": key.id, "alg": "ed25519",
           "seed_hex": seed.hex(), "pubkey_hex": key.public_hex}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=1)
        fh.write("\n")


def load_key(path: Path) -> SigningKey:
    obj = json.loads(Path(path).read_text())
    if obj.get("key_version") != KEY_VERSION or obj.get("alg") != "ed25519":
        raise ValueError(f"{path}: not a {KEY_VERSION} file")
    return SigningKey.from_seed(obj["id"], bytes.fromhex(obj["seed_hex"]))


def key_from_env(id: str, var: str) -> SigningKey:
    """Witness key from an environment variable holding the 32-byte seed as hex (CI secrets)."""
    raw = os.environ.get(var, "")
    if not raw:
        raise ValueError(f"environment variable {var} is empty")
    return SigningKey.from_seed(id, bytes.fromhex(raw.strip()))


# --------------------------------------------------------------------------- state

def witness_to_state(w: EgressWitness) -> dict[str, Any]:
    return {
        "state_version": STATE_VERSION, "profile": PROFILE,
        "run_id": w.run_id, "salt_hex": w.salt.hex(), "k_gram": w.k, "window": w.w,
        "bodies": w.bodies, "bytes": w.bytes_seen, "first_at": w.first_at, "last_at": w.last_at,
        "normalization": sorted(w.normalization),
        "fingerprints": sorted(fp.hex() for fp in w._map.keys()),  # noqa: SIM118 - SparseMerkleMap is not a dict
    }


def witness_from_state(state: dict[str, Any]) -> EgressWitness:
    if state.get("state_version") != STATE_VERSION:
        raise ValueError(f"unknown state version {state.get('state_version')!r}")
    m = SparseMerkleMap({bytes.fromhex(h): PRESENT for h in state.get("fingerprints", [])})
    return EgressWitness(run_id=state["run_id"], salt=bytes.fromhex(state["salt_hex"]),
                         k=int(state["k_gram"]), w=int(state["window"]), _map=m,
                         bodies=int(state["bodies"]), bytes_seen=int(state["bytes"]),
                         first_at=state.get("first_at"), last_at=state.get("last_at"),
                         normalization=tuple(state.get("normalization", [])))


def save_state(w: EgressWitness, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(witness_to_state(w), fh, separators=(",", ":"))
        fh.write("\n")


def load_state(path: Path) -> EgressWitness:
    return witness_from_state(json.loads(Path(path).read_text()))


# --------------------------------------------------------------------------- body sources

def rfc3339(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iter_bodies(paths: Iterable[Path], *, raw: bool = False) -> Iterable[tuple[bytes, str, str]]:
    """Yield ``(body, at, source)`` for every outbound body under ``paths``.

    A regular file is one body, timestamped with its mtime. A ``.jsonl`` or
    ``.ndjson`` file is a capture log: one JSON object per line with ``body``
    (string) or ``body_b64`` and an optional RFC 3339 ``at`` - the format
    LLM gateways and proxies can emit without knowing anything else about
    PNX. ``raw=True`` treats every file as a body regardless of extension.
    Directories are walked; hidden entries are skipped.
    """
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files = sorted(q for q in p.rglob("*") if q.is_file() and not any(part.startswith(".") for part in q.relative_to(p).parts))
        else:
            files = [p]
        for f in files:
            if not raw and f.suffix in (".jsonl", ".ndjson"):
                with f.open("rb") as fh:
                    for n, line in enumerate(fh, 1):
                        line = line.strip()
                        if not line:
                            continue
                        rec = json.loads(line)
                        if "body_b64" in rec:
                            body = base64.b64decode(rec["body_b64"])
                        elif isinstance(rec.get("body"), str):
                            body = rec["body"].encode("utf-8")
                        else:
                            body = canonicalize(rec)
                        yield body, rec.get("at") or rfc3339(f.stat().st_mtime), f"{f}:{n}"
            else:
                yield f.read_bytes(), rfc3339(f.stat().st_mtime), str(f)


# --------------------------------------------------------------------------- assets

def collect_assets(files: list[tuple[str, Path]], dirs: list[Path], env_vars: list[str]) -> list[tuple[str, bytes]]:
    """Labelled asset bytes from explicit files, whole directories (label = relative path) and env vars (label = env:NAME)."""
    out: list[tuple[str, bytes]] = []
    for label, path in files:
        out.append((label, Path(path).read_bytes()))
    for d in dirs:
        d = Path(d)
        for f in sorted(q for q in d.rglob("*") if q.is_file()):
            out.append((str(f.relative_to(d)).replace(os.sep, "/"), f.read_bytes()))
    for var in env_vars:
        val = os.environ.get(var)
        if val is None:
            raise ValueError(f"environment variable {var} is not set")
        out.append((f"env:{var}", val.encode("utf-8")))
    labels = [label for label, _ in out]
    dup = {x for x in labels if labels.count(x) > 1}
    if dup:
        raise ValueError(f"duplicate asset labels: {sorted(dup)}")
    return out


# --------------------------------------------------------------------------- seal wrapping

def _seal_module():
    try:
        from crovia_seal import constants
        from crovia_seal import seal as seal_mod
        return seal_mod, constants
    except ImportError as e:  # pragma: no cover
        raise ImportError("sealing needs the Crovia Seal reference implementation: pip install crovia-seal") from e


def _b32(nbytes: int = 16) -> str:
    return base64.b32encode(os.urandom(nbytes)).decode("ascii").rstrip("=")


def pnx_query(proof: dict[str, Any]) -> dict[str, Any]:
    """The question a PNX proof answers, as the Seal's input: which run, which assets (by hash, never by content)."""
    return {"profile": PROFILE, "run_id": proof["sheet"]["run_id"],
            "assets": [{"label": a["label"], "asset_sha256": a["asset_sha256"]} for a in proof["assets"]]}


def seal_pnx(proof: dict[str, Any], issuer: SigningKey, *, tacet_version: str, anchor: dict[str, Any] | None = None) -> dict[str, Any]:
    """Wrap a PNX proof in an unmodified crovia.seal.v1: {seal, query, proof}."""
    seal_mod, constants = _seal_module()
    query = pnx_query(proof)
    q_bytes, p_bytes = canonicalize(query), canonicalize(proof)
    now = datetime.now(timezone.utc)
    sheet = proof["sheet"]
    unsigned: dict[str, Any] = {
        "seal_version": constants.SEAL_VERSION,
        "seal_id": f"cs_{now.year}_{_b32()}",
        "issuer": {"id": issuer.id, "pubkey": issuer.pubkey_json()},
        "subject": {"input_hash": prefixed(sha256(q_bytes)), "output_hash": prefixed(sha256(p_bytes)),
                    "input_len": len(q_bytes), "output_len": len(p_bytes), "modality": "text"},
        "generator": {"id": GENERATOR_ID, "version": tacet_version, "weights_hash": None,
                      "params": {"profile": PROFILE, "run_id": sheet["run_id"], "verdict": proof["verdict"]}},
        "timestamp": {"emitted_at": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z", "nonce": _b32()},
        "chain": {"prev_seal_hash": None, "sequence": 0},
        "checks": {"pnx": {"verdict": proof["verdict"], "assets": len(proof["assets"]),
                           "bodies": sheet["egress"]["bodies"], "bytes": sheet["egress"]["bytes"],
                           "witness_id": sheet["witness"]["id"], "run_root": sheet["root"]}},
    }
    if anchor is not None:
        unsigned["anchor"] = anchor
    payload = seal_mod.compute_payload(unsigned)
    unsigned["signature"] = {"alg": constants.SIGNATURE_ALG, "canon": constants.CANON_ID, "domain": constants.SIGNATURE_DOMAIN,
                             "payload_hash_alg": constants.PAYLOAD_HASH_ALG, "sig_hex": issuer.sign(payload).hex()}
    seal_mod._validate_structure(unsigned)
    return {"seal": unsigned, "query": query, "proof": proof}


def verify_any(obj: dict[str, Any], assets: dict[str, bytes] | None = None) -> tuple[PnxVerifyResult, dict[str, Any]]:
    """Verify a bare PNX proof or a sealed bundle. Returns (inner result, outer info)."""
    outer: dict[str, Any] = {"sealed": False}
    proof = obj
    if "seal" in obj and "proof" in obj:
        outer["sealed"] = True
        proof = obj["proof"]
        try:
            seal_mod, _ = _seal_module()
        except ImportError:
            outer.update({"seal_ok": None, "seal_errors": ["crovia_seal not installed: outer Seal not checked"]})
        else:
            r = seal_mod.verify_seal(obj["seal"])
            errs = list(r.errors)
            if obj["seal"]["subject"]["input_hash"] != prefixed(sha256(canonicalize(obj.get("query", {})))):
                errs.append("seal.subject.input_hash does not bind the query")
            if obj["seal"]["subject"]["output_hash"] != prefixed(sha256(canonicalize(proof))):
                errs.append("seal.subject.output_hash does not bind the proof")
            if obj.get("query") != pnx_query(proof):
                errs.append("query does not describe this proof")
            outer.update({"seal_ok": r.ok and not errs, "seal_errors": errs, "issuer_id": r.issuer_id, "seal_id": r.seal_id})
    res = verify_pnx(proof, assets)
    if outer.get("seal_ok") is False:
        res.ok = False
        res.errors = outer["seal_errors"] + res.errors
    return res, outer
