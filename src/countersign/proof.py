"""Proof bundles: self-contained, offline-verifiable witnessing proofs.

A proof bundle is a single JSON document that a third party (auditor,
counterparty, regulator) can verify with **no network access and no
trust in the operator**, given only the witness public key::

    {
      "format": "countersign/proof.v1",
      "entry": { "digest": "…", "index": 42, "witnessed_at": "…", "note": "…" },
      "inclusion_path": ["<hex>", …],
      "sth": { "format": "countersign/sth.v1", "tree_size": …, "root_hash": "…",
               "timestamp": "…", "key_id": "…", "signature": "…" },
      "witness": { "public_key": "<hex>", "key_id": "…" }
    }

Verification establishes three facts:

1. the evidence digest is included in the witnessed tree (Merkle inclusion),
2. the tree head was signed by the named witness key (Ed25519),
3. therefore the evidence existed no later than ``sth.timestamp`` and any
   later alteration of it would change the digest and break the proof.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import keys as keys_mod
from . import merkle
from .canonical import canonical_bytes, is_hex_digest
from .log import STH_FORMAT, WitnessLog, sth_signing_bytes

PROOF_FORMAT = "countersign/proof.v1"


class ProofError(RuntimeError):
    pass


def build_proof(log: WitnessLog, digest: str, index: Optional[int] = None) -> Dict[str, Any]:
    """Build a proof bundle for *digest* against the latest STH of *log*.

    If the digest was witnessed multiple times, the most recent entry is
    used unless *index* selects a specific one.
    """
    entries = log.entries()
    entry: Optional[Dict[str, Any]] = None
    if index is not None:
        if not 0 <= index < len(entries):
            raise ProofError(f"index {index} out of range")
        if entries[index]["digest"] != digest:
            raise ProofError(f"entry {index} does not hold digest {digest}")
        entry = entries[index]
    else:
        for e in entries:
            if e["digest"] == digest:
                entry = e
    if entry is None:
        raise ProofError(f"digest not found in log: {digest}")

    hashes = [merkle.leaf_hash(canonical_bytes(e)) for e in entries]
    sth = log.latest_sth()
    if sth["tree_size"] != len(entries):
        raise ProofError("latest STH is stale; re-seal the log")

    path = merkle.inclusion_path(entry["index"], hashes)
    key = log.key()
    return {
        "format": PROOF_FORMAT,
        "entry": entry,
        "inclusion_path": [p.hex() for p in path],
        "sth": sth,
        "witness": {"public_key": key.public_hex, "key_id": key.key_id},
    }


def verify_proof(
    bundle: Dict[str, Any], expected_public_key: Optional[str] = None
) -> Dict[str, Any]:
    """Verify a proof bundle offline. Returns a report dict.

    If *expected_public_key* is given, the bundle's embedded key must match
    it — this is how a verifier pins the witness identity out-of-band.
    """
    problems: List[str] = []

    if bundle.get("format") != PROOF_FORMAT:
        problems.append(f"unknown proof format: {bundle.get('format')!r}")

    entry = bundle.get("entry") or {}
    sth = bundle.get("sth") or {}
    witness = bundle.get("witness") or {}
    public_key = witness.get("public_key", "")

    if expected_public_key and public_key != expected_public_key:
        problems.append("witness public key does not match the pinned key")
    if sth.get("format") != STH_FORMAT:
        problems.append(f"unknown STH format: {sth.get('format')!r}")
    if not is_hex_digest(entry.get("digest", "")):
        problems.append("entry digest is malformed")

    # 1. signature over the tree head
    sig_ok = False
    if public_key:
        key = keys_mod.public_only(public_key)
        if sth.get("key_id") != key.key_id:
            problems.append("sth.key_id does not match the witness public key")
        try:
            sig_ok = key.verify(sth_signing_bytes(sth), sth.get("signature", ""))
        except ValueError:
            sig_ok = False
        if not sig_ok:
            problems.append("tree head signature invalid")
    else:
        problems.append("no witness public key in bundle")

    # 2. Merkle inclusion of the entry under the signed root
    inclusion_ok = False
    try:
        leaf = merkle.leaf_hash(canonical_bytes(entry))
        path = [bytes.fromhex(p) for p in bundle.get("inclusion_path", [])]
        inclusion_ok = merkle.verify_inclusion(
            leaf,
            int(entry.get("index", -1)),
            int(sth.get("tree_size", 0)),
            path,
            bytes.fromhex(sth.get("root_hash", "")),
        )
    except (ValueError, TypeError) as exc:
        problems.append(f"inclusion proof malformed: {exc}")
    if not inclusion_ok and "inclusion proof malformed" not in " ".join(problems):
        problems.append("inclusion proof does not verify against the signed root")

    return {
        "ok": not problems,
        "digest": entry.get("digest"),
        "witnessed_at": entry.get("witnessed_at"),
        "tree_size": sth.get("tree_size"),
        "sth_timestamp": sth.get("timestamp"),
        "witness_key_id": sth.get("key_id"),
        "problems": problems,
    }


def load_bundle(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProofError(f"cannot read proof bundle {path}: {exc}") from exc
