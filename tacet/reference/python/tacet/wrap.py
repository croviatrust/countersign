"""Deliver a silence proof as an unmodified crovia.seal.v1 object (SPEC §10).

Requires the Crovia Seal reference implementation (`crovia_seal`, from
github.com/croviatrust/crovia-seal/reference/python). TACET adds nothing to the
Seal format: the query is the Seal's input, the proof is its output.
"""
from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .canonical import canonicalize
from .hashing import prefixed, sha256
from .keys import SigningKey
from .silence import SilenceVerifyResult, verify_silence_proof

GENERATOR_ID = "crovia/tacet"
TACET_VERSION = "0.1.1"


def _seal_module():
    try:
        import crovia_seal  # noqa: F401
        from crovia_seal import seal as seal_mod
        from crovia_seal import constants
        return seal_mod, constants
    except ImportError as e:  # pragma: no cover
        raise ImportError("crovia_seal reference implementation is required: "
                          "pip install -e <crovia-seal>/reference/python") from e


def _b32(nbytes: int = 16, *, rng: Optional[bytes] = None) -> str:
    raw = rng if rng is not None else os.urandom(nbytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def wrap_in_seal(
    *,
    issuer: SigningKey,
    query: Dict[str, Any],
    proof: Dict[str, Any],
    anchor: Optional[Dict[str, Any]] = None,
    prev_seal_hash: Optional[str] = None,
    sequence: int = 0,
    emitted_at: Optional[str] = None,
    nonce: Optional[str] = None,
    seal_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build and sign the outer Seal. Deterministic when emitted_at, nonce and seal_id are given."""
    seal_mod, constants = _seal_module()
    q_bytes = canonicalize(query)
    p_bytes = canonicalize(proof)
    now = datetime.now(timezone.utc)
    unsigned: Dict[str, Any] = {
        "seal_version": constants.SEAL_VERSION,
        "seal_id": seal_id or f"cs_{now.year}_{_b32()}",
        "issuer": {"id": issuer.id, "pubkey": issuer.pubkey_json()},
        "subject": {
            "input_hash": prefixed(sha256(q_bytes)),
            "output_hash": prefixed(sha256(p_bytes)),
            "input_len": len(q_bytes),
            "output_len": len(p_bytes),
            "modality": "text",
        },
        "generator": {
            "id": GENERATOR_ID,
            "version": TACET_VERSION,
            "weights_hash": None,
            "params": {
                "map_id": proof["map_id"],
                "strength": str(proof["strength"]),
                "epochs": f"{proof['from_epoch']}-{proof['to_epoch']}",
            },
        },
        "timestamp": {
            "emitted_at": emitted_at or now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
            "nonce": nonce or _b32(),
        },
        "chain": {"prev_seal_hash": prev_seal_hash, "sequence": sequence},
        "checks": {"tacet": {
            "strength": proof["strength"],
            "silence_days": proof["silence"]["silence_days"],
            "observed_to": proof["silence"]["observed_to"],
        }},
    }
    if anchor is not None:
        unsigned["anchor"] = anchor
    payload = seal_mod.compute_payload(unsigned)
    unsigned["signature"] = {
        "alg": constants.SIGNATURE_ALG,
        "canon": constants.CANON_ID,
        "domain": constants.SIGNATURE_DOMAIN,
        "payload_hash_alg": constants.PAYLOAD_HASH_ALG,
        "sig_hex": issuer.sign(payload).hex(),
    }
    seal_mod._validate_structure(unsigned)
    return {"seal": unsigned, "query": query, "proof": proof}


def verify_wrapped(bundle: Dict[str, Any], **silence_kwargs: Any) -> Dict[str, Any]:
    """Verify outer Seal, binding of query/proof bytes, then the silence proof itself."""
    seal_mod, _ = _seal_module()
    seal, query, proof = bundle["seal"], bundle["query"], bundle["proof"]
    outer = seal_mod.verify_seal(seal)
    errors = list(outer.errors)
    if seal["subject"]["input_hash"] != prefixed(sha256(canonicalize(query))):
        errors.append("seal.subject.input_hash does not bind the query")
    if seal["subject"]["output_hash"] != prefixed(sha256(canonicalize(proof))):
        errors.append("seal.subject.output_hash does not bind the proof")
    if query.get("target_id") != proof.get("target_id") or query.get("map_id") != proof.get("map_id"):
        errors.append("query and proof disagree on target or map")
    inner: SilenceVerifyResult = verify_silence_proof(proof, **silence_kwargs)
    errors.extend(inner.errors)
    if inner.ok and inner.strength_verified < int(query.get("min_strength", 1)):
        errors.append("proof strength below the query's min_strength")
    return {
        "ok": outer.ok and not errors,
        "seal_ok": outer.ok,
        "issuer_id": outer.issuer_id,
        "seal_id": outer.seal_id,
        "strength_verified": inner.strength_verified,
        "silence": inner.silence,
        "errors": errors,
        "warnings": inner.warnings,
    }
