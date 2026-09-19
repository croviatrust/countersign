"""PNX — Proof of Non-Exfiltration for agent egress (TACET profile ``crovia.pnx.v1``).

TACET proves that a public surface did *not* contain something during a
witnessed window. PNX turns the same machinery inward: an egress witness sits
where an AI agent's outbound bytes are visible in clear (a local LLM proxy, a
corporate egress proxy, a CI sidecar) and commits a fingerprint of everything
that left. Afterwards the operator can prove, to anyone, that a set of
protected assets — API keys, customer records, source files — never appeared
in that traffic, without revealing the traffic or the assets.

Construction
------------
1. Fingerprinting (winnowing, Schleimer–Wilkerson–Aiken 2003). Every outbound
   body is cut into k-grams of ``K_GRAM`` bytes; each k-gram is hashed with a
   per-run salt; within every window of ``WINDOW`` consecutive hashes the
   minimum is selected (rightmost on ties). The selected hashes are the body's
   fingerprints. Guarantee: any byte string of length ``>= THRESHOLD`` shared by
   an asset and a body yields at least one identical fingerprint on both sides.
2. Commitment. Fingerprints are keys of a depth-256 sparse Merkle map (SPEC §5)
   with a constant leaf value. The run sheet — root, salt, parameters, byte and
   body counts, first/last timestamp — is signed by the witness key.
3. Proof. For each asset the prover recomputes the asset's own fingerprints
   and attaches a compact non-inclusion path for each against the run root. If
   a fingerprint *is* present it attaches the inclusion path instead: the same
   object is then evidence of exposure, not of its absence.
4. Anchoring. The run root is meant to be committed as a leaf of a TACET epoch
   sheet (``epoch_leaf_key``), which gives it the epoch's drand opening and
   Bitcoin closing. That step is the operator's, not this module's.

What a verified PNX proof does and does not say
-----------------------------------------------
It says: no substring of length ``>= THRESHOLD`` of any listed asset occurred in
the bytes the witness saw, and (for shorter assets) whether the exact k-grams
occurred. It does not say anything about traffic that bypassed the witness,
about paraphrase or re-encoding the witness did not normalise, or about assets
shorter than ``K_GRAM`` bytes, which are reported as ``undetectable`` and never
counted as clean.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .canonical import canonicalize
from .hashing import prefixed, sha256, unprefixed
from .keys import SigningKey, verify_signature
from .smt import CompactPath, SparseMerkleMap, verify_inclusion, verify_non_inclusion

PROFILE = "crovia.pnx.v1"
K_GRAM = 32
WINDOW = 16
THRESHOLD = K_GRAM + WINDOW - 1  # 47 bytes: shared substrings at least this long are always detected

DOMAIN_FINGERPRINT = b"CROVIA-PNX-FP-v1\n"
DOMAIN_SHEET = b"CROVIA-PNX-SHEET-v1\n"
DOMAIN_LEAF_VALUE = b"CROVIA-PNX-PRESENT-v1\n"
PRESENT = sha256(DOMAIN_LEAF_VALUE)

VERDICT_ABSENT = "absent"            # every fingerprint proven not in the map (guaranteed for len >= THRESHOLD)
VERDICT_ABSENT_PARTIAL = "absent-partial"  # K_GRAM <= len < THRESHOLD: exact k-grams absent, guarantee does not apply
VERDICT_PRESENT = "present"          # at least one fingerprint proven in the map
VERDICT_UNDETECTABLE = "undetectable"  # len < K_GRAM: no k-gram can be formed


# --------------------------------------------------------------------------- fingerprints

def kgram_hashes(data: bytes, salt: bytes, k: int = K_GRAM) -> List[bytes]:
    """Salted hash of every k-gram of ``data`` in order (empty if ``len(data) < k``)."""
    if len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    prefix = DOMAIN_FINGERPRINT + salt
    return [hashlib.sha256(prefix + data[i:i + k]).digest() for i in range(len(data) - k + 1)]


def winnow(hashes: Sequence[bytes], w: int = WINDOW) -> Set[bytes]:
    """Select the minimum of every window of ``w`` consecutive hashes (rightmost on ties)."""
    n = len(hashes)
    if n == 0:
        return set()
    if n < w:
        return {min(hashes)}
    out: Set[bytes] = set()
    for i in range(n - w + 1):
        window = hashes[i:i + w]
        m = min(window)
        # rightmost minimum, as in the paper, so runs of equal hashes select consistently
        out.add(window[len(window) - 1 - window[::-1].index(m)])
    return out


def fingerprints(data: bytes, salt: bytes, k: int = K_GRAM, w: int = WINDOW) -> Set[bytes]:
    """Winnowed fingerprints of ``data``; the empty set if it is shorter than ``k``."""
    return winnow(kgram_hashes(data, salt, k), w)


def asset_fingerprints(asset: bytes, salt: bytes, k: int = K_GRAM, w: int = WINDOW) -> Tuple[str, List[bytes]]:
    """Fingerprints to check for an asset and the detection class they carry.

    Assets at or above ``THRESHOLD`` use winnowed fingerprints (guaranteed
    detection). Shorter assets that still hold at least one k-gram use every
    k-gram hash (best effort). Anything shorter is undetectable.
    """
    if len(asset) < k:
        return "undetectable", []
    hashes = kgram_hashes(asset, salt, k)
    if len(asset) >= k + w - 1:
        return "guaranteed", sorted(winnow(hashes, w))
    return "partial", sorted(set(hashes))


# --------------------------------------------------------------------------- witness

@dataclass
class EgressWitness:
    """Accumulates fingerprints of outbound bodies for one run."""

    run_id: str
    salt: bytes = field(default_factory=lambda: os.urandom(16))
    k: int = K_GRAM
    w: int = WINDOW
    _map: SparseMerkleMap = field(default_factory=SparseMerkleMap, repr=False)
    bodies: int = 0
    bytes_seen: int = 0
    first_at: Optional[str] = None
    last_at: Optional[str] = None

    def ingest(self, body: bytes, at: str) -> int:
        """Record one outbound body observed at RFC 3339 time ``at``; returns new fingerprints added."""
        added = 0
        for fp in fingerprints(body, self.salt, self.k, self.w):
            if fp not in self._map:
                self._map.set(fp, PRESENT)
                added += 1
        self.bodies += 1
        self.bytes_seen += len(body)
        self.first_at = self.first_at or at
        self.last_at = at
        return added

    @property
    def root(self) -> bytes:
        return self._map.root()

    def sheet(self, witness: SigningKey, closed_at: str) -> Dict[str, Any]:
        """Signed run sheet: the only object that has to leave the perimeter."""
        s: Dict[str, Any] = {
            "profile": PROFILE,
            "run_id": self.run_id,
            "salt_hex": self.salt.hex(),
            "params": {"k_gram": self.k, "window": self.w, "threshold": self.k + self.w - 1, "hash": "sha256"},
            "egress": {"bodies": self.bodies, "bytes": self.bytes_seen, "first_at": self.first_at, "last_at": self.last_at},
            "fingerprints": len(self._map),
            "root": prefixed(self.root),
            "closed_at": closed_at,
            "witness": {"id": witness.id, "pubkey": witness.pubkey_json()},
        }
        sig = witness.sign(DOMAIN_SHEET + canonicalize(s))
        s["signature"] = {"alg": "ed25519", "domain": DOMAIN_SHEET.strip().decode(), "sig_hex": sig.hex()}
        return s

    def prove(self, sheet: Dict[str, Any], assets: Iterable[Tuple[str, bytes]]) -> Dict[str, Any]:
        """Proof of Non-Exfiltration for labelled assets against this run's committed root."""
        if unprefixed(sheet["root"]) != self.root:
            raise ValueError("sheet root does not match the witness map")
        out_assets = []
        for label, data in assets:
            klass, fps = asset_fingerprints(data, self.salt, self.k, self.w)
            entry: Dict[str, Any] = {"label": label, "asset_len": len(data), "detection": klass,
                                     "asset_sha256": prefixed(sha256(data)), "fingerprints": []}
            present = 0
            for fp in fps:
                path = self._map.prove(fp)
                hit = fp in self._map
                present += hit
                entry["fingerprints"].append({"key": fp.hex(), "present": hit, "path": path.to_json()})
            if klass == "undetectable":
                entry["verdict"] = VERDICT_UNDETECTABLE
            elif present:
                entry["verdict"] = VERDICT_PRESENT
            else:
                entry["verdict"] = VERDICT_ABSENT if klass == "guaranteed" else VERDICT_ABSENT_PARTIAL
            out_assets.append(entry)
        verdict = (VERDICT_PRESENT if any(a["verdict"] == VERDICT_PRESENT for a in out_assets)
                   else VERDICT_ABSENT if out_assets and all(a["verdict"] == VERDICT_ABSENT for a in out_assets)
                   else "mixed")
        return {"profile": PROFILE, "proof_version": "crovia.pnx.proof.v1", "sheet": sheet,
                "assets": out_assets, "verdict": verdict}


def epoch_leaf_key(run_id: str) -> bytes:
    """Key under which a run root is committed into a TACET epoch map (namespace ``pnx/<run_id>``)."""
    return sha256(("pnx/" + run_id).encode("utf-8"))


# --------------------------------------------------------------------------- verification

@dataclass
class PnxVerifyResult:
    ok: bool
    verdict: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    assets: Dict[str, str] = field(default_factory=dict)


def _unsigned(sheet: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in sheet.items() if k != "signature"}


def verify_sheet(sheet: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if sheet.get("profile") != PROFILE:
        errors.append(f"unknown profile {sheet.get('profile')!r}")
    try:
        unprefixed(sheet["root"])
        bytes.fromhex(sheet["salt_hex"])
    except (KeyError, ValueError) as e:
        errors.append(f"malformed sheet: {e}")
        return errors
    p = sheet.get("params") or {}
    if p.get("hash") != "sha256" or p.get("threshold") != p.get("k_gram", 0) + p.get("window", 0) - 1:
        errors.append("inconsistent params")
    sig = sheet.get("signature") or {}
    try:
        ok = verify_signature(sheet["witness"]["pubkey"]["key_hex"], DOMAIN_SHEET + canonicalize(_unsigned(sheet)),
                              bytes.fromhex(sig.get("sig_hex", "")))
    except (KeyError, ValueError):
        ok = False
    if not ok:
        errors.append("witness signature invalid")
    return errors


def verify_pnx(proof: Dict[str, Any], assets: Optional[Dict[str, bytes]] = None) -> PnxVerifyResult:
    """Verify a PNX proof offline.

    With ``assets`` (label -> bytes) the verifier recomputes every fingerprint
    itself, so the prover cannot substitute keys. Without them it verifies the
    paths against the keys the prover listed, which proves non-inclusion of
    *those keys* only; the result carries a warning saying so.
    """
    res = PnxVerifyResult(ok=True, verdict=proof.get("verdict", "?"))
    sheet = proof.get("sheet") or {}
    res.errors += verify_sheet(sheet)
    if res.errors:
        res.ok = False
        return res
    root = unprefixed(sheet["root"])
    salt = bytes.fromhex(sheet["salt_hex"])
    k, w = sheet["params"]["k_gram"], sheet["params"]["window"]
    if assets is None:
        res.warnings.append("assets not supplied: fingerprints taken from the proof, not recomputed")

    computed_verdicts: Dict[str, str] = {}
    for a in proof.get("assets", []):
        label = a.get("label", "?")
        listed = a.get("fingerprints", [])
        if assets is not None:
            if label not in assets:
                res.errors.append(f"{label}: asset bytes not supplied")
                continue
            data = assets[label]
            if prefixed(sha256(data)) != a.get("asset_sha256"):
                res.errors.append(f"{label}: supplied asset does not match asset_sha256 in the proof")
                continue
            klass, expected = asset_fingerprints(data, salt, k, w)
            if klass != a.get("detection"):
                res.errors.append(f"{label}: detection class {a.get('detection')!r} does not match recomputed {klass!r}")
                continue
            if sorted(bytes.fromhex(f["key"]) for f in listed) != expected:
                res.errors.append(f"{label}: fingerprint set does not match the asset")
                continue
        else:
            klass = a.get("detection", "?")
        present = 0
        for f in listed:
            key = bytes.fromhex(f["key"])
            path = CompactPath.from_json(f["path"])
            if f.get("present"):
                if not verify_inclusion(root, key, PRESENT, path):
                    res.errors.append(f"{label}: inclusion path invalid for {f['key'][:16]}")
                present += 1
            elif not verify_non_inclusion(root, key, path):
                res.errors.append(f"{label}: non-inclusion path invalid for {f['key'][:16]}")
        if klass == "undetectable":
            v = VERDICT_UNDETECTABLE
        elif present:
            v = VERDICT_PRESENT
        else:
            v = VERDICT_ABSENT if klass == "guaranteed" else VERDICT_ABSENT_PARTIAL
        if v != a.get("verdict"):
            res.errors.append(f"{label}: stated verdict {a.get('verdict')!r}, computed {v!r}")
        computed_verdicts[label] = v
        if v == VERDICT_UNDETECTABLE:
            res.warnings.append(f"{label}: shorter than {k} bytes, cannot be fingerprinted; not counted as clean")
        if v == VERDICT_ABSENT_PARTIAL:
            res.warnings.append(f"{label}: shorter than the {k + w - 1}-byte guarantee; exact k-grams absent only")

    res.assets = computed_verdicts
    overall = (VERDICT_PRESENT if any(v == VERDICT_PRESENT for v in computed_verdicts.values())
               else VERDICT_ABSENT if computed_verdicts and all(v == VERDICT_ABSENT for v in computed_verdicts.values())
               else "mixed")
    if overall != proof.get("verdict"):
        res.errors.append(f"overall verdict {proof.get('verdict')!r} does not match computed {overall!r}")
    res.verdict = overall
    res.ok = not res.errors
    return res
