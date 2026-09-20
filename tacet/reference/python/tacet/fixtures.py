"""Deterministic scenario used by the test-suite and the conformance vectors.

Twelve hourly epochs of a small map. The target under test never receives a
disclosure. The observer records negative snapshots in epochs 0-6 and 10-11,
is down in epochs 7-9, and epoch 11 is not yet Bitcoin-anchored. Under the
monotonicity rule (SPEC §8.4) the proven silence is therefore
(epochs 0..6) + (epoch 10) = 8 hours, not the 12 hours a naive
first_seen → now computation would report.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from . import merkle
from .epoch import build_sheet, close_sheet, witness_sign
from .hashing import object_hash, target_key
from .keys import SigningKey
from .smt import CompactPath, SparseMerkleMap
from .snapshot import build_snapshot, snapshot_hash

MAP_ID = "urn:crovia:tacet:map:disclosure"
TARGET = "meta-llama/Llama-3.1-8B"
OTHER_TARGETS = [f"vendor{i}/model-{i}" for i in range(40)]
DISCLOSED_TARGET = "vendor30/model-30"
SURFACE = "https://huggingface.co/meta-llama/Llama-3.1-8B"
PREDICATE = ("crovia.pred.art53-summary", "1.0.0", hashlib.sha256(b"predicate source v1.0.0").digest())
GENESIS = datetime(2026, 9, 19, 0, 0, 0, tzinfo=timezone.utc)
N_EPOCHS = 12
OBSERVED_EPOCHS = [0, 1, 2, 3, 4, 5, 6, 10, 11]
UNANCHORED_EPOCHS = [11]
DISCLOSURE_EPOCH = 5


def _seed(label: str) -> bytes:
    return hashlib.sha256(b"tacet-fixture:" + label.encode()).digest()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


DRAND_GENESIS_UNIX = 1595431050  # League of Entropy default chain, 30 s period
DRAND_PERIOD = 30


def _drand(epoch: int) -> Dict[str, Any]:
    """Fixture beacon: real chain id and the round that actually opens the epoch's start second.

    Randomness and signature are synthetic (SPEC verifiers may only check them against the
    drand API); the round number is real so that a verifier enforcing §8.5 step 2 accepts
    the vectors.
    """
    start = int((GENESIS + timedelta(hours=epoch)).timestamp())
    return {
        "kind": "drand",
        "chain_hash": "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
        "round": (start - DRAND_GENESIS_UNIX) // DRAND_PERIOD + 1,
        "randomness": hashlib.sha256(_seed(f"rand{epoch}")).hexdigest(),
        "signature": hashlib.sha512(_seed(f"bsig{epoch}")).hexdigest(),
    }


@dataclass
class Scenario:
    operator: SigningKey
    observer: SigningKey
    witnesses: List[SigningKey]
    issuer: SigningKey
    sheets: List[Dict[str, Any]] = field(default_factory=list)
    paths: Dict[int, CompactPath] = field(default_factory=dict)
    disclosed_paths: Dict[int, CompactPath] = field(default_factory=dict)
    snapshot_hashes: Dict[int, List[bytes]] = field(default_factory=dict)
    negative_snapshots: List[Dict[str, Any]] = field(default_factory=list)
    witness_sigs: Dict[int, List[Dict[str, Any]]] = field(default_factory=dict)
    roots: Dict[int, bytes] = field(default_factory=dict)


def build_scenario() -> Scenario:
    sc = Scenario(
        operator=SigningKey.from_seed("urn:crovia:tacet:operator:fixture", _seed("operator")),
        observer=SigningKey.from_seed("urn:crovia:observer:fixture-1", _seed("observer")),
        witnesses=[SigningKey.from_seed(f"urn:crovia:witness:fixture-{i}", _seed(f"witness{i}")) for i in range(3)],
        issuer=SigningKey.from_seed("urn:crovia:seal-issuer:fixture", _seed("issuer")),
    )
    smap = SparseMerkleMap()
    for t in OTHER_TARGETS[:20]:
        smap.set(target_key(t), object_hash({"kind": "disclosure", "summary_hash": "sha256:" + "00" * 32,
                                             "summary_url": f"https://example.org/{t}", "snapshot_hash": "sha256:" + "11" * 32,
                                             "seal_hash": "sha256:" + "22" * 32, "reveals": None}))
    prev_hash = None
    key = target_key(TARGET)
    dkey = target_key(DISCLOSED_TARGET)
    for e in range(N_EPOCHS):
        if e == DISCLOSURE_EPOCH:
            smap.set(dkey, object_hash({"kind": "disclosure", "summary_hash": "sha256:" + "ab" * 32,
                                        "summary_url": f"https://example.org/{DISCLOSED_TARGET}",
                                        "snapshot_hash": "sha256:" + "cd" * 32, "seal_hash": "sha256:" + "ef" * 32,
                                        "reveals": None}))
        if e in (2, 8):
            smap.set(target_key(OTHER_TARGETS[20 + e]), object_hash({"kind": "commitment", "commit_hash": "sha256:" + "33" * 32,
                                                                      "committer": {"alg": "ed25519", "key_hex": "44" * 32},
                                                                      "seal_hash": "sha256:" + "55" * 32}))
        start, end = GENESIS + timedelta(hours=e), GENESIS + timedelta(hours=e + 1)
        beacon = _drand(e)
        snaps: List[Dict[str, Any]] = []
        if e in OBSERVED_EPOCHS:
            snaps.append(build_snapshot(
                observer=sc.observer, target_id=TARGET, surface_url=SURFACE,
                fetched_at=_iso(start + timedelta(minutes=17)), epoch=e, beacon_round=beacon["round"],
                http_status=200, body=f"<html>model card {e}</html>".encode(), predicate_id=PREDICATE[0],
                predicate_version=PREDICATE[1], predicate_code_hash=PREDICATE[2], result=False,
                tls_cert_sha256=hashlib.sha256(b"cert").digest(), resolved_ip="203.0.113.10"))
            snaps.append(build_snapshot(
                observer=sc.observer, target_id=OTHER_TARGETS[0], surface_url="https://example.org/other",
                fetched_at=_iso(start + timedelta(minutes=18)), epoch=e, beacon_round=beacon["round"],
                http_status=200, body=b"<html>other</html>", predicate_id=PREDICATE[0],
                predicate_version=PREDICATE[1], predicate_code_hash=PREDICATE[2], result=True))
        hashes = [snapshot_hash(s) for s in snaps]
        sc.snapshot_hashes[e] = hashes
        sc.negative_snapshots.extend(s for s in snaps if s["target_id"] == TARGET and s["result"] is False)

        root = smap.root()
        sc.roots[e] = root
        sheet = build_sheet(operator=sc.operator, map_id=MAP_ID, epoch=e, epoch_start=_iso(start), epoch_end=_iso(end),
                            root=root, size=len(smap), prev_sheet_hash=prev_hash, opened=beacon,
                            snapshots_root=merkle.merkle_root(hashes))
        if e not in UNANCHORED_EPOCHS:
            close_sheet(sheet, block_height=956_000 + e, proof_ref=f"ots://fixture/{e}.ots",
                        block_time=_iso(end + timedelta(minutes=40)))
        from .epoch import sheet_hash
        prev_hash = sheet_hash(sheet)
        sc.sheets.append(sheet)
        sc.paths[e] = smap.prove(key)
        sc.disclosed_paths[e] = smap.prove(dkey)
        sc.witness_sigs[e] = [witness_sign(w, sheet) for w in sc.witnesses[: (3 if e % 4 else 2)]]
    return sc


def witness_set(sc: Scenario, k: int = 2) -> Dict[str, Any]:
    return {"k": k, "n": len(sc.witnesses), "ids": [w.id for w in sc.witnesses]}


# --------------------------------------------------------------------------- PNX (crovia.pnx.v1)

def pnx_stream(label: str, n: int) -> bytes:
    """Deterministic pseudo-random bytes: SHA-256 in counter mode over a label.

    Language-independent, so a runner in any language can rebuild the bodies
    of the PNX vectors from the labels instead of storing them.
    """
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"tacet-pnx-fixture:{label}:{i}".encode()).digest()
        i += 1
    return out[:n]


PNX_RUN_ID = "conformance/run-001"
PNX_SALT = pnx_stream("salt", 16)
PNX_CLOSED_AT = "2026-09-20T12:00:00Z"
PNX_WITNESS_ID = "urn:crovia:pnx-witness:fixture"
PNX_ISSUER_ID = "urn:crovia:seal-issuer:fixture-pnx"

#: 80 bytes, above the 47-byte guarantee; appears verbatim in body 1.
PNX_LEAKED_KEY = b"sk-live-" + pnx_stream("openai_key", 36).hex().encode()
#: 64 bytes, never sent.
PNX_SAFE_KEY = b"AKIA" + pnx_stream("aws_key", 30).hex().encode()
#: A config file whose lines are all shorter than one k-gram (32 bytes incl. newline): it shares no
#: k-gram with the JSON body that quotes it (newlines arrive escaped), so only json-strings-v1 can find it.
PNX_LEAKED_FILE = ("database:\n"
                   "  host: db.internal.example\n"
                   "  user: svc_agent\n"
                   f"  password: p4ss-{pnx_stream('db_password', 6).hex()}\n"
                   "api:\n"
                   f"  token: {pnx_stream('api_token', 10).hex()}\n"
                   "  region: eu-west-1\n").encode()
PNX_CUSTOMER_CSV = b"id,email,plan\n" + b"".join(
    f"{1000 + i},user{i}@example.com,{('free', 'pro')[i % 2]}\n".encode() for i in range(8))
PNX_SESSION_ID = pnx_stream("session_id", 20).hex().encode()  # 40 bytes: partial class
PNX_DB_PIN = b"1234"                                            # 4 bytes: undetectable

PNX_BODIES: List[Dict[str, Any]] = [
    {"at": "2026-09-20T11:00:00Z", "body": b"POST /v1/chat/completions\n" + pnx_stream("noise-1", 300) + PNX_LEAKED_KEY + b"\n",
     "note": "raw leak: the key appears verbatim in a binary body"},
    {"at": "2026-09-20T11:05:00Z",
     "body": json.dumps({"model": "gpt-4o", "messages": [
         {"role": "system", "content": "You are a code reviewer."},
         {"role": "user", "content": "Review this file:\n" + PNX_LEAKED_FILE.decode()}], "temperature": 0}).encode(),
     "note": "leak inside a JSON string: newlines are escaped in the raw bytes; found only through json-strings-v1"},
    {"at": "2026-09-20T11:10:00Z", "body": b"GET /health HTTP/1.1\r\n", "note": "shorter than k_gram: adds no fingerprint"},
    {"at": "2026-09-20T11:15:00Z", "body": pnx_stream("noise-4", 1000), "note": "unrelated traffic"},
]
PNX_EXPOSURE_ASSETS: List[Tuple[str, bytes]] = [
    ("aws_key", PNX_SAFE_KEY), ("openai_key", PNX_LEAKED_KEY), ("config.yaml", PNX_LEAKED_FILE),
    ("session_id", PNX_SESSION_ID), ("db_pin", PNX_DB_PIN)]
PNX_CLEAN_ASSETS: List[Tuple[str, bytes]] = [("aws_key", PNX_SAFE_KEY), ("customer_export.csv", PNX_CUSTOMER_CSV)]


@dataclass
class PnxScenario:
    witness_key: SigningKey
    issuer: SigningKey
    witness: Any                      # EgressWitness after ingesting PNX_BODIES
    sheet: Dict[str, Any]
    clean: Dict[str, Any]             # proof over PNX_CLEAN_ASSETS: verdict absent
    exposure: Dict[str, Any]          # proof over PNX_EXPOSURE_ASSETS: verdict present
    other_sheet: Dict[str, Any]       # same salt and key, different traffic: a foreign root


def pnx_witness_key() -> SigningKey:
    return SigningKey.from_seed(PNX_WITNESS_ID, pnx_stream("witness-key", 32))


def build_pnx_scenario() -> PnxScenario:
    from .egress import EgressWitness
    key = pnx_witness_key()
    w = EgressWitness(run_id=PNX_RUN_ID, salt=PNX_SALT)
    for b in PNX_BODIES:
        w.ingest(b["body"], b["at"])
    sheet = w.sheet(key, PNX_CLOSED_AT)
    other = EgressWitness(run_id=PNX_RUN_ID, salt=PNX_SALT)
    other.ingest(pnx_stream("other-traffic", 700), "2026-09-20T11:00:00Z")
    return PnxScenario(
        witness_key=key,
        issuer=SigningKey.from_seed(PNX_ISSUER_ID, pnx_stream("issuer-key", 32)),
        witness=w, sheet=sheet,
        clean=w.prove(sheet, PNX_CLEAN_ASSETS),
        exposure=w.prove(sheet, PNX_EXPOSURE_ASSETS),
        other_sheet=other.sheet(key, PNX_CLOSED_AT),
    )
