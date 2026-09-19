"""drand League of Entropy beacon: the epoch's lower time bound (SPEC §6).

The default chain (pedersen-bls-chained, 30 s period, genesis 1595431050) is
pinned by hash. `fetch_latest` tries the public relays in order and returns the
`opened` object for an epoch sheet. `round_time` lets verifiers check that the
round could not have existed before `epoch_start`.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict

from .config import DRAND_CHAIN_HASH, DRAND_URLS, USER_AGENT

PERIOD = 30
GENESIS_TIME = 1595431050


class DrandError(RuntimeError):
    pass


def _get(url: str, timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_latest(timeout: float = 10.0) -> Dict[str, Any]:
    last = None
    for base in DRAND_URLS:
        try:
            d = _get(f"{base}/{DRAND_CHAIN_HASH}/public/latest", timeout)
            for k in ("round", "randomness", "signature"):
                if k not in d:
                    raise DrandError(f"{base}: missing {k}")
            return {
                "kind": "drand",
                "chain_hash": DRAND_CHAIN_HASH,
                "round": int(d["round"]),
                "randomness": d["randomness"],
                "signature": d["signature"],
            }
        except Exception as e:  # noqa: BLE001 - try next relay
            last = e
    raise DrandError(f"all drand relays failed: {last}")


def fetch_info(timeout: float = 10.0) -> Dict[str, Any]:
    last = None
    for base in DRAND_URLS:
        try:
            d = _get(f"{base}/{DRAND_CHAIN_HASH}/info", timeout)
            if d.get("hash") != DRAND_CHAIN_HASH:
                raise DrandError("chain hash mismatch")
            return {"chain_hash": d["hash"], "public_key": d["public_key"], "period": d["period"],
                    "genesis_time": d["genesis_time"], "scheme": d.get("schemeID")}
        except Exception as e:  # noqa: BLE001
            last = e
    raise DrandError(f"all drand relays failed: {last}")


def fetch_round(round_no: int, timeout: float = 10.0) -> Dict[str, Any]:
    """Historical round (used only to back-fill empty epochs after downtime)."""
    last = None
    for base in DRAND_URLS:
        try:
            d = _get(f"{base}/{DRAND_CHAIN_HASH}/public/{round_no}", timeout)
            if int(d["round"]) != round_no:
                raise DrandError("round mismatch")
            return {"kind": "drand", "chain_hash": DRAND_CHAIN_HASH, "round": round_no,
                    "randomness": d["randomness"], "signature": d["signature"]}
        except Exception as e:  # noqa: BLE001
            last = e
    raise DrandError(f"all drand relays failed for round {round_no}: {last}")


def round_time(round_no: int) -> int:
    """Unix time at which `round_no` became available."""
    return GENESIS_TIME + (round_no - 1) * PERIOD


def round_at(unix_time: int) -> int:
    """First round available at or after `unix_time`."""
    if unix_time <= GENESIS_TIME:
        return 1
    return (unix_time - GENESIS_TIME + PERIOD - 1) // PERIOD + 1


def beacon_check(opened: Dict[str, Any], epoch_start: str, tolerance_s: int = 1800) -> bool:
    """SPEC §8.5 step 2: the round must belong to the pinned chain and sit at the epoch start."""
    from datetime import datetime, timezone
    if opened.get("chain_hash") != DRAND_CHAIN_HASH:
        return False
    start = int(datetime.strptime(epoch_start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    t = round_time(int(opened["round"]))
    return start - PERIOD <= t <= start + tolerance_s
