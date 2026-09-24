"""drand League of Entropy beacon: the epoch's lower time bound (SPEC §6).

The default chain (pedersen-bls-chained, 30 s period, genesis 1595431050) is
pinned by hash. `fetch_latest` tries the public relays in order and returns the
`opened` object for an epoch sheet.

Verification, exactly (SPEC §8.5 step 2):

- `beacon_check` is the offline part: `opened.chain_hash` is the pinned chain
  and the round's scheduled time (genesis + (round − 1) · period) sits in
  [epoch_start − period, epoch_start + tolerance]. It reads nothing but the
  sheet. It does NOT verify the round's BLS signature, so on its own it does
  not prove that `randomness` and `signature` are the chain's output for that
  round: an operator could write a plausible round number with invented bytes.
- `beacon_check_online` adds the byte check without a BLS library: it fetches
  the same round from the public relays and requires `randomness` and
  `signature` to be identical. Relays unreachable → None (unchecked), never
  a pass.
- Verifying the BLS12-381 signature against `trust_root.beacon.public_key`
  would make the byte check offline too. This module does not implement it.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, List, Optional

from .config import DRAND_CHAIN_HASH, DRAND_URLS, USER_AGENT

PERIOD = 30
GENESIS_TIME = 1595431050
# The opening round must lie inside the hour it opens: scheduled no earlier than one period
# before epoch_start and strictly before epoch_end. Published as trust_root.beacon.tolerance_seconds.
# Until 2026-09-24 this was 1800 s; epochs 76, 87, 92 and 99 of the disclosure map were opened
# 31–42 minutes into their hour because the hourly run started late, and their signed, anchored
# sheets cannot change. A round inside the hour is still a correct lower bound for everything in
# that hour, so the bound is the hour. The operator now opens every epoch with the first round of
# its hour (see runner._emit_observed), so lateness no longer reaches the sheet.
TOLERANCE_S = 3600
# Openings later than this are correct but reported as late by the verifier.
LATE_OPENING_S = 900


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


def opening_delay_s(opened: Dict[str, Any], epoch_start: str) -> Optional[int]:
    """Seconds between `epoch_start` and the round's scheduled time; None if unreadable."""
    from datetime import datetime, timezone
    try:
        start = int(datetime.strptime(epoch_start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        return round_time(int(opened["round"])) - start
    except (TypeError, ValueError, KeyError):
        return None


def beacon_check(opened: Dict[str, Any], epoch_start: str, tolerance_s: int = TOLERANCE_S) -> bool:
    """Chain id and schedule only: `chain_hash` is the pinned chain and the round's
    scheduled time is within [epoch_start − period, epoch_start + tolerance).
    Offline. Does not look at `randomness` or `signature` (see module docstring)."""
    if opened.get("chain_hash") != DRAND_CHAIN_HASH:
        return False
    delay = opening_delay_s(opened, epoch_start)
    if delay is None:
        return False
    return -PERIOD <= delay < tolerance_s


beacon_schedule_check = beacon_check


def beacon_check_online(opened: Dict[str, Any], epoch_start: str, tolerance_s: int = TOLERANCE_S,
                        timeout: float = 10.0) -> Optional[bool]:
    """Schedule check, then the round's bytes against the public relays.

    True: chain, schedule, and `randomness` + `signature` identical to what the
    relays serve for that round. False: schedule wrong or bytes differ. None:
    schedule right, relays unreachable, bytes unchecked."""
    if not beacon_check(opened, epoch_start, tolerance_s):
        return False
    try:
        served = fetch_round(int(opened["round"]), timeout=timeout)
    except DrandError:
        return None
    return served["randomness"] == opened.get("randomness") and served["signature"] == opened.get("signature")


class BeaconChecker:
    """`beacon_check_online` with a per-sheet transcript, for `tacet-operator verify`."""

    def __init__(self, online: bool = True, timeout: float = 10.0) -> None:
        self.online = online
        self.timeout = timeout
        self.details: List[str] = []

    def __call__(self, opened: Dict[str, Any], epoch_start: str) -> Optional[bool]:
        rnd = opened.get("round")
        if not beacon_check(opened, epoch_start):
            self.details.append(f"round {rnd}: not the pinned chain or not inside the hour starting {epoch_start}")
            return False
        delay = opening_delay_s(opened, epoch_start) or 0
        when = f"{delay} s after the hour began" + (" (late opening)" if delay > LATE_OPENING_S else "")
        if not self.online:
            self.details.append(f"round {rnd}: chain ok, scheduled {when}; bytes not checked (offline)")
            return None
        verdict = beacon_check_online(opened, epoch_start, timeout=self.timeout)
        if verdict is None:
            self.details.append(f"round {rnd}: chain ok, scheduled {when}; bytes not checked (no relay reachable)")
        elif verdict:
            self.details.append(f"round {rnd}: chain ok, scheduled {when}; bytes match the relay")
        else:
            self.details.append(f"round {rnd}: randomness/signature differ from the relay's")
        return verdict
