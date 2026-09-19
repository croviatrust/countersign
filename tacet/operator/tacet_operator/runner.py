"""One epoch, one batch: open with drand, observe, update the map, sign the sheet, stamp it.

The operator is the only writer of the map. All changes of an epoch are applied
in this single batch and the sheet is emitted when the batch is complete, so
the root in the sheet is the map root at `epoch_end` even though the sheet is
signed while the hour is still running. Missed hours are back-filled with
empty sheets (historical drand round, no snapshots, no changes): they keep the
chain contiguous and contribute no silence.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from tacet import merkle
from tacet.canonical import canonicalize
from tacet.epoch import build_sheet, sheet_hash
from tacet.hashing import object_hash, prefixed, target_key
from tacet.keys import SigningKey
from tacet.snapshot import build_snapshot, snapshot_hash

from . import drand as drand_mod
from . import ots as ots_mod
from .config import EPOCH_SECONDS, GENESIS, MAP_ID, PUBLIC_BASE_URL, Settings, epoch_bounds, epoch_of
from .fetch import Fetched, fetch as http_fetch
from .predicates import load as load_predicate
from .state import State
from .targets import FEATURED_DEFAULT, load_list, plan_epoch, surfaces_for

log = logging.getLogger("tacet.operator")

PREDICATE_ID = "crovia.pred.hf-card-training-data"
RETRACTION_AFTER_NEGATIVES = 2

Fetcher = Callable[[str, float], Fetched]


def _seal_module():
    from crovia_seal import seal as seal_mod
    from crovia_seal.keys import load_issuer_key
    return seal_mod, load_issuer_key


def _issuer_for(key: SigningKey):
    _, load_issuer_key = _seal_module()
    from cryptography.hazmat.primitives import serialization
    seed = key._private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,  # noqa: SLF001
                                      serialization.NoEncryption())
    return load_issuer_key(key.id, seed.hex())


def assert_value(issuer_key: SigningKey, snapshot: Dict[str, Any], value_wo_seal: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Sign a slot value with a crovia.seal.v1 whose input is the snapshot and output is the value.

    The operator key signs sheets; the Seal-issuer key signs everything that is a Seal
    (slot-value assertions and silence proofs).
    """
    seal_mod, _ = _seal_module()
    issuer = _issuer_for(issuer_key)
    seal = seal_mod.emit_seal(
        issuer_key=issuer,
        input_bytes=canonicalize(snapshot),
        output_bytes=canonicalize(value_wo_seal),
        modality="text",
        generator_id="crovia/tacet-operator",
        generator_version="0.1.0",
        generator_params={"map_id": MAP_ID, "kind": value_wo_seal["kind"]},
    )
    return seal, seal_mod.compute_seal_hash(seal)


class EpochRunner:
    def __init__(self, settings: Settings, keys: Dict[str, SigningKey], *,
                 fetcher: Fetcher = http_fetch,
                 drand_latest: Callable[[], Dict[str, Any]] = drand_mod.fetch_latest,
                 drand_round: Optional[Callable[[int], Dict[str, Any]]] = None,
                 ots_stamp: Optional[Callable[[bytes, Any], None]] = ots_mod.stamp,
                 sleep: Callable[[float], None] = time.sleep):
        self.s = settings
        self.keys = keys
        self.state = State(settings.paths)
        self.fetcher = fetcher
        self.drand_latest = drand_latest
        self.drand_round = drand_round or drand_mod.fetch_round
        self.ots_stamp = ots_stamp
        self.sleep = sleep
        self.evaluate, self.pred_version, self.pred_code_hash = load_predicate(PREDICATE_ID)

    # -- public entry points ------------------------------------------------------

    def run(self, now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
        now = now or datetime.now(timezone.utc)
        if now < GENESIS:
            log.info("before genesis; nothing to do")
            return None
        current = epoch_of(now)
        last = self.state.latest_epoch()
        if last is not None and last >= current:
            log.info("epoch %s already emitted", current)
            return None
        first = 0 if last is None else last + 1
        for e in range(first, current):
            self._emit_empty(e)
        return self._emit_observed(current)

    # -- internals -----------------------------------------------------------------

    def _prev_hash(self, epoch: int) -> Optional[bytes]:
        if epoch == 0:
            return None
        prev = self.state.load_sheet(epoch - 1)
        if prev is None:
            raise RuntimeError(f"cannot emit epoch {epoch}: sheet {epoch - 1} missing")
        return sheet_hash(prev)

    def _finish(self, epoch: int, opened: Dict[str, Any], snaps: List[Dict[str, Any]],
                changes: List[Tuple[bytes, bytes]], m) -> Dict[str, Any]:
        start, end = epoch_bounds(epoch)
        snaps_root = merkle.merkle_root([snapshot_hash(s) for s in snaps])
        sheet = build_sheet(
            operator=self.keys["operator"], map_id=MAP_ID, epoch=epoch, epoch_start=start, epoch_end=end,
            root=m.root(), size=len(m), prev_sheet_hash=self._prev_hash(epoch), opened=opened,
            snapshots_root=snaps_root,
        )
        self.state.save_changes(epoch, changes)
        self.state.save_snapshots(epoch, snaps)
        self.state.save_map(m)
        self.state.save_sheet(sheet)
        if self.ots_stamp is not None:
            try:
                self.ots_stamp(sheet_hash(sheet), self.s.paths.ots / f"{epoch}.ots")
            except Exception as e:  # noqa: BLE001 - stamped later by refresh-anchors
                log.warning("epoch %s: OTS stamp deferred: %s", epoch, e)
        log.info("epoch %s: size=%s snapshots=%s changes=%s root=%s", epoch, len(m), len(snaps), len(changes), sheet["root"][:23])
        return sheet

    def _emit_empty(self, epoch: int) -> Dict[str, Any]:
        start, _ = epoch_bounds(epoch)
        ts = int(datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        opened = self.drand_round(drand_mod.round_at(ts))
        m = self.state.load_map()
        log.info("epoch %s: back-filled (operator was down)", epoch)
        return self._finish(epoch, opened, [], [], m)

    def _emit_observed(self, epoch: int) -> Dict[str, Any]:
        opened = self.drand_latest()
        m = self.state.load_map()
        all_targets = load_list(self.s.targets_file) if self.s.targets_file and self.s.targets_file.exists() else []
        featured = self.s.featured or FEATURED_DEFAULT
        picked, cursor = plan_epoch(all_targets, featured, self.state.cursor(), self.s.per_epoch_budget, self.s.featured_every_epoch)
        snaps: List[Dict[str, Any]] = []
        changes: List[Tuple[bytes, bytes]] = []
        fetch_log: List[Dict[str, Any]] = []
        for target in picked:
            f = self._observe(target)
            fetch_log.append({"target_id": target, "url": f.url, "status": f.status, "len": len(f.body),
                              "ms": f.elapsed_ms, "error": f.error, "at": f.fetched_at})
            if f.status != 200 or not f.body:
                continue  # collection failure is indeterminate, never absence
            result = bool(self.evaluate(f.body))
            snap = build_snapshot(
                observer=self.keys["observer"], target_id=target, surface_url=f.url, fetched_at=f.fetched_at,
                epoch=epoch, beacon_round=opened["round"], http_status=f.status, body=f.body,
                predicate_id=PREDICATE_ID, predicate_version=self.pred_version, predicate_code_hash=self.pred_code_hash,
                result=result, tls_cert_sha256=f.tls_cert_sha256, resolved_ip=f.resolved_ip,
            )
            snaps.append(snap)
            changes.extend(self._transition(m, target, snap))
            self.sleep(self.s.request_delay_s)
        self.state.save_cursor(cursor)
        (self.s.paths.fetch_log / f"{epoch}.jsonl").write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in fetch_log), encoding="utf-8")
        return self._finish(epoch, opened, snaps, changes, m)

    def _observe(self, target: str) -> Fetched:
        primary, fallback = surfaces_for(target)
        f = self.fetcher(primary, self.s.request_timeout_s)
        if f.status in (401, 403):
            self.sleep(self.s.request_delay_s)
            f = self.fetcher(fallback, self.s.request_timeout_s)
        return f

    def _transition(self, m, target: str, snap: Dict[str, Any]) -> List[Tuple[bytes, bytes]]:
        """Forward-only slot transitions (SPEC §5.3): ∅→disclosure, disclosure→retraction."""
        key = target_key(target)
        current = self.state.value(key)
        kind = current["value"]["kind"] if current else None
        meta = self.state.meta(key)
        out: List[Tuple[bytes, bytes]] = []
        if snap["result"] is True:
            meta["negative_streak"] = 0
            if kind is None:
                value = {"kind": "disclosure", "summary_hash": snap["body_sha256"], "summary_url": snap["surface_url"],
                         "snapshot_hash": prefixed(snapshot_hash(snap)), "reveals": None}
                seal, seal_h = assert_value(self.keys["issuer"], snap, value)
                value["seal_hash"] = seal_h
                vh = self.state.put_value(key, value, seal)
                m.set(key, vh)
                out.append((key, vh))
        else:
            if kind == "disclosure":
                meta["negative_streak"] = int(meta.get("negative_streak", 0)) + 1
                if meta["negative_streak"] >= RETRACTION_AFTER_NEGATIVES:
                    value = {"kind": "retraction", "of": current["value_hash"]}
                    seal, seal_h = assert_value(self.keys["issuer"], snap, value)
                    value["seal_hash"] = seal_h
                    vh = self.state.put_value(key, value, seal)
                    m.set(key, vh)
                    out.append((key, vh))
        meta["last_result"] = snap["result"]
        meta["last_epoch"] = snap["epoch"]
        self.state.put_meta(key, meta)
        return out


# -- anchoring -------------------------------------------------------------------

def refresh_anchors(settings: Settings, *, stamp=ots_mod.stamp, status=ots_mod.status, block_time=ots_mod.block_time) -> Dict[str, int]:
    """Stamp sheets that missed stamping; close sheets whose OTS proof reached Bitcoin."""
    from tacet.epoch import close_sheet
    st = State(settings.paths)
    counts = {"stamped": 0, "closed": 0, "pending": 0}
    last = st.latest_epoch()
    if last is None:
        return counts
    for e in range(0, last + 1):
        sheet = st.load_sheet(e)
        if sheet is None or sheet["closed"]["status"] == "bitcoin":
            continue
        ots_path = settings.paths.ots / f"{e}.ots"
        if not ots_path.exists():
            try:
                stamp(sheet_hash(sheet), ots_path)
                counts["stamped"] += 1
            except Exception as ex:  # noqa: BLE001
                log.warning("epoch %s: stamp failed: %s", e, ex)
                counts["pending"] += 1
                continue
        state_, height = status(ots_path)
        if state_ == "bitcoin" and height:
            bt = block_time(height, settings.paths.state / "block_times.json")
            if bt is None:
                counts["pending"] += 1
                continue
            close_sheet(sheet, block_height=height, proof_ref=f"{PUBLIC_BASE_URL}/ots/{e}.ots", block_time=bt)
            st.save_sheet(sheet)
            counts["closed"] += 1
        else:
            counts["pending"] += 1
    return counts


def value_hash_of(value: Dict[str, Any]) -> str:
    return prefixed(object_hash(value))


__all__ = ["EpochRunner", "refresh_anchors", "assert_value", "EPOCH_SECONDS"]
