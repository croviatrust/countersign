"""Three epochs with a fake network: one target stays silent, one discloses, one is unreachable.

Then: refresh anchors with a fake OTS, build a level-2 proof for the silent
target, verify it offline, and check the monotonicity rule numerically.
"""
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

from tacet.epoch import validate_chain
from tacet.hashing import target_key
from tacet.silence import SilenceProofError
from tacet_operator import drand as drand_mod
from tacet_operator.config import GENESIS, EPOCH_SECONDS, Paths, Settings
from tacet_operator.fetch import Fetched
from tacet_operator.keys import load_all
from tacet_operator.prove import build as build_proof, verify_file
from tacet_operator.publish import badges, featured_proofs, health, index, observed_targets, trust_root
from tacet_operator.runner import EpochRunner, refresh_anchors
from tacet_operator.state import State

SILENT = "vendor/silent-model"
DISCLOSED = "vendor/open-model"
DOWN = "vendor/unreachable-model"
GATED = "vendor/gated-model"

SILENT_CARD = b"---\nlicense: mit\n---\n# Silent\nA model. Nothing about data here.\n"
OPEN_CARD = b"---\nlicense: mit\ndatasets: [allenai/c4]\n---\n# Open\n"
GATED_HTML = b"<h2>Training Data</h2><p>Pretrained on 15T tokens of publicly available web data; see the paper for details on filtering and mixture.</p>"


def fake_fetcher(url: str, timeout: float) -> Fetched:
    at = "2026-09-19T18:07:00Z"
    if SILENT in url:
        return Fetched(url, 200, SILENT_CARD, b"\x11" * 32, "1.2.3.4", at, 10)
    if DISCLOSED in url:
        return Fetched(url, 200, OPEN_CARD, b"\x11" * 32, "1.2.3.4", at, 10)
    if GATED in url:
        if url.endswith("README.md"):
            return Fetched(url, 401, b"", b"\x11" * 32, "1.2.3.4", at, 10)
        return Fetched(url, 200, GATED_HTML, b"\x11" * 32, "1.2.3.4", at, 10)
    return Fetched(url, 0, b"", None, None, at, 10, error="timeout")


class FakeDrand:
    def __init__(self):
        self.now = GENESIS

    def latest(self):
        r = drand_mod.round_at(int(self.now.timestamp()))
        return {"kind": "drand", "chain_hash": drand_mod.DRAND_CHAIN_HASH, "round": r,
                "randomness": hashlib.sha256(str(r).encode()).hexdigest(), "signature": "00" * 96}

    def round(self, r):
        return {"kind": "drand", "chain_hash": drand_mod.DRAND_CHAIN_HASH, "round": r,
                "randomness": hashlib.sha256(str(r).encode()).hexdigest(), "signature": "00" * 96}


class FakeOTS:
    def __init__(self):
        self.stamped = {}
        self.confirm = set()

    def stamp(self, digest: bytes, out: Path):
        out.write_bytes(b"OTS" + digest)
        self.stamped[out.name] = digest

    def status(self, path: Path):
        return ("bitcoin", 960_000 + int(path.stem)) if path.stem in self.confirm else ("pending", None)

    def block_time(self, height: int, cache: Path):
        return "2026-09-20T00:00:00Z"


@pytest.fixture
def env(tmp_path):
    s = Settings(paths=Paths(tmp_path / "state", tmp_path / "public"))
    s.per_epoch_budget = 10
    s.featured = [SILENT, DISCLOSED, DOWN, GATED]
    s.request_delay_s = 0
    s.paths.ensure()
    keys = load_all(s.paths.keys)
    return s, keys


def run_epochs(s, keys, n, fake_drand, fake_ots):
    runner = EpochRunner(s, keys, fetcher=fake_fetcher, drand_latest=fake_drand.latest,
                         drand_round=fake_drand.round, ots_stamp=fake_ots.stamp, sleep=lambda _: None)
    sheets = []
    for i in range(n):
        fake_drand.now = GENESIS + timedelta(seconds=EPOCH_SECONDS * i + 300)
        sheets.append(runner.run(now=fake_drand.now))
    return runner, sheets


def test_three_epochs_then_proof(env):
    s, keys = env
    fd, fo = FakeDrand(), FakeOTS()
    runner, sheets = run_epochs(s, keys, 3, fd, fo)
    assert [x["epoch"] for x in sheets] == [0, 1, 2]
    validate_chain(sheets)

    st = State(s.paths)
    # map: disclosed + gated inserted in epoch 0 only (forward-only, no re-insert)
    assert sheets[0]["size"] == 2 and sheets[2]["size"] == 2
    assert len(st.load_changes(0)) == 2 and st.load_changes(1) == []
    assert st.value(target_key(DISCLOSED))["value"]["kind"] == "disclosure"
    assert st.value(target_key(SILENT)) is None
    # unreachable target: no snapshot at all (indeterminate, never absence)
    for e in range(3):
        assert not any(x["target_id"] == DOWN for x in st.load_snapshots(e))
        assert any(x["target_id"] == SILENT and x["result"] is False for x in st.load_snapshots(e))
        assert (s.paths.ots / f"{e}.ots").exists()

    # a fourth run in the same hour is a no-op
    assert runner.run(now=fd.now + timedelta(seconds=60)) is None

    # anchors: confirm epochs 0 and 1 only
    fo.confirm = {"0", "1"}
    counts = refresh_anchors(s, stamp=fo.stamp, status=fo.status, block_time=fo.block_time)
    assert counts == {"stamped": 0, "closed": 2, "pending": 1}
    assert st.load_sheet(1)["closed"]["status"] == "bitcoin"
    assert st.load_sheet(2)["closed"]["status"] == "pending"

    bundle = build_proof(s, keys["issuer"], SILENT, from_epoch=0, to_epoch=2)
    sil = bundle["proof"]["silence"]
    assert sil["map_epochs"] == 3 and sil["observed_epochs"] == 2          # epoch 2 unanchored -> not counted
    assert sil["silence_seconds"] == 2 * EPOCH_SECONDS
    assert sil["silence_days"] == f"{2 * EPOCH_SECONDS / 86400:.2f}"
    assert bundle["seal"]["seal_version"] == "crovia.seal.v1"

    out = s.paths.public / "proofs" / "t.seal.json"
    out.write_text(json.dumps(bundle))
    res = verify_file(out, expected_operator_pubkey_hex=keys["operator"].public_hex, check_beacon=True, check_ots=False, offline=True)
    assert res["ok"], res["errors"]
    assert res["strength_verified"] == 2
    # offline, the verifier says what it did not check: round bytes (no relay, no BLS) and anchors (no hook)
    assert len(res["beacon"]) == 3 and all("bytes not checked (offline)" in d for d in res["beacon"])
    assert any("round bytes unchecked" in w for w in res["warnings"])
    assert any("Bitcoin anchors not externally verified" in w for w in res["warnings"])

    # a disclosed target cannot get a silence proof: its slot is not empty
    with pytest.raises(SilenceProofError):
        build_proof(s, keys["issuer"], DISCLOSED, from_epoch=0, to_epoch=2)

    # publishing
    tr = trust_root(s, keys)
    assert tr["operator"]["pubkey"]["key_hex"] == keys["operator"].public_hex
    now = GENESIS + timedelta(minutes=22)  # the fake fetcher stamps every fetch 18:07:00Z; 15 min later
    latest = index(s, now=now)
    assert latest["latest_epoch"] == 2 and latest["anchored_epochs"] == 2 and latest["map_size"] == 2
    st_ = latest["status"]
    assert st_["state"] == "ok" and st_["reasons"] == [], st_
    assert st_["observation"]["last_observed_epoch"] == 2 and st_["observation"]["late_runs_24h"] == []
    assert st_["anchoring"]["pending_epochs"] == 1 and st_["anchoring"]["oldest_pending_epoch"] == 2
    # the same rows read two hours later are stale, whatever the file says: readers must compare as_of too
    assert index(s, now=now + timedelta(hours=2))["status"]["state"] == "stale"
    rows = featured_proofs(s, keys)
    assert [r["target_id"] for r in rows] == [SILENT]
    tg = observed_targets(s)
    by = {r["target_id"]: r for r in tg["targets"]}
    assert by[SILENT]["negative"] == 3 and by[SILENT]["negative_anchored_epochs"] == 2
    assert by[GATED]["last_result"] is True and by[GATED]["last_surface"].endswith(GATED)
    assert DOWN not in by
    b = badges(s, latest, tg)
    assert b["epochs"]["message"] == "3 (2 in Bitcoin)" and b["models"]["message"] == str(tg["count"])
    shield = json.loads((s.paths.public / "badges" / "negative.json").read_text())
    assert shield["schemaVersion"] == 1 and shield["message"] == str(latest["negative_snapshots_total"])


def test_backfill_after_downtime(env):
    s, keys = env
    fd, fo = FakeDrand(), FakeOTS()
    runner, _ = run_epochs(s, keys, 1, fd, fo)
    # operator returns three hours later: epochs 1 and 2 are back-filled empty, 3 is observed
    fd.now = GENESIS + timedelta(seconds=EPOCH_SECONDS * 3 + 300)
    sheet = runner.run(now=fd.now)
    assert sheet["epoch"] == 3
    st = State(s.paths)
    assert st.load_snapshots(1) == [] and st.load_snapshots(2) == []
    validate_chain(list(st.iter_sheets(0, 3)))
    for e in (1, 2):
        sh = st.load_sheet(e)
        assert drand_mod.beacon_check(sh["opened"], sh["epoch_start"])
    fo.confirm = {"0", "1", "2", "3"}
    refresh_anchors(s, stamp=fo.stamp, status=fo.status, block_time=fo.block_time)
    bundle = build_proof(s, keys["issuer"], SILENT, from_epoch=0, to_epoch=3)
    # silence only from the two observed epochs (0 and 3), not the empty hours in between
    assert bundle["proof"]["silence"]["observed_epochs"] == 2
    assert bundle["proof"]["silence"]["silence_seconds"] == 2 * EPOCH_SECONDS


def test_beacon_check_is_schedule_only_and_online_adds_the_bytes(monkeypatch):
    from datetime import datetime, timezone
    start = "2026-09-19T09:00:00Z"
    r = drand_mod.round_at(int(datetime(2026, 9, 19, 9, tzinfo=timezone.utc).timestamp()))  # first round of the hour
    good = {"kind": "drand", "chain_hash": drand_mod.DRAND_CHAIN_HASH, "round": r, "randomness": "aa" * 32, "signature": "bb" * 48}
    # offline: the schedule check accepts any bytes for a well-placed round — it cannot tell, and says so
    assert drand_mod.beacon_check(good, start)
    assert drand_mod.beacon_check({**good, "randomness": "ff" * 32}, start)
    assert not drand_mod.beacon_check({**good, "chain_hash": "00" * 32}, start)
    assert drand_mod.beacon_check({**good, "round": r + 80}, start)            # 40 minutes in: late, still this hour
    assert not drand_mod.beacon_check({**good, "round": r + 120}, start)       # the next hour's first round
    assert not drand_mod.beacon_check({**good, "round": r - 2}, start)         # a round from before the hour
    assert not drand_mod.beacon_check({**good, "round": "x"}, start)
    assert drand_mod.opening_delay_s({**good, "round": r + 80}, start) == 2400

    served = dict(good)
    monkeypatch.setattr(drand_mod, "fetch_round", lambda n, timeout=10.0: dict(served))
    assert drand_mod.beacon_check_online(good, start) is True
    assert drand_mod.beacon_check_online({**good, "randomness": "ff" * 32}, start) is False
    assert drand_mod.beacon_check_online({**good, "round": r + 120}, start) is False
    chk = drand_mod.BeaconChecker(online=True)
    assert chk({**good, "round": r + 80}, start) is True and "2400 s after the hour began (late opening)" in chk.details[-1]

    def down(n, timeout=10.0):
        raise drand_mod.DrandError("all drand relays failed")
    monkeypatch.setattr(drand_mod, "fetch_round", down)
    assert drand_mod.beacon_check_online(good, start) is None

    chk = drand_mod.BeaconChecker(online=True)
    assert chk(good, start) is None and "no relay reachable" in chk.details[-1]
    chk = drand_mod.BeaconChecker(online=False)
    assert chk(good, start) is None and "offline" in chk.details[-1]
    assert chk({**good, "round": r + 120}, start) is False and "not inside the hour" in chk.details[-1]


def test_late_run_still_opens_with_the_first_round_of_the_hour(env):
    s, keys = env
    fd, fo = FakeDrand(), FakeOTS()
    runner, _ = run_epochs(s, keys, 1, fd, fo)
    # the hourly run for epoch 1 starts 41 minutes late (what happened to epochs 76, 87, 92, 99 of the live map)
    fd.now = GENESIS + timedelta(seconds=EPOCH_SECONDS + 41 * 60)
    sheet = runner.run(now=fd.now)
    first_round_of_hour = drand_mod.round_at(int((GENESIS + timedelta(seconds=EPOCH_SECONDS)).timestamp()))
    assert sheet["opened"]["round"] == first_round_of_hour
    assert drand_mod.opening_delay_s(sheet["opened"], sheet["epoch_start"]) == 0
    assert drand_mod.beacon_check(sheet["opened"], sheet["epoch_start"])
    # every snapshot of the epoch is bound to that round
    for snap in State(s.paths).load_snapshots(1):
        assert snap["beacon_round"] == first_round_of_hour

    # a relay answering with a round outside the hour is refused: the operator never signs what its verifier rejects
    def wrong_round(n):
        return {"kind": "drand", "chain_hash": drand_mod.DRAND_CHAIN_HASH, "round": n + 500,
                "randomness": "00" * 32, "signature": "00" * 48}
    bad = EpochRunner(s, keys, fetcher=fake_fetcher, drand_round=wrong_round, ots_stamp=fo.stamp, sleep=lambda _: None)
    with pytest.raises(RuntimeError, match="not inside the hour"):
        bad.run(now=GENESIS + timedelta(seconds=EPOCH_SECONDS * 2 + 300))
    assert State(s.paths).latest_epoch() == 1


def test_health_is_fail_closed():
    def row(e, snaps=3, closed="bitcoin", first_delay=300):
        start = GENESIS + timedelta(seconds=EPOCH_SECONDS * e)
        fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        return {"epoch": e, "epoch_start": fmt(start), "epoch_end": fmt(start + timedelta(seconds=EPOCH_SECONDS)),
                "snapshots": snaps, "closed": closed,
                "first_fetched_at": fmt(start + timedelta(seconds=first_delay)) if snaps else None,
                "last_fetched_at": fmt(start + timedelta(seconds=first_delay + 90)) if snaps else None}
    rows = [row(e, closed="bitcoin" if e < 29 else "pending") for e in range(30)]
    now = GENESIS + timedelta(seconds=EPOCH_SECONDS * 29 + 1200)
    assert health(rows, now)["state"] == "ok"
    assert health([], now)["state"] == "stale"
    # two epochs behind
    h = health(rows, now + timedelta(hours=2))
    assert h["state"] == "stale" and any("current hour is epoch 31" in r for r in h["reasons"])
    # a gap in the last 24 hours
    h = health(rows[:20] + [row(20, snaps=0)] + rows[21:], now)
    assert h["state"] == "degraded" and h["observation"]["empty_epochs_24h"] == [20]
    # three late runs
    late = [row(e, first_delay=2400 if e in (10, 15, 20) else 300, closed="bitcoin" if e < 29 else "pending") for e in range(30)]
    h = health(late, now)
    assert h["state"] == "degraded" and h["observation"]["late_runs_24h"] == [10, 15, 20]
    assert health([row(e, first_delay=2400 if e in (10, 15) else 300, closed="bitcoin" if e < 29 else "pending") for e in range(30)], now)["state"] == "ok"
    # an anchor pending for more than a day
    h = health([row(e, closed="pending" if e == 2 else "bitcoin") for e in range(30)], now)
    assert h["state"] == "degraded" and h["anchoring"]["oldest_pending_epoch"] == 2 and any("without a Bitcoin anchor" in r for r in h["reasons"])
    # the latest epoch is a back-fill
    h = health(rows[:29] + [row(29, snaps=0, closed="pending")], now)
    assert h["state"] == "degraded" and any("back-fill" in r for r in h["reasons"])


def test_transient_relay_failure_does_not_cost_the_hour(env):
    s, keys = env
    fd, fo = FakeDrand(), FakeOTS()
    calls = {"n": 0}
    slept = []

    def flaky(n):
        calls["n"] += 1
        if calls["n"] < 3:
            raise drand_mod.DrandError("all drand relays failed: timeout")
        return fd.round(n)
    runner = EpochRunner(s, keys, fetcher=fake_fetcher, drand_round=flaky, ots_stamp=fo.stamp, sleep=slept.append)
    sheet = runner.run(now=GENESIS + timedelta(seconds=300))
    assert sheet["epoch"] == 0 and calls["n"] == 3 and [t for t in slept if t] == [15, 30]

    def dead(n):
        raise drand_mod.DrandError("all drand relays failed")
    runner = EpochRunner(s, keys, fetcher=fake_fetcher, drand_round=dead, ots_stamp=fo.stamp, sleep=slept.append)
    with pytest.raises(drand_mod.DrandError):
        runner.run(now=GENESIS + timedelta(seconds=EPOCH_SECONDS + 300))
    assert State(s.paths).latest_epoch() == 0
