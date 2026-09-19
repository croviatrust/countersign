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
from tacet_operator.publish import featured_proofs, index, observed_targets, trust_root
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
    res = verify_file(out, expected_operator_pubkey_hex=keys["operator"].public_hex, check_beacon=True)
    assert res["ok"], res["errors"]
    assert res["strength_verified"] == 2

    # a disclosed target cannot get a silence proof: its slot is not empty
    with pytest.raises(SilenceProofError):
        build_proof(s, keys["issuer"], DISCLOSED, from_epoch=0, to_epoch=2)

    # publishing
    tr = trust_root(s, keys)
    assert tr["operator"]["pubkey"]["key_hex"] == keys["operator"].public_hex
    latest = index(s)
    assert latest["latest_epoch"] == 2 and latest["anchored_epochs"] == 2 and latest["map_size"] == 2
    rows = featured_proofs(s, keys)
    assert [r["target_id"] for r in rows] == [SILENT]
    tg = observed_targets(s)
    by = {r["target_id"]: r for r in tg["targets"]}
    assert by[SILENT]["negative"] == 3 and by[SILENT]["negative_anchored_epochs"] == 2
    assert by[GATED]["last_result"] is True and by[GATED]["last_surface"].endswith(GATED)
    assert DOWN not in by


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
