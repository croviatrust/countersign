from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MAP_ID = "urn:crovia:tacet:map:disclosure"
OPERATOR_ID = "urn:crovia:tacet:operator:crovia-trust"
OBSERVER_ID = "urn:crovia:observer:hetzner-1"
ISSUER_ID = "urn:crovia:seal-issuer:tacet"  # Seal issuer ids are constrained by the Seal spec

# Epoch 0 starts here; epoch e covers [GENESIS + e*EPOCH_SECONDS, GENESIS + (e+1)*EPOCH_SECONDS).
GENESIS = datetime(2026, 9, 19, 18, 0, 0, tzinfo=timezone.utc)
EPOCH_SECONDS = 3600

DRAND_CHAIN_HASH = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
DRAND_URLS = (
    "https://api.drand.sh",
    "https://drand.cloudflare.com",
    "https://api2.drand.sh",
)

PUBLIC_BASE_URL = "https://croviatrust.com/registry/data/tacet"
USER_AGENT = "crovia-tacet-observer/0.1 (+https://croviatrust.com/registry/tacet/)"


@dataclass
class Paths:
    state: Path
    public: Path

    @property
    def keys(self) -> Path:
        return self.state / "keys"

    @property
    def map_file(self) -> Path:
        return self.state / "map.json"

    @property
    def values(self) -> Path:
        return self.state / "values"

    @property
    def cursor(self) -> Path:
        return self.state / "cursor.json"

    @property
    def fetch_log(self) -> Path:
        return self.state / "fetch_log"

    @property
    def sheets(self) -> Path:
        return self.public / "sheets"

    @property
    def snapshots(self) -> Path:
        return self.public / "snapshots"

    @property
    def changes(self) -> Path:
        return self.public / "changes"

    @property
    def ots(self) -> Path:
        return self.public / "ots"

    @property
    def proofs(self) -> Path:
        return self.public / "proofs"

    def ensure(self) -> None:
        for d in (self.state, self.keys, self.values, self.fetch_log,
                  self.public, self.sheets, self.snapshots, self.changes, self.ots, self.proofs):
            d.mkdir(parents=True, exist_ok=True)


@dataclass
class Settings:
    paths: Paths
    per_epoch_budget: int = 120          # surfaces fetched per epoch (HF-friendly: 2/min)
    featured_every_epoch: int = 40       # featured targets observed in every epoch
    request_delay_s: float = 0.6
    request_timeout_s: float = 25.0
    featured: list = field(default_factory=list)
    targets_file: Path | None = None     # newline-separated org/model ids

    @classmethod
    def from_env(cls) -> "Settings":
        state = Path(os.environ.get("TACET_STATE", "/opt/crovia/tacet/state"))
        public = Path(os.environ.get("TACET_PUBLIC", "/var/www/registry/data/tacet"))
        s = cls(paths=Paths(state, public))
        if os.environ.get("TACET_BUDGET"):
            s.per_epoch_budget = int(os.environ["TACET_BUDGET"])
        if os.environ.get("TACET_TARGETS"):
            s.targets_file = Path(os.environ["TACET_TARGETS"])
        return s


def epoch_of(ts: datetime) -> int:
    return int((ts - GENESIS).total_seconds() // EPOCH_SECONDS)


def epoch_bounds(epoch: int) -> tuple[str, str]:
    start = GENESIS.timestamp() + epoch * EPOCH_SECONDS
    end = start + EPOCH_SECONDS
    f = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    return f(start), f(end)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
