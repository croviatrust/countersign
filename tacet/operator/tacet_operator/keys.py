"""Ed25519 seeds on disk (0600). Three roles, three keys, never shared."""
from __future__ import annotations

import os
from pathlib import Path

from tacet.keys import SigningKey

from .config import ISSUER_ID, OBSERVER_ID, OPERATOR_ID

ROLES = {"operator": OPERATOR_ID, "observer": OBSERVER_ID, "issuer": ISSUER_ID}


def load_or_create(keys_dir: Path, role: str) -> SigningKey:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")
    path = keys_dir / f"{role}.seed"
    if path.exists():
        seed = path.read_bytes()
        if len(seed) != 32:
            raise ValueError(f"{path} must hold exactly 32 bytes")
    else:
        keys_dir.mkdir(parents=True, exist_ok=True)
        seed = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(seed)
    return SigningKey.from_seed(ROLES[role], seed)


def load_all(keys_dir: Path) -> dict[str, SigningKey]:
    return {role: load_or_create(keys_dir, role) for role in ROLES}
