"""Public predicates (SPEC §7.3): pure functions bytes -> bool, versioned, hashed.

`code_hash` is SHA-256 of the predicate module's source file, so a third party
re-running the predicate on an archived copy of the surface can check that it
executed the same code the snapshot names.
"""
from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from typing import Callable

REGISTRY = {
    "crovia.pred.hf-card-training-data": "hf_card_training_data_v1",
}


def load(predicate_id: str) -> tuple[Callable[[bytes], bool], str, bytes]:
    """Return (evaluate, version, code_hash) for a registered predicate."""
    module_name = REGISTRY[predicate_id]
    mod = importlib.import_module(f"{__name__}.{module_name}")
    src = Path(mod.__file__).read_bytes()
    return mod.evaluate, mod.VERSION, hashlib.sha256(src).digest()
