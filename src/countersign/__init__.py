"""Countersign — independent witnessing for AI agent evidence.

Self-signed audit logs prove nothing in a dispute: whoever holds the key
and the storage can rewrite history. Countersign adds the missing party —
an independent witness. Evidence digests are appended to a Merkle log
(RFC 6962 hashing), every tree head is Ed25519-signed, and any entry can
be exported as a self-contained proof bundle that verifies offline.

Public API:

- :class:`countersign.log.WitnessLog` — create, append, audit a witness log
- :func:`countersign.proof.build_proof` / :func:`countersign.proof.verify_proof`
- :mod:`countersign.adapters` — digest files and JSONL evidence streams
"""

from .log import WitnessLog, WitnessReceipt
from .proof import build_proof, verify_proof

__version__ = "0.1.0"

__all__ = ["WitnessLog", "WitnessReceipt", "build_proof", "verify_proof", "__version__"]
