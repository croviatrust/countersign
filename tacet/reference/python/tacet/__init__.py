"""TACET reference implementation — verifiable silence for AI training disclosure.

See ../../SPEC.md. Public API:

    from tacet import SparseMerkleMap, target_key, build_sheet, build_snapshot,
                      build_silence_proof, verify_silence_proof, wrap_in_seal, verify_wrapped
"""
from .canonical import canonicalize, CanonicalizationError
from .hashing import EMPTY, object_hash, target_key, namespace_key, prefixed, unprefixed
from .keys import SigningKey, verify_signature
from .smt import SparseMerkleMap, CompactPath, verify_inclusion, verify_non_inclusion
from .epoch import build_sheet, close_sheet, validate_sheet, validate_chain, sheet_hash, witness_sign, witness_verify, SheetError
from .snapshot import build_snapshot, validate_snapshot, snapshot_hash, SnapshotError
from .silence import (build_silence_proof, verify_silence_proof, build_query, compute_silence,
                      SilenceVerifyResult, SilenceProofError,
                      STRENGTH_MAP, STRENGTH_SURFACE, STRENGTH_WITNESSED)
from .wrap import wrap_in_seal, verify_wrapped

__version__ = "0.4.0"
__all__ = [
    "canonicalize", "CanonicalizationError",
    "EMPTY", "object_hash", "target_key", "namespace_key", "prefixed", "unprefixed",
    "SigningKey", "verify_signature",
    "SparseMerkleMap", "CompactPath", "verify_inclusion", "verify_non_inclusion",
    "build_sheet", "close_sheet", "validate_sheet", "validate_chain", "sheet_hash", "witness_sign", "witness_verify", "SheetError",
    "build_snapshot", "validate_snapshot", "snapshot_hash", "SnapshotError",
    "build_silence_proof", "verify_silence_proof", "build_query", "compute_silence",
    "SilenceVerifyResult", "SilenceProofError", "STRENGTH_MAP", "STRENGTH_SURFACE", "STRENGTH_WITNESSED",
    "wrap_in_seal", "verify_wrapped",
]
