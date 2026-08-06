"""Ed25519 key management for witness identities.

A witness identity is a single Ed25519 keypair stored on disk:

- ``witness.key``  — 32-byte private seed, hex-encoded (keep secret)
- ``witness.pub``  — 32-byte public key, hex-encoded (publish freely)

The ``key_id`` is the first 16 hex chars of SHA-256(public key bytes) and
is embedded in every signed tree head so verifiers can pick the right key.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

PRIVATE_NAME = "witness.key"
PUBLIC_NAME = "witness.pub"


def key_id_of(public_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


@dataclass
class WitnessKey:
    """A loaded witness keypair (or public half only, for verification)."""

    public_hex: str
    _private: Ed25519PrivateKey | None = None

    @property
    def key_id(self) -> str:
        return key_id_of(self.public_hex)

    def can_sign(self) -> bool:
        return self._private is not None

    def sign(self, message: bytes) -> str:
        if self._private is None:
            raise RuntimeError("this key has no private half; cannot sign")
        return self._private.sign(message).hex()

    def verify(self, message: bytes, signature_hex: str) -> bool:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_hex))
        try:
            pub.verify(bytes.fromhex(signature_hex), message)
            return True
        except (InvalidSignature, ValueError):
            return False


def generate(key_dir: Path) -> WitnessKey:
    """Generate a keypair under *key_dir*. Refuses to overwrite existing keys."""
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / PRIVATE_NAME
    pub_path = key_dir / PUBLIC_NAME
    if priv_path.exists():
        raise FileExistsError(f"refusing to overwrite existing key: {priv_path}")

    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes_raw()
    public_hex = private.public_key().public_bytes_raw().hex()

    priv_path.write_text(seed.hex() + "\n", encoding="ascii")
    _restrict_permissions(priv_path)
    pub_path.write_text(public_hex + "\n", encoding="ascii")
    return WitnessKey(public_hex=public_hex, _private=private)


def load(key_dir: Path) -> WitnessKey:
    """Load a keypair. Falls back to public-only if the private key is absent."""
    pub_path = key_dir / PUBLIC_NAME
    priv_path = key_dir / PRIVATE_NAME
    if not pub_path.exists():
        raise FileNotFoundError(f"no public key at {pub_path}; run 'countersign init'")
    public_hex = pub_path.read_text(encoding="ascii").strip()

    private = None
    if priv_path.exists():
        seed = bytes.fromhex(priv_path.read_text(encoding="ascii").strip())
        private = Ed25519PrivateKey.from_private_bytes(seed)
        derived = private.public_key().public_bytes_raw().hex()
        if derived != public_hex:
            raise ValueError("witness.pub does not match witness.key")
    return WitnessKey(public_hex=public_hex, _private=private)


def public_only(public_hex: str) -> WitnessKey:
    return WitnessKey(public_hex=public_hex)


def _restrict_permissions(path: Path) -> None:
    """Best-effort owner-only permissions (no-op on filesystems without POSIX modes)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
