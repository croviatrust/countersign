"""Ed25519 keys for operators, observers, witnesses and vendors."""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class SigningKey:
    id: str
    _private: Ed25519PrivateKey

    @classmethod
    def generate(cls, id: str) -> "SigningKey":
        return cls(id, Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, id: str, seed: bytes) -> "SigningKey":
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return cls(id, Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization
        raw = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return raw.hex()

    def pubkey_json(self) -> dict:
        return {"alg": "ed25519", "key_hex": self.public_hex}

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)


def verify_signature(public_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
