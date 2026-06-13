"""Bind a capauth/fqid identity to its BLE mesh keypair (spec §5).

- Ed25519 signing key  → signs ANNOUNCE/packets.
- X25519 (Curve25519) static key → Noise_XX static identity.
- fingerprint = SHA-256(noise static pubkey).hex  (TOFU id, matches pairing.py).
- id_hash(fqid) = SHA-256(fqid)[:8]  (the 8-byte wire sender/recipient id).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def id_hash(fqid: str) -> bytes:
    return hashlib.sha256(fqid.encode()).digest()[:8]


def fingerprint_of(noise_static_pub: bytes) -> str:
    return hashlib.sha256(noise_static_pub).hexdigest()


def _x_raw_pub(k: X25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _ed_raw_pub(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass
class MeshIdentity:
    fqid: str
    _ed_priv: Ed25519PrivateKey
    _x_priv: X25519PrivateKey

    @classmethod
    def generate(cls, fqid: str) -> "MeshIdentity":
        return cls(fqid=fqid, _ed_priv=Ed25519PrivateKey.generate(),
                   _x_priv=X25519PrivateKey.generate())

    @property
    def ed25519_pub(self) -> bytes:
        return _ed_raw_pub(self._ed_priv)

    @property
    def noise_static_pub(self) -> bytes:
        return _x_raw_pub(self._x_priv)

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.noise_static_pub)

    @property
    def my_id(self) -> bytes:
        return id_hash(self.fqid)

    def noise_static_private_bytes(self) -> bytes:
        return self._x_priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, data: bytes) -> bytes:
        return self._ed_priv.sign(data)

    @staticmethod
    def verify(ed_pub: bytes, data: bytes, sig: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, data)
            return True
        except InvalidSignature:
            return False
