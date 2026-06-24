"""Pluggable hybrid-KEM backend abstraction (PQC-MIGRATION Q1, §4.3).

The architecture mandates routing all KEM operations through one internal
interface so hybrid and classical can coexist during rollout (plan §4.3
"Backend abstraction"). This module defines a small KEM-shaped ABC,
:class:`HybridKemBackend`, that mirrors capauth's ``CryptoBackend`` pattern but
for key *encapsulation* rather than signing.

The default concrete backend, :class:`LiboqsHybridKemBackend`, binds the verified
``pqkem`` primitive (X25519 + ML-KEM-768 via liboqs). New suites (e.g. a future
HQC backup KEM, or ML-KEM-1024 for the CNSA-2.0 ceiling) become *new backend
classes selected by suite id* — never a hard-coded fork in caller code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from . import pqkem


@dataclass(frozen=True)
class KemKeyPair:
    """Backend-agnostic hybrid keypair (raw wire bytes)."""

    public_key: bytes
    private_key: bytes


class HybridKemBackend(ABC):
    """Abstract KEM backend — one interface for every (hybrid) KEM suite.

    Implementations encapsulate a single suite. The suite id they advertise
    MUST match an entry in :mod:`skcomms.crypto_suites`. This is the seam that
    Q2/Q3/Q4 plug into; it keeps algorithm choice config-driven (policy) and out
    of the call sites (mechanism), per NIST CSWP 39.
    """

    #: Registry suite id this backend implements (e.g. ``"x25519-mlkem768"``).
    suite_id: str = ""

    @abstractmethod
    def available(self) -> bool:
        """Whether this backend's dependencies (e.g. liboqs) are usable."""

    @abstractmethod
    def generate_keypair(self) -> KemKeyPair:
        """Generate a fresh keypair on the wire format for this suite."""

    @abstractmethod
    def encapsulate(self, peer_public_key: bytes, info: bytes = b"") -> tuple[bytes, bytes]:
        """Encapsulate to ``peer_public_key`` -> ``(ciphertext, shared_secret)``."""

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, private_key: bytes, info: bytes = b"") -> bytes:
        """Decapsulate ``ciphertext`` with ``private_key`` -> ``shared_secret``."""


class LiboqsHybridKemBackend(HybridKemBackend):
    """X25519 + ML-KEM-768 hybrid KEM backed by :mod:`skcomms.pqkem` (liboqs).

    This is the **default active** KEM backend for the ``x25519-mlkem768`` suite.
    It performs no crypto of its own — it delegates to the verified ``pqkem``
    functions, which bind liboqs (ML-KEM) + pyca (X25519/HKDF).
    """

    suite_id = pqkem.SUITE_ID

    def available(self) -> bool:
        return pqkem.is_available()

    def generate_keypair(self) -> KemKeyPair:
        kp = pqkem.hybrid_keypair()
        return KemKeyPair(public_key=kp.public_key, private_key=kp.private_key)

    def encapsulate(
        self, peer_public_key: bytes, info: bytes = pqkem.HKDF_INFO
    ) -> tuple[bytes, bytes]:
        return pqkem.hybrid_encap(peer_public_key, info=info)

    def decapsulate(
        self, ciphertext: bytes, private_key: bytes, info: bytes = pqkem.HKDF_INFO
    ) -> bytes:
        return pqkem.hybrid_decap(ciphertext, private_key, info=info)


#: Map of suite_id -> KEM backend instance. Selection is by suite id only —
#: callers never branch on the concrete class.
_KEM_BACKENDS: dict[str, HybridKemBackend] = {
    LiboqsHybridKemBackend.suite_id: LiboqsHybridKemBackend(),
}


def get_kem_backend(suite_id: str = pqkem.SUITE_ID) -> HybridKemBackend:
    """Return the KEM backend for ``suite_id``.

    Raises:
        KeyError: if no backend is registered for ``suite_id``.
    """
    try:
        return _KEM_BACKENDS[suite_id]
    except KeyError as exc:
        raise KeyError(
            f"no hybrid-KEM backend registered for suite {suite_id!r}; "
            f"known: {sorted(_KEM_BACKENDS)}"
        ) from exc


def register_kem_backend(backend: HybridKemBackend) -> HybridKemBackend:
    """Register (or replace) a KEM backend by its ``suite_id``."""
    if not backend.suite_id:
        raise ValueError("backend.suite_id must be set")
    _KEM_BACKENDS[backend.suite_id] = backend
    return backend
