"""Hybrid post-quantum key encapsulation — **X25519 + ML-KEM-768**.

This is **Phase 1 / Q1** of the PQC-MIGRATION epic (coord ``e1d6ba2a``; plan
``skchat/docs/quantum-resistance-architecture.md`` §3 S4-S7 / §4 / §6 Q1). It
delivers *one vetted hybrid-KEM primitive* — the building block that Q2 (group
epoch ratchet), Q3 (envelope/DM confidentiality) and Q4 (at-rest wrap) compose
on top of. **This module does not wire itself into group.py / envelope.py.**

Suite id: ``x25519-mlkem768`` — the same construction as TLS ``X25519MLKEM768``
and Signal PQXDH. It is byte-for-byte interoperable with the ``sk_pqc`` Dart
package (cross-impl vector ``sk_pqc/test_vectors/hybrid_kem_x25519_mlkem768.json``).

GOLDEN RULE — we never implement the lattice or curve math:
    * **ML-KEM-768** leg  -> ``oqs.KeyEncapsulation("ML-KEM-768")`` (binds liboqs,
      FIPS 203 with implicit rejection).
    * **X25519** leg      -> ``cryptography`` (pyca) X25519, used as an
      ephemeral-static DHKEM (as in HPKE / TLS).
    * **combiner**        -> ``cryptography`` HKDF-SHA256 (RFC 5869).

The *only* original cryptographic code is the combiner wiring::

    shared_secret = HKDF-SHA256(
        IKM  = X25519_ss || MLKEM768_ss,     # X25519 FIRST, then ML-KEM
        salt = b"",                          # RFC 5869: HashLen zero bytes
        info = b"sk_pqc/x25519-mlkem768/v1",
        L    = 32,
    )

Wire format — the interop contract (lengths are fixed, MUST NOT change)::

    public key  = X25519_pub(32)            || MLKEM768_pub(1184)    = 1216 B
    private key = X25519_priv_seed(32)      || MLKEM768_secret(2400) = 2432 B
    ciphertext  = X25519_ephemeral_pub(32)  || MLKEM768_ct(1088)     = 1120 B
    shared secret = 32 B

**Concatenate-then-KDF. Never XOR. Never pure-PQ.** The derived secret is secure
if *either* X25519 or ML-KEM-768 holds.

Honesty / fallback: if ``oqs`` (liboqs-python) is unavailable this module raises
:class:`PqKemUnavailable` loudly. It NEVER silently downgrades to classical-only
— a missing PQ binary is a hard error, not a degraded-but-quiet success. Callers
that want a classical fallback must select a classical suite explicitly via the
registry (``crypto_suites.py``), not by accident.

liboqs lookup: ``oqs`` 0.15.x will, by default, try to *build* liboqs from source
into ``~/_oqs`` if it cannot find a system copy. To use a prebuilt shared library
(e.g. the one at ``~/.local/lib/liboqs.so``), set ``OQS_INSTALL_PATH`` (and/or
``LD_LIBRARY_PATH``) to its prefix *before import*. See the module-level
``ensure_liboqs_path()`` helper which applies this best-effort.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Interop constants — DO NOT CHANGE (pinned by the sk_pqc cross-impl vector).
# ---------------------------------------------------------------------------

SUITE_ID = "x25519-mlkem768"
MLKEM_ALG = "ML-KEM-768"

#: HKDF parameters (RFC 5869). ``salt`` empty -> HashLen zero bytes.
HKDF_SALT = b""
HKDF_INFO = b"sk_pqc/x25519-mlkem768/v1"
SHARED_SECRET_LEN = 32

# Fixed leg sizes (bytes).
X25519_PUB_LEN = 32
X25519_SEED_LEN = 32
MLKEM_PUB_LEN = 1184
MLKEM_SECRET_LEN = 2400
MLKEM_CT_LEN = 1088

# Composite wire sizes.
PUBLIC_KEY_LEN = X25519_PUB_LEN + MLKEM_PUB_LEN       # 1216
PRIVATE_KEY_LEN = X25519_SEED_LEN + MLKEM_SECRET_LEN  # 2432
CIPHERTEXT_LEN = X25519_PUB_LEN + MLKEM_CT_LEN        # 1120


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PqKemError(Exception):
    """Base error for the hybrid KEM helper."""


class PqKemUnavailable(PqKemError):  # noqa: N818 — deliberate name (not *Error)
    """Raised when the post-quantum backend (liboqs via ``oqs``) is missing.

    Deliberately a *hard* error: we never silently fall back to classical-only
    key exchange. A caller that wants classical crypto must select a classical
    suite explicitly.
    """


class PqKemFormatError(PqKemError, ValueError):
    """Raised on malformed/wrong-length keys or ciphertext (never a crash)."""


# ---------------------------------------------------------------------------
# liboqs discovery + lazy import
# ---------------------------------------------------------------------------


def ensure_liboqs_path() -> None:
    """Best-effort: point ``oqs`` at a prebuilt liboqs so it doesn't self-build.

    ``oqs`` 0.15.x auto-clones+builds liboqs into ``~/_oqs`` when it can't find
    one. If a prebuilt ``liboqs.so`` exists under a known prefix and the env var
    isn't already set, export ``OQS_INSTALL_PATH`` (oqs honours this) so import
    is fast and deterministic. Idempotent; never raises.
    """
    if os.environ.get("OQS_INSTALL_PATH"):
        return
    candidates = []
    sk_lib = os.environ.get("SK_PQC_LIBOQS")
    if sk_lib:
        candidates.append(Path(sk_lib).parent.parent)
    candidates += [Path.home() / ".local", Path("/usr/local"), Path("/usr")]
    for prefix in candidates:
        libdir = prefix / "lib"
        if any(
            (libdir / name).exists()
            for name in ("liboqs.so", "liboqs.so.8", "liboqs.dylib")
        ):
            os.environ["OQS_INSTALL_PATH"] = str(prefix)
            existing = os.environ.get("LD_LIBRARY_PATH", "")
            if str(libdir) not in existing.split(os.pathsep):
                os.environ["LD_LIBRARY_PATH"] = (
                    f"{libdir}{os.pathsep}{existing}" if existing else str(libdir)
                )
            return


def _import_oqs():
    """Import ``oqs`` lazily, raising :class:`PqKemUnavailable` if missing."""
    ensure_liboqs_path()
    try:
        import oqs  # type: ignore
    except Exception as exc:  # ImportError or liboqs load/build failure
        raise PqKemUnavailable(
            "Post-quantum KEM backend unavailable: could not import 'oqs' "
            "(liboqs-python). Install with `pip install liboqs-python` and ensure "
            "a liboqs shared library is reachable (e.g. ~/.local/lib/liboqs.so; "
            "set OQS_INSTALL_PATH or SK_PQC_LIBOQS). This is a hard error — the "
            f"hybrid KEM never silently downgrades to classical-only. ({exc})"
        ) from exc
    return oqs


def is_available() -> bool:
    """Return True iff the PQ backend (liboqs via ``oqs``) can be imported."""
    try:
        _import_oqs()
        return True
    except PqKemUnavailable:
        return False


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HybridKeyPair:
    """A hybrid keypair on the wire.

    Attributes:
        public_key: 1216-byte X25519_pub || MLKEM768_pub.
        private_key: 2432-byte X25519_seed || MLKEM768_secret.
    """

    public_key: bytes
    private_key: bytes


# ---------------------------------------------------------------------------
# Internal HKDF combiner (the only original crypto)
# ---------------------------------------------------------------------------


def _combine(x25519_ss: bytes, mlkem_ss: bytes, info: bytes = HKDF_INFO) -> bytes:
    """Concat-then-KDF combiner. X25519 secret FIRST, then ML-KEM secret.

    ``shared = HKDF-SHA256(x25519_ss || mlkem_ss, salt=b"", info=info, L=32)``.
    """
    ikm = bytes(x25519_ss) + bytes(mlkem_ss)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SHARED_SECRET_LEN,
        salt=HKDF_SALT,
        info=info,
    ).derive(ikm)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def hybrid_keypair() -> HybridKeyPair:
    """Generate a fresh hybrid keypair.

    Returns:
        HybridKeyPair with the 1216-byte public key and 2432-byte private key
        laid out as ``X25519_part || MLKEM768_part``.

    Raises:
        PqKemUnavailable: if the liboqs/``oqs`` backend is missing.
    """
    oqs = _import_oqs()

    x_priv = X25519PrivateKey.generate()
    x_seed = x_priv.private_bytes_raw()
    x_pub = x_priv.public_key().public_bytes_raw()

    with oqs.KeyEncapsulation(MLKEM_ALG) as kem:
        mlkem_pub = kem.generate_keypair()
        mlkem_secret = kem.export_secret_key()

    _expect_len("ML-KEM public key", mlkem_pub, MLKEM_PUB_LEN)
    _expect_len("ML-KEM secret key", mlkem_secret, MLKEM_SECRET_LEN)

    return HybridKeyPair(
        public_key=bytes(x_pub) + bytes(mlkem_pub),
        private_key=bytes(x_seed) + bytes(mlkem_secret),
    )


def hybrid_encap(peer_public_key: bytes, info: bytes = HKDF_INFO) -> tuple[bytes, bytes]:
    """Encapsulate to a peer's hybrid public key.

    The X25519 leg is ephemeral-static DHKEM: a fresh ephemeral X25519 keypair is
    generated, ``DH(eph_priv, peer_static_pub)`` is the X25519 shared secret, and
    the ephemeral public key is shipped as the 32-byte X25519 "ciphertext".

    Args:
        peer_public_key: 1216-byte hybrid public key.
        info: HKDF ``info`` for domain separation (default the suite label).

    Returns:
        ``(ciphertext, shared_secret)`` — ciphertext is 1120 bytes
        (X25519_ephemeral_pub || MLKEM768_ct), shared_secret is 32 bytes.

    Raises:
        PqKemFormatError: if ``peer_public_key`` is malformed.
        PqKemUnavailable: if the liboqs/``oqs`` backend is missing.
    """
    oqs = _import_oqs()
    _expect_len("hybrid public key", peer_public_key, PUBLIC_KEY_LEN)

    x_peer_pub = bytes(peer_public_key[:X25519_PUB_LEN])
    mlkem_peer_pub = bytes(peer_public_key[X25519_PUB_LEN:])

    # X25519 ephemeral-static DH.
    try:
        x_peer = X25519PublicKey.from_public_bytes(x_peer_pub)
    except Exception as exc:
        raise PqKemFormatError(f"invalid X25519 public key: {exc}") from exc
    x_eph = X25519PrivateKey.generate()
    x_eph_pub = x_eph.public_key().public_bytes_raw()
    x_ss = x_eph.exchange(x_peer)

    # ML-KEM encapsulation.
    with oqs.KeyEncapsulation(MLKEM_ALG) as kem:
        try:
            mlkem_ct, mlkem_ss = kem.encap_secret(mlkem_peer_pub)
        except Exception as exc:
            raise PqKemFormatError(f"ML-KEM encapsulation failed: {exc}") from exc
    _expect_len("ML-KEM ciphertext", mlkem_ct, MLKEM_CT_LEN)

    ciphertext = bytes(x_eph_pub) + bytes(mlkem_ct)
    shared = _combine(x_ss, mlkem_ss, info=info)
    return ciphertext, shared


def hybrid_decap(
    ciphertext: bytes, private_key: bytes, info: bytes = HKDF_INFO
) -> bytes:
    """Decapsulate a hybrid ciphertext with the recipient's private key.

    Args:
        ciphertext: 1120-byte X25519_ephemeral_pub || MLKEM768_ct.
        private_key: 2432-byte X25519_seed || MLKEM768_secret.
        info: HKDF ``info`` (must match the encapsulator's).

    Returns:
        The 32-byte hybrid shared secret. ML-KEM uses implicit rejection: a
        tampered ML-KEM ciphertext does NOT raise — it yields a pseudo-random
        secret that simply won't match the sender's. (Wrong *length* still
        raises :class:`PqKemFormatError`.)

    Raises:
        PqKemFormatError: if ``ciphertext`` or ``private_key`` is the wrong size.
        PqKemUnavailable: if the liboqs/``oqs`` backend is missing.
    """
    oqs = _import_oqs()
    _expect_len("hybrid ciphertext", ciphertext, CIPHERTEXT_LEN)
    _expect_len("hybrid private key", private_key, PRIVATE_KEY_LEN)

    x_eph_pub = bytes(ciphertext[:X25519_PUB_LEN])
    mlkem_ct = bytes(ciphertext[X25519_PUB_LEN:])

    x_seed = bytes(private_key[:X25519_SEED_LEN])
    mlkem_secret = bytes(private_key[X25519_SEED_LEN:])

    # X25519 leg: DH(static_priv, ephemeral_pub).
    try:
        x_priv = X25519PrivateKey.from_private_bytes(x_seed)
        x_ss = x_priv.exchange(X25519PublicKey.from_public_bytes(x_eph_pub))
    except Exception as exc:
        raise PqKemFormatError(f"invalid X25519 key material: {exc}") from exc

    # ML-KEM leg: decapsulate (implicit rejection — never raises on tamper).
    with oqs.KeyEncapsulation(MLKEM_ALG, secret_key=mlkem_secret) as kem:
        try:
            mlkem_ss = kem.decap_secret(mlkem_ct)
        except Exception as exc:
            raise PqKemFormatError(f"ML-KEM decapsulation failed: {exc}") from exc

    return _combine(x_ss, mlkem_ss, info=info)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expect_len(label: str, value: bytes, expected: int) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise PqKemFormatError(f"{label} must be bytes, got {type(value).__name__}")
    if len(value) != expected:
        raise PqKemFormatError(f"{label} must be {expected} bytes, got {len(value)}")
