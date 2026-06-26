"""PQC P3 — ``pqroute1`` metadata-sealing routing envelope.

This is **RFC-0001 P3** of the PQC-MIGRATION work. It composes the vetted Q1
primitive (:mod:`skcomms.pqkem`, ``x25519-mlkem768``) and the Q3 wrap idiom
(:mod:`skcomms.pqdm`) into a *routing* envelope that separates what a relay
needs to forward from what only the destination may read.

Why this beats a classical mix/relay layer
-------------------------------------------
A classical onion/mix relay protects routing metadata with classical public-key
crypto only, so a harvest-now-decrypt-later adversary that records every hop can
decrypt the sealed metadata once a cryptographically-relevant quantum computer
exists. ``pqroute1`` seals the inner metadata + content with the **hybrid**
X25519 + ML-KEM-768 KEM (FIPS 203, ML-KEM-768): the inner layer stays
confidential if *EITHER* the X25519 leg *or* the ML-KEM-768 leg holds. We make
no "quantum-proof" claim — the guarantee is hybrid: secure as long as one leg
survives.

The split
---------
``seal_routed`` produces::

    OUTER route header   -> plaintext, readable by an intermediate relay so it can
                            forward to the next hop (e.g. ``{"to_relay": "...",
                            "v": 1}``). It carries ONLY next-hop routing fields.
    INNER blob           -> the sensitive metadata (final destination, flags,
                            timestamps) + the content, hybrid-sealed to the
                            destination's prekey. A relay cannot read it.

Wire format (the interop contract)::

    blob = hdr_len(4, big-endian) || route_hdr_json(plaintext)
         || ct(1120) || nonce(12) || aesgcm(inner)            # the sealed inner

    inner (plaintext, before sealing) =
        meta_len(4, big-endian) || inner_metadata_json || content

The sealed inner reuses the :mod:`skcomms.pqdm` wrap exactly:

    ss        = hybrid_encap(dest_hybrid_pub)                 # X25519 || ML-KEM-768
    aad       = b"pqroute1" || canonical(route_hdr)           # binds the header
    wrap_key  = HKDF-SHA256(ss, salt=b"", info=_INFO_WRAP || aad)
    sealed    = ct || nonce || AES-256-GCM(wrap_key).encrypt(nonce, inner, aad)

Header authenticity (defence beyond confidentiality)
----------------------------------------------------
The outer route header is plaintext (a relay must read it) but it is folded into
the AEAD **AAD**, so it is *authenticated* end-to-end. A relay that rewrites the
next-hop field cannot do so silently: the destination reconstructs the AAD from
the header it actually receives, the AEAD fails to authenticate, and the open
raises :class:`PqRouteOpenError`. The header is therefore tamper-evident even
though it is not encrypted.

Honesty / fallback
------------------
Hybrid sealing only. If liboqs is missing the underlying KEM raises loudly
(:class:`skcomms.pqkem.PqKemUnavailable`); this module never silently downgrades
to a classical-only routing layer.

CLEAN-ROOM: the routing-split *idea* is inspired by mix/relay designs (incl.
SimpleX) but no third-party code was used — only the SK primitives above.
"""

from __future__ import annotations

import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .pqkem import (
    CIPHERTEXT_LEN as HYBRID_CIPHERTEXT_LEN,
)
from .pqkem import (
    PUBLIC_KEY_LEN as HYBRID_PUBLIC_KEY_LEN,
)
from .pqkem import (
    PqKemError,
    hybrid_decap,
    hybrid_encap,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The routing-envelope suite id (bound into the AEAD AAD).
ROUTE_SUITE = "pqroute1"

#: HKDF domain-separation label for the routing-inner wrap key (distinct from
#: pqdm's DM/envelope-wrap label and group_ratchet's epoch-wrap label).
_INFO_WRAP = b"skcomms/pqroute/wrap/v1"

_LEN_PREFIX = 4  # bytes for both hdr_len and meta_len (big-endian uint32)
_WRAP_NONCE_LEN = 12
_AESGCM_TAG_LEN = 16

#: Minimum sealed-inner size = ct + nonce + tag (empty inner plaintext is still
#: 4 bytes of meta_len, so the true floor is a touch larger; this is the AEAD
#: floor used for length validation).
_SEALED_MIN_LEN = HYBRID_CIPHERTEXT_LEN + _WRAP_NONCE_LEN + _AESGCM_TAG_LEN


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PqRouteError(Exception):
    """Base error for the pqroute1 routing envelope."""


class PqRouteFormatError(PqRouteError, ValueError):
    """Malformed envelope / wrong-length key (never a crash)."""


class PqRouteOpenError(PqRouteError):
    """Raised when opening fails — wrong key, tampered inner, or a rewritten
    (AAD-bound) route header. A security event, not a retry signal."""


# ---------------------------------------------------------------------------
# Canonicalisation + AAD
# ---------------------------------------------------------------------------


def _canonical(obj: dict) -> bytes:
    """Deterministic, canonical JSON encoding (sorted keys, tight separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _aad(route_hdr_canonical: bytes) -> bytes:
    """AEAD AAD = suite id || canonical route header (binds + tamper-evidences)."""
    return ROUTE_SUITE.encode("ascii") + b"|" + route_hdr_canonical


def _wrap_key(shared: bytes, aad: bytes) -> bytes:
    """Derive the AES-256 wrap key from the hybrid shared secret + AAD."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=_INFO_WRAP + b"|" + aad,
    ).derive(shared)


# ---------------------------------------------------------------------------
# Seal / open (the only original crypto — wiring pqkem + AES-256-GCM + HKDF)
# ---------------------------------------------------------------------------


def seal_routed(
    inner_metadata: dict,
    content: bytes,
    dest_hybrid_pub: bytes,
    *,
    route_hdr: dict,
) -> bytes:
    """Build a ``pqroute1`` envelope: plaintext route header + sealed inner.

    Args:
        inner_metadata: Sensitive metadata (final destination, flags, timestamps,
            ...) sealed to the destination. JSON-serialisable.
        content: The message body bytes (also sealed).
        dest_hybrid_pub: The destination's 1216-byte hybrid public key (prekey).
        route_hdr: The OUTER routing header — only next-hop routing fields, e.g.
            ``{"to_relay": "...", "v": 1}``. Stays plaintext (a relay reads it)
            but is AEAD-bound so it is tamper-evident. JSON-serialisable.

    Returns:
        ``hdr_len(4) || route_hdr_json || ct(1120) || nonce(12) || aesgcm(inner)``.

    Raises:
        PqRouteFormatError: if ``dest_hybrid_pub`` is the wrong length or the
            headers are not JSON-serialisable.
        PqKemError / PqKemUnavailable: propagated from the KEM (missing liboqs is
            a hard error — never a silent classical downgrade).
    """
    if not isinstance(dest_hybrid_pub, (bytes, bytearray)):
        raise PqRouteFormatError(
            f"dest_hybrid_pub must be bytes, got {type(dest_hybrid_pub).__name__}"
        )
    if len(dest_hybrid_pub) != HYBRID_PUBLIC_KEY_LEN:
        raise PqRouteFormatError(
            f"dest_hybrid_pub must be {HYBRID_PUBLIC_KEY_LEN} bytes, "
            f"got {len(dest_hybrid_pub)}"
        )
    try:
        route_bytes = _canonical(route_hdr)
        meta_bytes = _canonical(inner_metadata)
    except (TypeError, ValueError) as exc:
        raise PqRouteFormatError(f"header not JSON-serialisable: {exc}") from exc

    inner = struct.pack(">I", len(meta_bytes)) + meta_bytes + bytes(content)

    aad = _aad(route_bytes)
    try:
        ciphertext, shared = hybrid_encap(bytes(dest_hybrid_pub))
    except PqKemError as exc:
        raise PqRouteFormatError(f"hybrid encapsulation failed: {exc}") from exc
    wrap_key = _wrap_key(shared, aad)
    nonce = os.urandom(_WRAP_NONCE_LEN)
    sealed_inner = AESGCM(wrap_key).encrypt(nonce, inner, aad)

    return (
        struct.pack(">I", len(route_bytes))
        + route_bytes
        + ciphertext
        + nonce
        + sealed_inner
    )


def read_route_header(blob: bytes) -> dict:
    """Parse + return ONLY the outer routing header (what a relay reads).

    Does no decryption: an intermediate relay calls this to learn the next hop.
    The sealed inner (metadata + content) is opaque to it.

    Raises:
        PqRouteFormatError: if the blob is too short / the header isn't valid JSON.
    """
    route_bytes, _ = _split_outer(blob)
    try:
        return json.loads(route_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PqRouteFormatError(f"route header not valid JSON: {exc}") from exc


def replace_route_header(blob: bytes, new_route_hdr: dict) -> bytes:
    """Return a blob with the outer header replaced, sealed inner untouched.

    Models a relay rewriting the next-hop field. The new header is NOT re-bound to
    the sealed inner, so :func:`open_routed` at the destination will reject it
    (AEAD AAD mismatch) — this is exactly the tamper-evidence property. Provided
    as a test/inspection helper, not a production path.
    """
    _, sealed_inner = _split_outer(blob)
    try:
        route_bytes = _canonical(new_route_hdr)
    except (TypeError, ValueError) as exc:
        raise PqRouteFormatError(f"header not JSON-serialisable: {exc}") from exc
    return struct.pack(">I", len(route_bytes)) + route_bytes + sealed_inner


def open_routed(blob: bytes, dest_hybrid_priv: bytes) -> tuple[dict, dict, bytes]:
    """Open a ``pqroute1`` envelope with the destination's hybrid private key.

    Reconstructs the AEAD AAD from the route header actually present in the blob;
    a rewritten header (or any tamper) fails the AEAD open.

    Args:
        blob: The envelope from :func:`seal_routed`.
        dest_hybrid_priv: The destination's 2432-byte hybrid private key.

    Returns:
        ``(route_hdr, inner_metadata, content)``.

    Raises:
        PqRouteFormatError: on malformed input.
        PqRouteOpenError: if the AEAD open fails (wrong key, tampered inner, or a
            rewritten route header).
        PqKemError / PqKemUnavailable: propagated from the KEM.
    """
    route_bytes, sealed_inner = _split_outer(blob)
    if len(sealed_inner) < _SEALED_MIN_LEN:
        raise PqRouteFormatError(
            f"sealed inner must be >= {_SEALED_MIN_LEN} bytes, got {len(sealed_inner)}"
        )
    try:
        route_hdr = json.loads(route_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PqRouteFormatError(f"route header not valid JSON: {exc}") from exc

    ciphertext = sealed_inner[:HYBRID_CIPHERTEXT_LEN]
    nonce = sealed_inner[
        HYBRID_CIPHERTEXT_LEN : HYBRID_CIPHERTEXT_LEN + _WRAP_NONCE_LEN
    ]
    body = sealed_inner[HYBRID_CIPHERTEXT_LEN + _WRAP_NONCE_LEN :]

    aad = _aad(route_bytes)
    try:
        shared = hybrid_decap(bytes(ciphertext), bytes(dest_hybrid_priv))
    except PqKemError as exc:
        # A failed decap at open time = the envelope can't be opened with this key
        # (wrong/invalid private key). A relay holding the blob but no dest key
        # lands here. Treat as an open failure, not a blob-format error.
        raise PqRouteOpenError(f"hybrid decapsulation failed: {exc}") from exc
    wrap_key = _wrap_key(shared, aad)
    try:
        inner = AESGCM(wrap_key).decrypt(bytes(nonce), bytes(body), aad)
    except Exception as exc:  # GCM auth failure / wrong key / rewritten header
        raise PqRouteOpenError(
            "pqroute1 open failed — wrong key, tampered inner, or a rewritten "
            f"route header (the header is AEAD-bound): {exc}"
        ) from exc

    if len(inner) < _LEN_PREFIX:
        raise PqRouteOpenError("decrypted inner is truncated")
    (meta_len,) = struct.unpack(">I", inner[:_LEN_PREFIX])
    if _LEN_PREFIX + meta_len > len(inner):
        raise PqRouteOpenError("decrypted inner metadata length is out of range")
    meta_bytes = inner[_LEN_PREFIX : _LEN_PREFIX + meta_len]
    content = inner[_LEN_PREFIX + meta_len :]
    try:
        inner_metadata = json.loads(meta_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PqRouteOpenError(f"inner metadata not valid JSON: {exc}") from exc

    return route_hdr, inner_metadata, content


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_outer(blob: bytes) -> tuple[bytes, bytes]:
    """Split ``hdr_len || route_hdr || sealed_inner`` -> (route_bytes, sealed)."""
    if not isinstance(blob, (bytes, bytearray)):
        raise PqRouteFormatError(f"blob must be bytes, got {type(blob).__name__}")
    if len(blob) < _LEN_PREFIX:
        raise PqRouteFormatError("blob too short for a route-header length prefix")
    (hdr_len,) = struct.unpack(">I", blob[:_LEN_PREFIX])
    start = _LEN_PREFIX
    end = start + hdr_len
    if end > len(blob):
        raise PqRouteFormatError("route header length exceeds blob size")
    return bytes(blob[start:end]), bytes(blob[end:])
