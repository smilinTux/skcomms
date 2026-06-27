"""PQC P3 wiring — flag-gated transport wrapper around ``pqroute1``.

This module wires the vetted :mod:`skcomms.pqroute` metadata-sealing envelope
into the **outbound transport path** as an *additive, flag-gated* layer. It
adds no new crypto — it composes :func:`skcomms.pqroute.seal_routed` /
:func:`~skcomms.pqroute.open_routed` (X25519 + ML-KEM-768 hybrid KEM, HKDF,
AES-256-GCM) with the canonical :class:`skcomms.envelope.SignedEnvelope`.

What it buys (vs a classical relay layer)
-----------------------------------------
A classical onion/mix relay protects routing metadata with classical public-key
crypto only, so a harvest-now-decrypt-later adversary that records every hop can
later decrypt the *final destination* once a cryptographically-relevant quantum
computer exists. Here, when the wrapper is enabled, the **final destination FQID
and flags** plus the whole signed envelope move into the hybrid-sealed INNER
blob; only a minimal next-hop header (``{"to_relay": ..., "v": 1}``) stays
outer/relay-readable. The inner stays confidential if EITHER the X25519 leg or
the ML-KEM-768 leg holds (FIPS 203). We make NO "quantum-proof" claim — the
guarantee is hybrid (either-leg).

The flag gate (default OFF -> byte-identical to today)
------------------------------------------------------
Enabling is opt-in and gated two ways (override beats env):

    * per-send ``enabled=True`` (or ``False``) argument, OR
    * the ``SKCOMMS_PQROUTE`` environment variable (``1``/``true``/``yes``/``on``).

When the wrapper is OFF **or** no destination hybrid prekey is available, the
returned wire bytes are EXACTLY ``SignedEnvelope.to_bytes()`` — byte-for-byte
identical to today (honest fallback; never a silent classical "pqroute" that
isn't actually sealed). Only when ON *and* a prekey is present do we emit the
framed pqroute1 blob (prefixed with :data:`PQROUTE_MAGIC` so a receiver can
cleanly distinguish a wrapped blob from a plain JSON SignedEnvelope).

Wire framing (wrapped form only)::

    PQROUTE_MAGIC || pqroute1_blob
        where pqroute1_blob = hdr_len(4) || route_hdr_json || ct || nonce || sealed

The unwrapped form is just the plain ``SignedEnvelope`` JSON bytes (no magic).
"""

from __future__ import annotations

import os
from typing import Optional

from .envelope import SignedEnvelope
from .pqroute import (
    PqRouteFormatError,
    open_routed,
    read_route_header,
    seal_routed,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Environment variable that opts the whole process into pqroute wrapping.
PQROUTE_ENV = "SKCOMMS_PQROUTE"

#: Magic prefix that marks a wrapped (pqroute1) wire blob. Distinguishes it from
#: a plain ``SignedEnvelope`` JSON document (which starts with ``{``). The NUL
#: keeps it out of the JSON/text space so detection is unambiguous.
PQROUTE_MAGIC = b"SKCPQR1\x00"

#: Routing-envelope wire version carried in the outer next-hop header.
_ROUTE_HDR_VERSION = 1

_TRUTHY = {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Flag gate
# ---------------------------------------------------------------------------


def pqroute_enabled(override: Optional[bool] = None) -> bool:
    """Whether transport-level pqroute wrapping is enabled.

    Resolution order (first that applies wins):
        1. ``override`` — an explicit per-send ``True``/``False`` (when not None).
        2. the ``SKCOMMS_PQROUTE`` env var (``1``/``true``/``yes``/``on`` => on).

    Default (no override, env unset/falsey) is **OFF** — the additive guarantee.
    """
    if override is not None:
        return bool(override)
    return os.environ.get(PQROUTE_ENV, "").strip().lower() in _TRUTHY


# ---------------------------------------------------------------------------
# Detection / relay read
# ---------------------------------------------------------------------------


def is_pqrouted(wire: bytes) -> bool:
    """True iff ``wire`` is a pqroute1-wrapped blob (carries the magic prefix)."""
    return isinstance(wire, (bytes, bytearray)) and bytes(wire[: len(PQROUTE_MAGIC)]) == PQROUTE_MAGIC


def read_next_hop(wire: bytes) -> dict:
    """Return ONLY the outer next-hop header — what an intermediate relay reads.

    Does no decryption: the sealed inner (final destination + flags + the signed
    envelope) stays opaque to the relay.

    Raises:
        PqRouteFormatError: if ``wire`` is not a pqroute1-wrapped blob or the
            header is malformed.
    """
    if not is_pqrouted(wire):
        raise PqRouteFormatError("not a pqroute1-wrapped blob (missing magic)")
    return read_route_header(bytes(wire)[len(PQROUTE_MAGIC):])


# ---------------------------------------------------------------------------
# Wrap (outbound) / unwrap (at the destination)
# ---------------------------------------------------------------------------


def wrap_signed(
    signed: SignedEnvelope,
    *,
    next_hop: str,
    dest_hybrid_pub: Optional[bytes] = None,
    enabled: Optional[bool] = None,
    flags: Optional[list] = None,
    extra_inner_meta: Optional[dict] = None,
) -> bytes:
    """Produce the outbound wire bytes for a :class:`SignedEnvelope`.

    Default OFF (or no prekey) -> returns ``signed.to_bytes()`` byte-for-byte
    identical to today. ON *and* a ``dest_hybrid_pub`` present -> returns a
    framed pqroute1 blob where the FINAL destination FQID + flags + the whole
    signed envelope are hybrid-sealed inside, and only ``next_hop`` is outer.

    Args:
        signed: The canonical signed envelope to put on the wire.
        next_hop: The relay/next-hop address that stays outer (relay-readable).
        dest_hybrid_pub: The FINAL destination's 1216-byte hybrid public key
            (prekey). Required to seal; if ``None`` the classical byte-identical
            path is kept (honest fallback).
        enabled: Per-send override of the flag gate (see :func:`pqroute_enabled`).
        flags: Optional sensitive routing flags sealed into the inner metadata.
        extra_inner_meta: Optional extra sensitive fields merged into the sealed
            inner metadata (e.g. timestamps). Never relay-visible.

    Returns:
        Wire bytes — plain ``SignedEnvelope`` JSON (OFF) or ``PQROUTE_MAGIC ||
        pqroute1_blob`` (ON).
    """
    if not pqroute_enabled(enabled) or not dest_hybrid_pub:
        # Default / honest-fallback path: nothing new on the wire.
        return signed.to_bytes()

    inner_meta = {
        "final_dest": signed.envelope.to_fqid,
        "flags": list(flags or []),
    }
    if extra_inner_meta:
        inner_meta.update(extra_inner_meta)

    route_hdr = {"to_relay": next_hop, "v": _ROUTE_HDR_VERSION}
    blob = seal_routed(
        inner_meta,
        signed.to_bytes(),
        bytes(dest_hybrid_pub),
        route_hdr=route_hdr,
    )
    return PQROUTE_MAGIC + blob


def unwrap_signed(
    wire: bytes, dest_hybrid_priv: bytes
) -> tuple[dict, SignedEnvelope]:
    """Open a wrapped wire blob at the FINAL destination.

    Args:
        wire: A pqroute1-wrapped blob (``PQROUTE_MAGIC || pqroute1_blob``).
        dest_hybrid_priv: The destination's 2432-byte hybrid private key.

    Returns:
        ``(inner_metadata, SignedEnvelope)`` — the sealed sensitive metadata
        (``final_dest`` + ``flags`` + any extras) and the recovered signed
        envelope (byte-for-byte the original).

    Raises:
        PqRouteFormatError: if ``wire`` is not a wrapped blob / is malformed.
        PqRouteOpenError: if the inner cannot be opened (wrong key / tamper /
            rewritten outer header — the header is AEAD-bound).
    """
    if not is_pqrouted(wire):
        raise PqRouteFormatError("not a pqroute1-wrapped blob (missing magic)")
    _route_hdr, inner_meta, content = open_routed(
        bytes(wire)[len(PQROUTE_MAGIC):], dest_hybrid_priv
    )
    return inner_meta, SignedEnvelope.from_bytes(content)


def parse_inbound(
    wire: bytes, dest_hybrid_priv: Optional[bytes] = None
) -> tuple[Optional[dict], SignedEnvelope]:
    """Parse an inbound wire blob in either form (wrapped or plain).

    Convenience for a receiver that may get either a wrapped pqroute1 blob or a
    plain ``SignedEnvelope`` (default-OFF senders). Returns
    ``(inner_metadata_or_None, SignedEnvelope)``.

    Args:
        wire: Inbound wire bytes.
        dest_hybrid_priv: The destination hybrid private key — required only if
            ``wire`` is wrapped.

    Raises:
        PqRouteFormatError: wrapped blob but no private key supplied.
        PqRouteOpenError: wrapped blob fails to open.
    """
    if is_pqrouted(wire):
        if not dest_hybrid_priv:
            raise PqRouteFormatError(
                "inbound blob is pqroute1-wrapped but no hybrid private key given"
            )
        return unwrap_signed(wire, dest_hybrid_priv)
    return None, SignedEnvelope.from_bytes(bytes(wire))
