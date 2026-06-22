"""SKFed — federation message core (canonical signed envelope + replay/freshness).

This is the rail-agnostic heart of node-to-node federation (epic ``skfed-comms``,
design: ``docs/federation-data-comms-architecture.md``). It sits on top of the
existing :mod:`skcomms.envelope` (canonical :class:`Envelope` v1 + detached-sig
:class:`SignedEnvelope`) and :mod:`skcomms.signing` (PGP sign/verify), adding the
two receive-side guards every rail's inbox needs:

* **nonce replay protection** — each :class:`Envelope` carries a per-transmission
  ``nonce``; a receiver dedups against recently-seen nonces.
* **two-sided freshness** — reject envelopes too old or too far in the future
  (clock-skew tolerant), bounding the replay window.

The same verified :class:`Envelope` is produced regardless of which rail carried
the bytes (HTTP S2S, Nostr, LoRa, Telegram, file) — federation = *route the
canonical signed envelope to the recipient's node over any rail*; this module is
what the recipient node runs to accept it safely.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from .envelope import Envelope, SignedEnvelope
from .signing import EnvelopeVerifier

# Default freshness window (seconds) on each side of "now".
DEFAULT_MAX_AGE_S = 300
DEFAULT_MAX_SKEW_S = 60
# Nonce cache TTL should exceed the freshness window so a replayed-but-still-fresh
# envelope is still caught by the nonce guard.
_NONCE_TTL_S = DEFAULT_MAX_AGE_S + DEFAULT_MAX_SKEW_S + 60


class FederationError(Exception):
    """Base class for federation receive-side rejections."""


class ReplayError(FederationError):
    """The envelope's nonce was already seen (replay)."""


class StaleError(FederationError):
    """The envelope is outside the accepted freshness window."""


class SignatureError(FederationError):
    """The envelope signature is missing or did not verify."""


class NonceCache:
    """In-memory TTL set of seen ``(from_fqid, nonce)`` pairs.

    Bounds memory by lazily evicting expired entries. Suitable per-process;
    a multi-process node should back this with a shared store, but the
    contract (``check_and_add``) is identical.
    """

    def __init__(self, ttl_s: int = _NONCE_TTL_S) -> None:
        self._ttl = ttl_s
        self._seen: dict[str, float] = {}

    def _evict(self, now: float) -> None:
        cutoff = now - self._ttl
        for k, ts in list(self._seen.items()):
            if ts < cutoff:
                del self._seen[k]

    def check_and_add(self, from_fqid: str, nonce: str, *, now: Optional[float] = None) -> bool:
        """Return True if fresh (and record it); False if already seen."""
        now = time.time() if now is None else now
        self._evict(now)
        key = f"{from_fqid}\x1f{nonce}"
        if key in self._seen:
            return False
        self._seen[key] = now
        return True


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def check_freshness(
    envelope: Envelope,
    *,
    max_age_s: int = DEFAULT_MAX_AGE_S,
    max_skew_s: int = DEFAULT_MAX_SKEW_S,
    now: Optional[datetime] = None,
) -> None:
    """Raise :class:`StaleError` if the envelope is too old or future-dated."""
    now = now or datetime.now(timezone.utc)
    created = _parse_iso(envelope.created_at)
    if created is None:
        raise StaleError(f"unparseable created_at: {envelope.created_at!r}")
    age = (now - created).total_seconds()
    if age > max_age_s:
        raise StaleError(f"envelope too old ({age:.0f}s > {max_age_s}s)")
    if age < -max_skew_s:
        raise StaleError(f"envelope future-dated ({-age:.0f}s > {max_skew_s}s skew)")


def accept_signed(
    signed: SignedEnvelope,
    *,
    verifier: EnvelopeVerifier,
    nonce_cache: NonceCache,
    max_age_s: int = DEFAULT_MAX_AGE_S,
    max_skew_s: int = DEFAULT_MAX_SKEW_S,
) -> Envelope:
    """Validate an inbound :class:`SignedEnvelope` and return its Envelope.

    The full receive-side gate any rail's inbox runs, in order:
      1. signature present + verifies against the sender's known/pinned key,
      2. freshness (two-sided window),
      3. nonce not previously seen (replay guard).

    Args:
        signed: The inbound signed envelope (e.g. parsed from POST body bytes).
        verifier: An :class:`~skcomms.signing.EnvelopeVerifier` preloaded with
            (or able to resolve) the sender's public key.
        nonce_cache: Per-node replay cache.

    Returns:
        Envelope: the verified, fresh, non-replayed envelope.

    Raises:
        SignatureError / StaleError / ReplayError on rejection.
    """
    if not signed.is_signed:
        raise SignatureError("unsigned envelope rejected")
    result = verifier.verify(signed)
    if not getattr(result, "valid", False):
        reason = getattr(result, "reason", "signature verification failed")
        raise SignatureError(str(reason))

    env = signed.envelope
    check_freshness(env, max_age_s=max_age_s, max_skew_s=max_skew_s)
    if not nonce_cache.check_and_add(env.from_fqid, env.nonce):
        raise ReplayError(f"replayed nonce from {env.from_fqid}: {env.nonce}")
    return env


def accept_bytes(
    raw: bytes,
    *,
    verifier: EnvelopeVerifier,
    nonce_cache: NonceCache,
    **kw,
) -> Envelope:
    """Convenience: parse ``SignedEnvelope`` bytes then :func:`accept_signed`."""
    return accept_signed(
        SignedEnvelope.from_bytes(raw), verifier=verifier, nonce_cache=nonce_cache, **kw
    )
