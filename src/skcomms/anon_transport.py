"""No-identity anonymous transport framing — RFC-0001 P5 **foundation**.

This is the additive, flag-gated layer that turns the
:mod:`skcomms.anon_queue` addressing primitive + the :mod:`skcomms.padding`
length-hiding ladder into a single **wire frame** for a no-identity message
queue. It composes three already-vetted building blocks and adds NO new crypto:

    1. **Addressing without identity** — a peer is named ONLY by an opaque
       ``aqid:`` address (relay + 16-byte ``sender_id``). There is no FQID, no
       DID, no capauth identity, no public key, no fingerprint anywhere in the
       frame. A relay routes on the opaque ``sender_id`` and learns nothing
       linking it to a subscriber (see :mod:`skcomms.anon_queue`).
    2. **Deniable authentication** — each frame carries a
       :func:`skcomms.anon_queue.auth_tag` HMAC-SHA256 tag over a shared
       per-queue secret. The tag proves the frame came from *someone holding the
       queue secret* but is **repudiable**: either party could have produced it,
       so it is authentic to the participants yet gives a third party no
       transferable proof. It is NEVER a signature.
    3. **Length hiding** — the payload is run through
       :func:`skcomms.padding.pad_to_bucket` so a passive relay sees only a
       coarse size *class*, not the exact byte count.

Wire framing (anon frame)::

    ANON_MAGIC(8) || ver(1) || sender_id(16) || nonce(16) || tag(32) || padded_body

    where  padded_body = pad_to_bucket(payload)
           tag         = auth_tag(secret, ver || sender_id || padded_body, nonce)

The magic prefix (``SKCANON1\\x00``) keeps anon frames cleanly distinguishable
from a plain ``SignedEnvelope`` JSON document (starts with ``{``) and from a
``pqroute1`` blob (different magic), so a receiver/relay can dispatch
unambiguously. The tag binds the version, the routing ``sender_id``, and the
**padded** body, so a frame cannot be silently re-pointed at a different queue
nor have its pad region tampered with.

The flag gate (default OFF -> nothing emitted)
----------------------------------------------
Anon mode is a distinct opt-in *mode*, not a transform of the existing paths.
Producing a frame is gated two ways (override beats env):

    * a per-call ``enabled=True`` (the **explicit API**), OR
    * the ``SKCOMMS_ANON`` environment variable (``1``/``true``/``yes``/``on``).

When neither is set, :func:`frame_anon` raises :class:`AnonDisabledError` rather
than emitting anything — so the classical, sovereign (DID), and ``pqroute``
paths are **byte-untouched**: this module is purely additive and never runs
unless explicitly turned on. (Parsing an already-received frame is ungated — a
recipient that opted in must be able to read what it receives.)

Honesty (sk-standards)
----------------------
    * This is **addressing + deniable auth + length-padding ONLY**. It does
      **not** encrypt the payload: a relay sees the padded body bytes. Pass an
      already-sealed payload for confidentiality — compose with
      :mod:`skcomms.pqdm` / :mod:`skcomms.pqkem` (hybrid X25519 || ML-KEM-768,
      FIPS 203; confidential if EITHER leg holds — no "quantum-proof" claim).
    * The deniable MAC gives **authenticity + deniability**, never
      non-repudiation; its security rests on HMAC-SHA256 and the secrecy of the
      shared per-queue secret.
    * **Anonymity-set honesty:** opaque, uncorrelated ids reduce metadata leak
      *at the relay*, but on a small sovereign network the anonymity set is
      small. With few participants, timing/volume correlation can still
      deanonymize. This raises the bar for a passive relay; it is not a magic
      anonymity cloak on a 3-node net.
    * Scope: framing + a two-party state holder ONLY. No relay, no network, no
      delivery, no queue rotation — those come later.

Primitives are reused, never hand-rolled: ids/MAC from
:mod:`skcomms.anon_queue`, padding from :mod:`skcomms.padding`, ``os.urandom``
for the per-frame nonce.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .anon_queue import (
    QUEUE_ID_LEN,
    auth_tag,
    decode_aqid,
    encode_aqid,
    new_queue_pair,
    verify_tag,
)
from .padding import PAD_LADDER, pad_to_bucket, unpad

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Environment variable that opts a process into anon-frame production.
ANON_ENV = "SKCOMMS_ANON"

#: Magic prefix marking an anon frame. The NUL keeps it out of JSON/text space
#: so it never collides with a ``SignedEnvelope`` (``{``) or a ``pqroute1`` blob.
ANON_MAGIC = b"SKCANON1\x00"

#: Stable self-report label for this framing construction.
ANON_TRANSPORT_SUITE = "anon-transport-v1"

#: Frame-format version byte (bound into the deniable tag).
_FRAME_VERSION = 1

#: Per-frame nonce length (bytes). 16 B CSPRNG, matching the queue-id sizing.
NONCE_LEN = 16

#: Deniable-auth tag length (bytes) — HMAC-SHA256 output.
_TAG_LEN = 32

_TRUTHY = {"1", "true", "yes", "on"}

#: Fixed header length before the padded body:
#: magic + ver(1) + sender_id + nonce + tag.
_HEADER_LEN = len(ANON_MAGIC) + 1 + QUEUE_ID_LEN + NONCE_LEN + _TAG_LEN

# Field offsets within the frame.
_OFF_VER = len(ANON_MAGIC)
_OFF_SID = _OFF_VER + 1
_OFF_NONCE = _OFF_SID + QUEUE_ID_LEN
_OFF_TAG = _OFF_NONCE + NONCE_LEN
_OFF_BODY = _OFF_TAG + _TAG_LEN


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AnonTransportError(Exception):
    """Base error for the anonymous-transport framing layer."""


class AnonDisabledError(AnonTransportError):
    """Frame production attempted while the anon flag gate is OFF.

    Raised by :func:`frame_anon` when neither ``enabled=True`` nor
    ``SKCOMMS_ANON`` is set — so nothing is ever emitted unless intentionally
    turned on (the additive guarantee).
    """


class AnonFrameError(AnonTransportError, ValueError):
    """Malformed / truncated anon frame, or a wrong-queue routing id."""


class AnonAuthError(AnonTransportError):
    """Deniable-auth verification failed (wrong secret / tampered frame)."""


# ---------------------------------------------------------------------------
# Flag gate
# ---------------------------------------------------------------------------


def anon_enabled(override: Optional[bool] = None) -> bool:
    """Whether anon-frame production is enabled.

    Resolution order (first that applies wins):
        1. ``override`` — explicit per-call ``True``/``False`` (when not None).
        2. ``SKCOMMS_ANON`` env var (``1``/``true``/``yes``/``on`` => on).

    Default (no override, env unset/falsey) is **OFF** — the additive guarantee.
    """
    if override is not None:
        return bool(override)
    return os.environ.get(ANON_ENV, "").strip().lower() in _TRUTHY


# ---------------------------------------------------------------------------
# Detection / relay read
# ---------------------------------------------------------------------------


def is_anon_frame(wire: bytes) -> bool:
    """True iff ``wire`` is an anon frame (carries :data:`ANON_MAGIC`)."""
    return (
        isinstance(wire, (bytes, bytearray))
        and bytes(wire[: len(ANON_MAGIC)]) == ANON_MAGIC
    )


def read_sender_id(wire: bytes) -> bytes:
    """Return ONLY the opaque routing ``sender_id`` — what a relay reads.

    Does no authentication (a relay holds no secret) and no decryption: the
    relay routes on this opaque 16-byte id and learns nothing else linking it to
    a subscriber.

    Raises:
        AnonFrameError: if ``wire`` is not an anon frame or is too short.
    """
    if not is_anon_frame(wire):
        raise AnonFrameError("not an anon frame (missing magic)")
    blob = bytes(wire)
    if len(blob) < _OFF_NONCE:
        raise AnonFrameError("anon frame truncated before sender_id")
    return blob[_OFF_SID:_OFF_NONCE]


# ---------------------------------------------------------------------------
# Frame (seal) / parse (open)
# ---------------------------------------------------------------------------


def frame_anon(
    payload: bytes,
    sender_id: bytes,
    secret: bytes,
    *,
    nonce: Optional[bytes] = None,
    ladder: tuple = PAD_LADDER,
    enabled: Optional[bool] = None,
) -> bytes:
    """Frame ``payload`` for an anon queue: pad, deniably authenticate, wrap.

    Flag-gated: raises :class:`AnonDisabledError` unless ``enabled=True`` or
    ``SKCOMMS_ANON`` is set (so the non-anon paths stay byte-untouched).

    The ``payload`` is treated as **opaque bytes** — this layer does not encrypt
    it. Pass an already-sealed body for confidentiality (see module docstring).

    Args:
        payload: The opaque body bytes to frame (any length).
        sender_id: The 16-byte opaque routing id (the published half of an
            :func:`skcomms.anon_queue.new_queue_pair`). Relay routes on this.
        secret: The shared per-queue deniable-auth secret (non-empty bytes;
            use >=32 CSPRNG bytes in practice).
        nonce: Optional explicit per-frame nonce; defaults to fresh
            :func:`os.urandom` (:data:`NONCE_LEN` bytes).
        ladder: Padding bucket ladder (defaults to
            :data:`skcomms.padding.PAD_LADDER`).
        enabled: Per-call override of the flag gate (see :func:`anon_enabled`).

    Returns:
        The anon-frame wire bytes (see module docstring for the layout).

    Raises:
        AnonDisabledError: the flag gate is OFF.
        AnonFrameError: invalid ``sender_id``/``secret``/``nonce``.
    """
    if not anon_enabled(enabled):
        raise AnonDisabledError(
            "anon framing is OFF — set SKCOMMS_ANON=1 or pass enabled=True"
        )
    if not isinstance(sender_id, (bytes, bytearray)) or len(sender_id) != QUEUE_ID_LEN:
        raise AnonFrameError(f"sender_id must be {QUEUE_ID_LEN} bytes")
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise AnonFrameError("secret must be non-empty bytes")
    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    elif not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
        raise AnonFrameError(f"nonce must be {NONCE_LEN} bytes")

    sid = bytes(sender_id)
    nonce = bytes(nonce)
    ver = bytes([_FRAME_VERSION])
    padded_body = pad_to_bucket(bytes(payload), ladder)
    # Bind version + routing id + the *padded* body into the deniable tag, with
    # the nonce mixed in by auth_tag (HMAC(secret, nonce || message)).
    tag = auth_tag(bytes(secret), ver + sid + padded_body, nonce)
    return ANON_MAGIC + ver + sid + nonce + tag + padded_body


@dataclass(frozen=True)
class AnonFrame:
    """A parsed anon frame: the opaque routing id + the recovered payload."""

    sender_id: bytes
    payload: bytes


def parse_anon(
    wire: bytes,
    secret: bytes,
    *,
    expected_sender_id: Optional[bytes] = None,
) -> AnonFrame:
    """Verify + open an anon frame back to ``(sender_id, payload)``.

    Recomputes the deniable tag, rejects on mismatch (constant-time), then
    unpads to recover the exact opaque payload. Parsing is **ungated** — a
    recipient that opted in must be able to read what it received.

    Args:
        wire: The anon-frame bytes from :func:`frame_anon`.
        secret: The shared per-queue deniable-auth secret.
        expected_sender_id: If given, the frame's routing id MUST equal it (a
            wrong-queue frame is rejected before the body is touched).

    Returns:
        :class:`AnonFrame` — the opaque ``sender_id`` and recovered ``payload``.

    Raises:
        AnonFrameError: malformed/truncated frame, bad version, or a routing id
            that does not match ``expected_sender_id``.
        AnonAuthError: the deniable tag does not verify (wrong secret / tamper).
    """
    if not is_anon_frame(wire):
        raise AnonFrameError("not an anon frame (missing magic)")
    blob = bytes(wire)
    if len(blob) < _HEADER_LEN:
        raise AnonFrameError(
            f"anon frame shorter than {_HEADER_LEN}-byte header: {len(blob)} bytes"
        )
    ver = blob[_OFF_VER]
    if ver != _FRAME_VERSION:
        raise AnonFrameError(f"unsupported anon frame version {ver}")
    sid = blob[_OFF_SID:_OFF_NONCE]
    nonce = blob[_OFF_NONCE:_OFF_TAG]
    tag = blob[_OFF_TAG:_OFF_BODY]
    padded_body = blob[_OFF_BODY:]

    if expected_sender_id is not None and sid != bytes(expected_sender_id):
        raise AnonFrameError("frame sender_id does not match this queue")

    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise AnonFrameError("secret must be non-empty bytes")
    if not verify_tag(
        bytes(secret), bytes([ver]) + sid + padded_body, nonce, tag
    ):
        raise AnonAuthError("deniable auth failed (wrong secret or tampered frame)")

    try:
        payload = unpad(padded_body)
    except Exception as exc:  # PaddingError (subclass of ValueError)
        raise AnonFrameError(f"padded body malformed: {exc}") from exc
    return AnonFrame(sender_id=sid, payload=payload)


# ---------------------------------------------------------------------------
# Two-party state holder (pure-ish): an anon channel keyed by sender_id + secret
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnonChannel:
    """A two-party no-identity channel: opaque routing id + shared secret.

    Both parties share the routing ``sender_id`` (relay address) and the
    deniable-auth ``secret``. The recipient additionally holds the private
    ``recipient_id`` (its relay SUBSCRIPTION id, uncorrelated with the
    ``sender_id``) — that id is for the future relay layer, NOT used in framing.

    There is **no identity here**: an :class:`AnonChannel` is fully described by
    a relay locator, an opaque 16-byte id, and a shared secret. The secret is
    exchanged out of band (e.g. inside an already-sealed first contact).
    """

    relay: str
    sender_id: bytes
    secret: bytes
    recipient_id: Optional[bytes] = None  # private SUB id (recipient side only)

    @classmethod
    def create(cls, relay: str, secret: bytes) -> "AnonChannel":
        """Recipient side: mint a fresh uncorrelated queue pair for ``relay``.

        Generates ``(recipient_id, sender_id)`` via
        :func:`skcomms.anon_queue.new_queue_pair`; keeps ``recipient_id``
        private and publishes ``sender_id`` (via :attr:`address`).
        """
        if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
            raise AnonFrameError("secret must be non-empty bytes")
        recipient_id, sender_id = new_queue_pair()
        return cls(relay=relay, sender_id=sender_id, secret=bytes(secret),
                   recipient_id=recipient_id)

    @classmethod
    def from_address(cls, aqid: str, secret: bytes) -> "AnonChannel":
        """Sender side: resolve an ``aqid:`` address + out-of-band secret.

        Decodes the address to ``(relay, sender_id)``. The sender never learns
        the recipient's private subscription id.
        """
        if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
            raise AnonFrameError("secret must be non-empty bytes")
        relay, sender_id = decode_aqid(aqid)
        return cls(relay=relay, sender_id=sender_id, secret=bytes(secret),
                   recipient_id=None)

    @property
    def address(self) -> str:
        """The publishable ``aqid:`` address (relay + opaque sender_id)."""
        return encode_aqid(self.relay, self.sender_id)

    def seal(
        self,
        payload: bytes,
        *,
        nonce: Optional[bytes] = None,
        ladder: tuple = PAD_LADDER,
        enabled: Optional[bool] = None,
    ) -> bytes:
        """Frame ``payload`` for this channel (flag-gated, see :func:`frame_anon`).

        Returns the wire bytes; address the transport to :attr:`relay`.
        """
        return frame_anon(
            payload, self.sender_id, self.secret,
            nonce=nonce, ladder=ladder, enabled=enabled,
        )

    def open(self, wire: bytes) -> bytes:
        """Verify + open a frame addressed to this channel, returning payload.

        Enforces that the frame's routing id matches this channel's
        ``sender_id`` (rejects a frame for a different queue).
        """
        return parse_anon(
            wire, self.secret, expected_sender_id=self.sender_id
        ).payload
