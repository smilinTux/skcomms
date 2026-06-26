"""Anonymous, no-identity queue addressing — RFC-0001 P5 **foundation only**.

This is the *addressing + deniable-authentication* primitive that a future
SimpleX-style unidirectional message queue composes on top of. It is the
building block, **NOT a transport**: there is no relay, no network, no store,
no delivery here — only opaque id generation, an ``aqid:`` address codec, and a
repudiable shared-secret authenticator.

CLEAN-ROOM NOTICE
    SimpleX Chat / SMP is **AGPL-3.0**. Nothing here is derived from, copied
    from, or a translation of their source. Only the *protocol idea* is
    borrowed — that a queue can be addressed without any long-term identity by
    giving the sender and the recipient two **independent, uncorrelated** opaque
    ids, so that the relay holding the queue cannot link "who subscribes" to
    "who sends". The wire format, the codec, and the MAC construction below are
    original.

What this module provides
    * :func:`new_queue_pair` — one unidirectional queue's ``(recipient_id,
      sender_id)``: two INDEPENDENT 16-byte random ids. The recipient SUBs on
      ``recipient_id``; senders SEND to ``sender_id``. They are deliberately
      uncorrelated — knowing one tells a relay nothing about the other.
    * :func:`encode_aqid` / :func:`decode_aqid` — the ``aqid:`` address codec,
      ``aqid:<relay>/<base64url-unpadded(sender_id)>``. Only the *sender* id is
      ever published (that is the part you hand out); the recipient id is the
      private subscription secret and never appears in an address.
    * :func:`auth_tag` / :func:`verify_tag` — a **deniable** authenticator:
      ``HMAC-SHA256(secret, nonce || message)`` over a shared secret. Because it
      is a symmetric MAC, a valid tag proves the message came from *someone who
      holds the shared secret* — but EITHER party could have produced it, so it
      is repudiable: it is authentic to the participants yet provides no
      transferable proof to a third party (the opposite of a digital signature).

Honesty (sk-standards)
    * This is **addressing + deniable auth ONLY**. No transport/relay exists
      yet, and nothing here encrypts message bodies — compose with
      :mod:`skcomms.pqkem` (hybrid X25519 || ML-KEM-768, FIPS 203) and
      AES-256-GCM for confidentiality when the transport is built.
    * The deniable MAC gives **authenticity + deniability**, never
      non-repudiation, and is not "unbreakable" — its security rests on
      HMAC-SHA256 and the secrecy of the shared secret.
    * **Anonymity-set honesty:** unlinkable ids reduce metadata leakage *at the
      relay*, but on a small sovereign network the anonymity set is small. With
      few participants, timing/volume correlation and the sheer paucity of
      candidates can still deanonymize. This primitive raises the bar for a
      passive relay; it is not a magic anonymity cloak on a 3-node net.

Primitives are reused, never hand-rolled: ``os.urandom`` (CSPRNG) for ids,
``cryptography`` HMAC-SHA256 for the MAC, and stdlib base64url for the codec.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes, hmac

# ---------------------------------------------------------------------------
# Suite id (crypto_suites.py style: lowercase, versioned label).
# ---------------------------------------------------------------------------

#: Stable label for this addressing + deniable-auth construction.
ANON_SUITE = "aqid-v1"

#: Length (bytes) of each opaque queue id. 16 B = 128 bits of CSPRNG entropy —
#: collision-negligible and unlinkable, matching the hybrid-prekey id sizing.
QUEUE_ID_LEN = 16

#: ``aqid:`` scheme prefix for the address codec.
AQID_SCHEME = "aqid:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AnonQueueError(Exception):
    """Base error for the anonymous-queue addressing primitive."""


class AnonQueueFormatError(AnonQueueError, ValueError):
    """Malformed id, address, or argument (never a crash)."""


# ---------------------------------------------------------------------------
# Queue id generation
# ---------------------------------------------------------------------------


def new_queue_pair() -> tuple[bytes, bytes]:
    """Generate one unidirectional queue's ``(recipient_id, sender_id)``.

    The two ids are **independent** 16-byte CSPRNG values, deliberately
    uncorrelated: a relay that sees a SEND to ``sender_id`` cannot link it to
    the SUB on ``recipient_id`` (and vice-versa). The recipient keeps
    ``recipient_id`` private (its subscription secret) and publishes only
    ``sender_id`` (via :func:`encode_aqid`).

    Returns:
        ``(recipient_id, sender_id)`` — two distinct 16-byte values.
    """
    recipient_id = os.urandom(QUEUE_ID_LEN)
    sender_id = os.urandom(QUEUE_ID_LEN)
    # Astronomically unlikely with 128-bit ids, but keep the invariant exact:
    # the pair MUST be distinct (their independence is the whole point).
    while sender_id == recipient_id:  # pragma: no cover — 2^-128 event
        sender_id = os.urandom(QUEUE_ID_LEN)
    return recipient_id, sender_id


# ---------------------------------------------------------------------------
# aqid: address codec
# ---------------------------------------------------------------------------


def encode_aqid(relay: str, sender_id: bytes) -> str:
    """Encode a publishable queue address ``aqid:<relay>/<base64url(sid)>``.

    Only the *sender* id is encoded — that is the half meant to be handed out.
    The base64url is unpadded so the address stays clean in URLs/QR codes.

    Args:
        relay: Non-empty relay locator (host/host:port/onion/etc.). Must not
            contain ``/`` (that delimits the id) and must be non-empty.
        sender_id: The 16-byte sender id from :func:`new_queue_pair`.

    Raises:
        AnonQueueFormatError: on empty/invalid relay or wrong-length id.
    """
    if not isinstance(relay, str) or not relay:
        raise AnonQueueFormatError("relay must be a non-empty string")
    if "/" in relay:
        raise AnonQueueFormatError("relay must not contain '/'")
    if not isinstance(sender_id, (bytes, bytearray)):
        raise AnonQueueFormatError(
            f"sender_id must be bytes, got {type(sender_id).__name__}"
        )
    if len(sender_id) != QUEUE_ID_LEN:
        raise AnonQueueFormatError(
            f"sender_id must be {QUEUE_ID_LEN} bytes, got {len(sender_id)}"
        )
    b64 = base64.urlsafe_b64encode(bytes(sender_id)).rstrip(b"=").decode("ascii")
    return f"{AQID_SCHEME}{relay}/{b64}"


def decode_aqid(s: str) -> tuple[str, bytes]:
    """Decode an ``aqid:`` address back to ``(relay, sender_id)`` exactly.

    Round-trips :func:`encode_aqid`. Rejects anything malformed.

    Raises:
        AnonQueueFormatError: missing/wrong scheme, empty relay, empty or
            non-base64url id, or an id that is not exactly 16 bytes.
    """
    if not isinstance(s, str):
        raise AnonQueueFormatError(f"address must be a string, got {type(s).__name__}")
    if not s.startswith(AQID_SCHEME):
        raise AnonQueueFormatError(f"address must start with '{AQID_SCHEME}'")
    body = s[len(AQID_SCHEME):]
    relay, sep, b64 = body.partition("/")
    if not sep:
        raise AnonQueueFormatError("address must be 'aqid:<relay>/<id>'")
    if not relay:
        raise AnonQueueFormatError("relay must be non-empty")
    if not b64:
        raise AnonQueueFormatError("id must be non-empty")
    try:
        sender_id = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception as exc:  # binascii.Error (subclasses ValueError) or bad chars
        raise AnonQueueFormatError(f"id is not valid base64url: {exc}") from exc
    if len(sender_id) != QUEUE_ID_LEN:
        raise AnonQueueFormatError(
            f"decoded id must be {QUEUE_ID_LEN} bytes, got {len(sender_id)}"
        )
    return relay, sender_id


# ---------------------------------------------------------------------------
# Deniable (repudiable) authenticator — HMAC-SHA256(secret, nonce || message)
# ---------------------------------------------------------------------------


def auth_tag(secret: bytes, message: bytes, nonce: bytes) -> bytes:
    """Compute a **deniable** authenticator over ``message``.

    ``tag = HMAC-SHA256(secret, nonce || message)``. Being a shared-secret MAC,
    a valid tag is authentic to the holders of ``secret`` but **repudiable** —
    either party could have produced it, so it is NOT a signature and grants no
    transferable proof to a third party. The ``nonce`` is bound into the MAC
    (prepended to the message), so a fresh nonce yields a fresh tag.

    Args:
        secret: Shared symmetric secret (e.g. a derived per-queue key).
        message: The bytes being authenticated.
        nonce: Per-message nonce, bound into the tag.

    Returns:
        The 32-byte HMAC-SHA256 tag.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise AnonQueueFormatError("secret must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise AnonQueueFormatError("message must be bytes")
    if not isinstance(nonce, (bytes, bytearray)):
        raise AnonQueueFormatError("nonce must be bytes")
    h = hmac.HMAC(bytes(secret), hashes.SHA256())
    h.update(bytes(nonce) + bytes(message))
    return h.finalize()


def verify_tag(secret: bytes, message: bytes, nonce: bytes, tag: bytes) -> bool:
    """Constant-time verify a :func:`auth_tag` tag. Returns True/False, no raise.

    Recomputes the expected MAC and compares in constant time
    (``hmac.HMAC.verify``). A wrong secret, tampered message, wrong nonce, or
    tampered tag all return ``False`` rather than raising.
    """
    if not isinstance(tag, (bytes, bytearray)):
        return False
    try:
        h = hmac.HMAC(bytes(secret), hashes.SHA256())
        h.update(bytes(nonce) + bytes(message))
        h.verify(bytes(tag))
        return True
    except Exception:
        # InvalidSignature (constant-time mismatch) or any malformed input.
        return False
