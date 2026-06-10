"""Envelope v1 — the canonical FQID-addressed message schema (T5, ``38b146c6``).

This is the real protocol envelope for skcomms: messages are addressed by
FQID (``<agent>@<operator>.<realm>``), carry a content-typed body, and are
signed with a PGP detached signature over a stable canonical byte stream.

``Envelope`` is the unsigned schema; :class:`SignedEnvelope` wraps it with a
detached signature + signer fingerprint (see :mod:`skcomms.signing`).

The legacy transport-level ``MessageEnvelope`` (``skcomms.models``) is still
used by the inherited transport stack; Envelope v1 is the new canonical layer
that sits above it.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with offset."""
    return datetime.now(timezone.utc).isoformat()


class Envelope(BaseModel):
    """Envelope v1 — a FQID-addressed, content-typed message.

    Attributes:
        version: Schema version, always ``"1"``.
        id: Per-message UUID (stable identity of this message).
        from_fqid: Sender FQID (``<agent>@<operator>.<realm>``).
        to_fqid: Recipient FQID.
        created_at: UTC ISO-8601 timestamp.
        content_type: MIME-ish content type of ``body`` (e.g. ``text/plain``).
        body: The message payload (string).
        subject: Optional human-readable subject.
        thread_id: Optional conversation/thread grouping id.
        reply_to: Optional id of the message this one replies to.
        headers: Optional free-form string header map.
    """

    version: str = "1"
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    from_fqid: str
    to_fqid: str
    created_at: str = Field(default_factory=_utc_now_iso)
    content_type: str = "text/plain"
    body: str
    subject: Optional[str] = None
    thread_id: Optional[str] = None
    reply_to: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """Produce a stable byte serialization for signing.

        Deterministic regardless of field-construction order: keys are
        sorted and separators are compact. The signature is never part of
        the envelope itself, so nothing is excluded here beyond that.

        Returns:
            bytes: Canonical UTF-8 JSON of the envelope.
        """
        data = self.model_dump(mode="json")
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_dict(self) -> dict:
        """Serialize to a plain JSON-safe dict."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict) -> "Envelope":
        """Reconstruct an Envelope from a plain dict."""
        return cls.model_validate(data)

    def to_bytes(self) -> bytes:
        """Serialize the full envelope to pretty UTF-8 JSON bytes."""
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope":
        """Deserialize an envelope from UTF-8 JSON bytes."""
        return cls.model_validate_json(data)


class SignedEnvelope(BaseModel):
    """An :class:`Envelope` plus a PGP detached signature.

    The signature covers :meth:`Envelope.canonical_bytes`. ``content_hash``
    is a SHA-256 of the same bytes for a cheap tamper pre-check.

    Attributes:
        envelope: The signed Envelope v1.
        signature: ASCII-armored PGP detached signature.
        signer_fingerprint: 40-char hex fingerprint of the signing key.
        signed_at: UTC ISO-8601 timestamp of signing.
        content_hash: SHA-256 hex of the signed canonical bytes.
    """

    envelope: Envelope
    signature: str = ""
    signer_fingerprint: str = ""
    signed_at: str = Field(default_factory=_utc_now_iso)
    content_hash: str = ""

    @property
    def is_signed(self) -> bool:
        """Whether a signature is present."""
        return bool(self.signature)

    def to_bytes(self) -> bytes:
        """Serialize the signed envelope to pretty UTF-8 JSON bytes."""
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedEnvelope":
        """Deserialize a signed envelope from UTF-8 JSON bytes."""
        return cls.model_validate_json(data)
