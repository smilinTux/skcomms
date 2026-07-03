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


# Canonical content types the current protocol renders with a specific view.
# Anything NOT in this set is still a valid message: it falls back to the plain
# ``body`` text (see :meth:`Envelope.render`) so a newer message kind never
# breaks an older client. Extend this set as new typed views are added.
KNOWN_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "text/plain",
        "text/markdown",
        "application/cot+xml",
        "application/geo+json",
    }
)


class Envelope(BaseModel):
    """Envelope v1 — a FQID-addressed, content-typed message.

    Attributes:
        version: Schema version, always ``"1"``.
        id: Per-message UUID (stable identity of this message).
        nonce: Per-message anti-replay nonce. Distinct from ``id`` so a
            message can be re-sent (same ``id``) while each transmission
            carries a fresh nonce the receiver dedups against (SKFed S2S).
        from_fqid: Sender FQID (``<agent>@<operator>.<realm>``).
        to_fqid: Recipient FQID.
        created_at: UTC ISO-8601 timestamp.
        content_type: MIME-ish content type of ``body`` (e.g. ``text/plain``);
            this is the rail-agnostic "kind" of the message.
        body: The message payload (string).
        subject: Optional human-readable subject.
        thread_id: Optional conversation/thread grouping id.
        reply_to: Optional id of the message this one replies to.
        headers: Optional free-form string header map.
        consent_token: Optional gate-4 per-contact capability token (hex), carried
            UNENCRYPTED on the OUTER envelope so the recipient node's consent gate
            can read it. It MUST live here (not in ``body``) because an established
            contact's DM body is ratchet-sealed and therefore opaque to the
            receiving node — only the envelope is inspectable before delivery. The
            sender lifts the token here from its :class:`skchat.token_wallet.TokenWallet`;
            the recipient's gate-4 (:meth:`skcomms.consent_pipeline.ConsentPipeline.decide`)
            recomputes + constant-time-compares it against
            :class:`skcomms.consent_tokens.TokenStore`. Additive + inert: ``None``
            (the default / legacy case) leaves :meth:`canonical_bytes` byte-for-byte
            unchanged. When present it IS folded into the signed transcript, so a
            forged/swapped token after signing breaks the signature.
    """

    version: str = "1"
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex)
    from_fqid: str
    to_fqid: str
    created_at: str = Field(default_factory=_utc_now_iso)
    content_type: str = "text/plain"
    body: str
    subject: Optional[str] = None
    thread_id: Optional[str] = None
    reply_to: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)
    consent_token: Optional[str] = None

    def canonical_bytes(self) -> bytes:
        """Produce a stable byte serialization for signing.

        Deterministic regardless of field-construction order: keys are
        sorted and separators are compact. The signature is never part of
        the envelope itself, so nothing is excluded here beyond that.

        ``consent_token`` is dropped from the transcript when ``None`` so a
        legacy / no-token envelope hashes byte-for-byte identically to before
        the field existed (additive + inert). When a token IS present it stays
        in the transcript, so the signature covers it and a forged or swapped
        token cannot survive verification.

        Returns:
            bytes: Canonical UTF-8 JSON of the envelope.
        """
        data = self.model_dump(mode="json")
        if data.get("consent_token") is None:
            data.pop("consent_token", None)
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

    def is_known_content_type(
        self, registry: frozenset[str] = KNOWN_CONTENT_TYPES
    ) -> bool:
        """Whether ``content_type`` has a recognized rich view."""
        return self.content_type in registry

    def render(self, registry: frozenset[str] = KNOWN_CONTENT_TYPES) -> str:
        """Return display text for this envelope, with plain-body fallback.

        Unknown content types fall back to the raw ``body`` so a newer message
        kind is shown as plain text rather than breaking an older client. Known
        types also return ``body`` here; a caller with a rich view branches on
        :meth:`is_known_content_type`. This is the typed-message contract at the
        canonical Envelope-v1 layer (mirrors ``MessagePayload.render``).
        """
        return self.body


# Default classical signature suite id (PQC Q0 crypto-agility scaffolding).
# Kept as a module constant so deserializing an envelope never requires the
# crypto_suites registry to be importable. The canonical definition of this id
# lives in :mod:`skcomms.crypto_suites` (DEFAULT_SIG_SUITE).
CLASSICAL_SIG_SUITE = "ed25519-v1"

# Hybrid post-quantum signature suite id (PQC Q7 / Phase 2). When
# ``SignedEnvelope.sig_suite`` is this value the ``signature`` field carries a
# base64 ``skcomms.pqsig`` composite (Ed25519 + ML-DSA-65, FIPS 204) and the
# hybrid public-key fields below are populated. The canonical definition lives
# in :mod:`skcomms.crypto_suites` (suite ``mldsa65-ed25519-v2``).
HYBRID_SIG_SUITE = "mldsa65-ed25519-v2"


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
        sig_suite: Machine-readable signature cipher-suite id (PQC Q0
            crypto-agility). Defaults to the current classical suite
            (``"ed25519-v1"``) so older envelopes serialized *without* this
            field still parse and are correctly described as classical. The id
            resolves against :mod:`skcomms.crypto_suites`; the registry is the
            single source of truth for what it means and whether it is
            quantum-resistant. Phase 0 changes **no crypto** — this field only
            makes the object self-describe its suite for future non-breaking
            swaps (e.g. ``"mldsa65-ed25519-v2"`` in Phase 2).
        hybrid_ed25519_pub: base64 32-byte Ed25519 public key for the hybrid
            signature's classical leg (Phase 2 / Q7). ``None`` for classical
            envelopes — additive, back-compatible.
        hybrid_mldsa_pub: base64 1952-byte ML-DSA-65 (FIPS 204) public key for
            the hybrid signature's PQ leg. ``None`` for classical envelopes.
            When both hybrid_* fields are set and ``sig_suite`` is the hybrid
            suite, ``signature`` carries a base64 ``skcomms.pqsig`` composite.
    """

    envelope: Envelope
    signature: str = ""
    signer_fingerprint: str = ""
    signed_at: str = Field(default_factory=_utc_now_iso)
    content_hash: str = ""
    sig_suite: str = CLASSICAL_SIG_SUITE
    hybrid_ed25519_pub: Optional[str] = None
    hybrid_mldsa_pub: Optional[str] = None

    @property
    def is_signed(self) -> bool:
        """Whether a signature is present."""
        return bool(self.signature)

    @property
    def is_hybrid(self) -> bool:
        """Whether this envelope carries a hybrid post-quantum signature.

        True iff ``sig_suite`` selects the hybrid suite *and* both hybrid
        public-key fields are populated (so a verifier can check both legs).
        Existing classical envelopes (no ``sig_suite`` or ``ed25519-v1``) are
        never reported hybrid — back-compat is byte-for-byte.
        """
        return (
            self.sig_suite == HYBRID_SIG_SUITE
            and bool(self.hybrid_ed25519_pub)
            and bool(self.hybrid_mldsa_pub)
        )

    def to_bytes(self) -> bytes:
        """Serialize the signed envelope to pretty UTF-8 JSON bytes."""
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedEnvelope":
        """Deserialize a signed envelope from UTF-8 JSON bytes."""
        return cls.model_validate_json(data)
