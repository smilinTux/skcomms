"""SKComm envelope signing -- PGP authenticity for every message.

Every outbound envelope gets PGP-signed by the sender's CapAuth key.
Receivers verify the signature against the sender's known public key
before processing the payload. This prevents spoofing and tampering.

The signature covers the full serialized envelope JSON (minus the
signature field itself), ensuring any modification is detectable.

Usage:
    signer = EnvelopeSigner(private_key_armor, passphrase)
    signed = signer.sign(envelope)

    verifier = EnvelopeVerifier()
    verifier.add_key("alice", alice_public_armor)
    is_valid = verifier.verify(signed)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from .models import MessageEnvelope

logger = logging.getLogger("skcomm.signing")


class SignedEnvelope(BaseModel):
    """A MessageEnvelope with a PGP signature for authenticity.

    The signature field contains a PGP detached signature over
    the canonical JSON representation of the envelope (with the
    signature field excluded from the signed content).

    Attributes:
        envelope: The original MessageEnvelope.
        signature: PGP signature armor string.
        signer_fingerprint: PGP fingerprint of the signer.
        signed_at: When the signature was created.
        content_hash: SHA-256 of the signed content for quick checks.
    """

    envelope: MessageEnvelope
    signature: str = ""
    signer_fingerprint: str = ""
    signed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str = ""

    def to_bytes(self) -> bytes:
        """Serialize the signed envelope to UTF-8 JSON bytes.

        Returns:
            bytes: JSON-encoded signed envelope.
        """
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedEnvelope:
        """Deserialize from UTF-8 JSON bytes.

        Args:
            data: JSON bytes.

        Returns:
            SignedEnvelope: Parsed signed envelope.
        """
        return cls.model_validate_json(data)

    @property
    def is_signed(self) -> bool:
        """Check if this envelope has a signature."""
        return bool(self.signature)


def _canonical_json(envelope: MessageEnvelope) -> str:
    """Produce canonical JSON for signing.

    Uses sorted keys and compact separators for deterministic output.

    Args:
        envelope: The envelope to canonicalize.

    Returns:
        str: Deterministic JSON string.
    """
    data = json.loads(envelope.model_dump_json())
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


class EnvelopeSigner:
    """Signs outbound envelopes with a PGP private key.

    Each signed envelope includes the PGP signature, the signer's
    fingerprint, and a SHA-256 content hash for quick validation.

    Args:
        private_key_armor: ASCII-armored PGP private key.
        passphrase: Passphrase to unlock the key.
    """

    def __init__(self, private_key_armor: str, passphrase: str) -> None:
        import pgpy

        self._key, _ = pgpy.PGPKey.from_blob(private_key_armor)
        self._passphrase = passphrase
        self._fingerprint = str(self._key.fingerprint).replace(" ", "")

    @property
    def fingerprint(self) -> str:
        """The signer's PGP fingerprint.

        Returns:
            str: 40-char hex fingerprint.
        """
        return self._fingerprint

    def sign(self, envelope: MessageEnvelope) -> SignedEnvelope:
        """Sign an envelope with the loaded private key.

        Args:
            envelope: The MessageEnvelope to sign.

        Returns:
            SignedEnvelope: Envelope with PGP signature attached.
        """
        import pgpy

        canonical = _canonical_json(envelope)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        pgp_message = pgpy.PGPMessage.new(canonical.encode("utf-8"), cleartext=False)

        _ctx = (
            self._key.unlock(self._passphrase)
            if self._key.is_protected
            else contextlib.nullcontext()
        )
        with _ctx:
            sig = self._key.sign(pgp_message)

        return SignedEnvelope(
            envelope=envelope,
            signature=str(sig),
            signer_fingerprint=self._fingerprint,
            content_hash=content_hash,
        )


class EnvelopeVerifier:
    """Verifies PGP signatures on incoming signed envelopes.

    Maintains a keyring of known sender public keys. Verification
    checks both the PGP signature and the content hash.

    Usage:
        verifier = EnvelopeVerifier()
        verifier.add_key("alice", alice_pub_armor)
        result = verifier.verify(signed_envelope)
    """

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}

    def add_key(self, identity: str, public_key_armor: str) -> str:
        """Register a sender's public key.

        Args:
            identity: Sender name or fingerprint.
            public_key_armor: ASCII-armored PGP public key.

        Returns:
            str: The key's fingerprint.
        """
        import pgpy

        key, _ = pgpy.PGPKey.from_blob(public_key_armor)
        fp = str(key.fingerprint).replace(" ", "")
        self._keys[fp] = public_key_armor
        self._keys[identity] = public_key_armor
        return fp

    def verify(self, signed: SignedEnvelope) -> VerificationResult:
        """Verify the PGP signature on a signed envelope.

        Checks:
        1. Signature is present
        2. Signer's public key is known
        3. Content hash matches
        4. PGP signature is cryptographically valid

        Args:
            signed: The signed envelope to verify.

        Returns:
            VerificationResult: Detailed verification outcome.
        """
        if not signed.is_signed:
            return VerificationResult(
                valid=False,
                reason="No signature present",
            )

        pub_armor = self._find_key(signed)
        if not pub_armor:
            return VerificationResult(
                valid=False,
                reason=f"Unknown signer: {signed.signer_fingerprint[:16]}",
                fingerprint=signed.signer_fingerprint,
            )

        canonical = _canonical_json(signed.envelope)
        actual_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if signed.content_hash and actual_hash != signed.content_hash:
            return VerificationResult(
                valid=False,
                reason="Content hash mismatch (envelope tampered)",
                fingerprint=signed.signer_fingerprint,
            )

        try:
            import pgpy

            pub_key, _ = pgpy.PGPKey.from_blob(pub_armor)
            sig = pgpy.PGPSignature.from_blob(signed.signature)
            pgp_message = pgpy.PGPMessage.new(canonical.encode("utf-8"), cleartext=False)
            pgp_message |= sig

            verification = pub_key.verify(pgp_message)
            is_valid = bool(verification)

            return VerificationResult(
                valid=is_valid,
                reason="Signature valid" if is_valid else "PGP signature invalid",
                fingerprint=signed.signer_fingerprint,
            )
        except Exception as exc:
            logger.warning("signing.py: %s", exc)
            return VerificationResult(
                valid=False,
                reason=f"Verification error: {exc}",
                fingerprint=signed.signer_fingerprint,
            )

    def has_key(self, identity_or_fingerprint: str) -> bool:
        """Check if a sender's key is registered.

        Args:
            identity_or_fingerprint: Sender name or fingerprint.

        Returns:
            bool: True if the key is known.
        """
        return identity_or_fingerprint in self._keys

    @property
    def key_count(self) -> int:
        """Number of unique keys registered (by fingerprint)."""
        fps = set()
        for k, v in self._keys.items():
            if len(k) == 40:
                fps.add(k)
        return len(fps)

    def _find_key(self, signed: SignedEnvelope) -> Optional[str]:
        """Look up the public key for a signed envelope's signer.

        Args:
            signed: The signed envelope.

        Returns:
            Optional[str]: Public key armor, or None if unknown.
        """
        if signed.signer_fingerprint in self._keys:
            return self._keys[signed.signer_fingerprint]

        sender = signed.envelope.sender
        if sender in self._keys:
            return self._keys[sender]

        return None


class VerificationResult(BaseModel):
    """Outcome of an envelope signature verification.

    Attributes:
        valid: Whether the signature is valid.
        reason: Human-readable explanation.
        fingerprint: Signer's fingerprint (if known).
        verified_at: When verification was performed.
    """

    valid: bool = False
    reason: str = ""
    fingerprint: str = ""
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
