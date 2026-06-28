"""SKComms envelope signing -- PGP authenticity for every message.

Every outbound envelope gets PGP-signed by the sender's CapAuth key.
Receivers verify the signature against the sender's known public key
before processing the payload. This prevents spoofing and tampering.

As of T5 (``38b146c6``) the canonical schema is **Envelope v1**
(:mod:`skcomms.envelope`). ``EnvelopeSigner.sign`` /
``EnvelopeVerifier.verify`` operate over :class:`~skcomms.envelope.Envelope`
and its stable :meth:`~skcomms.envelope.Envelope.canonical_bytes`.

The legacy transport-level ``MessageEnvelope`` (``skcomms.models``) is still
supported for backward compatibility via :func:`sign_message_envelope` and a
content-hash fallback in the canonicalizer.

Usage:
    signer = EnvelopeSigner(private_key_armor, passphrase)
    signed = signer.sign(envelope)            # Envelope -> SignedEnvelope

    verifier = EnvelopeVerifier()
    verifier.add_key("lumina@chef.skworld", lumina_public_armor)
    result = verifier.verify(signed)
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Union

from pydantic import BaseModel, Field

from .envelope import (
    CLASSICAL_SIG_SUITE,
    HYBRID_SIG_SUITE,
    Envelope,
    SignedEnvelope,
)
from .models import MessageEnvelope

logger = logging.getLogger("skcomms.signing")


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def _canonical_bytes(envelope: Union[Envelope, MessageEnvelope]) -> bytes:
    """Return the canonical bytes to sign for either envelope schema.

    Envelope v1 exposes its own :meth:`canonical_bytes`. The legacy
    ``MessageEnvelope`` is canonicalized with sorted-key compact JSON (the
    historical behaviour) for backward compatibility.
    """
    if isinstance(envelope, Envelope):
        return envelope.canonical_bytes()
    # Legacy MessageEnvelope path
    data = json.loads(envelope.model_dump_json())
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Signer
# ---------------------------------------------------------------------------


class EnvelopeSigner:
    """Signs outbound Envelope v1 messages with a PGP private key.

    Each signed envelope includes the PGP signature, the signer's
    fingerprint, and a SHA-256 content hash for quick validation.

    Args:
        private_key_armor: ASCII-armored PGP private key.
        passphrase: Passphrase to unlock the key (``""`` if unprotected).
    """

    def __init__(self, private_key_armor: str, passphrase: str = "") -> None:
        import pgpy

        self._key, _ = pgpy.PGPKey.from_blob(private_key_armor)
        self._passphrase = passphrase
        self._fingerprint = str(self._key.fingerprint).replace(" ", "")

    @property
    def fingerprint(self) -> str:
        """The signer's 40-char hex PGP fingerprint."""
        return self._fingerprint

    def _detached_sig(self, canonical: bytes) -> str:
        """Produce an armored PGP signature over *canonical* bytes."""
        import pgpy

        pgp_message = pgpy.PGPMessage.new(canonical, cleartext=False)
        _ctx = (
            self._key.unlock(self._passphrase)
            if self._key.is_protected
            else contextlib.nullcontext()
        )
        with _ctx:
            sig = self._key.sign(pgp_message)
        return str(sig)

    def sign_bytes(self, canonical: bytes) -> str:
        """Produce an armored detached PGP signature over arbitrary *canonical* bytes.

        Public wrapper around the same detached-signing path :meth:`sign` uses.
        Lets non-envelope payloads (e.g. the SKFed realm directory) be CapAuth
        signed with the SAME proven key + verifier, without inventing a parallel
        crypto path. Verify with :meth:`EnvelopeVerifier.verify_bytes`.

        Args:
            canonical: The exact bytes to sign (caller is responsible for a
                stable/canonical serialization).

        Returns:
            str: ASCII-armored PGP detached signature.
        """
        return self._detached_sig(canonical)

    def sign(self, envelope: Envelope) -> SignedEnvelope:
        """Sign an Envelope v1 with the loaded private key.

        Args:
            envelope: The :class:`~skcomms.envelope.Envelope` to sign.

        Returns:
            SignedEnvelope: Envelope with PGP signature attached.
        """
        canonical = envelope.canonical_bytes()
        content_hash = hashlib.sha256(canonical).hexdigest()
        signature = self._detached_sig(canonical)
        return SignedEnvelope(
            envelope=envelope,
            signature=signature,
            signer_fingerprint=self._fingerprint,
            content_hash=content_hash,
        )

    def sign_message_envelope(self, envelope: MessageEnvelope) -> "LegacySignedEnvelope":
        """Backward-compat: sign a legacy transport ``MessageEnvelope``.

        Args:
            envelope: The legacy ``MessageEnvelope`` to sign.

        Returns:
            LegacySignedEnvelope: Legacy signed wrapper.
        """
        canonical = _canonical_bytes(envelope)
        content_hash = hashlib.sha256(canonical).hexdigest()
        signature = self._detached_sig(canonical)
        return LegacySignedEnvelope(
            envelope=envelope,
            signature=signature,
            signer_fingerprint=self._fingerprint,
            content_hash=content_hash,
        )


# ---------------------------------------------------------------------------
# Hybrid post-quantum signer (PQC Q7 / Phase 2) — ADDITIVE, opt-in
# ---------------------------------------------------------------------------


class HybridEnvelopeSigner:
    """Signs Envelope v1 with a **hybrid Ed25519 + ML-DSA-65** composite.

    This is the Phase 2 / Q7 opt-in signer. It composes the vetted
    :mod:`skcomms.pqsig` primitive (FIPS 204 ML-DSA-65 + RFC 8032 Ed25519) over
    the SAME ``Envelope.canonical_bytes()`` the classical signer uses, so the
    signed transcript is identical — only the signature scheme changes.

    The ML-DSA-65 keypair is a **per-signer key, SEPARATE from the PGP identity
    key** (generated/persisted by ``pqsig.load_or_create_signer_keypair`` or
    passed in). This signer NEVER touches the PGP root key; the classical
    Ed25519 leg here is the hybrid keypair's own Ed25519 half. The resulting
    :class:`~skcomms.envelope.SignedEnvelope` carries:

    * ``sig_suite = "mldsa65-ed25519-v2"`` (selects the hybrid verify path),
    * ``signature`` = base64 of the :func:`skcomms.pqsig.hybrid_sign` composite,
    * ``hybrid_ed25519_pub`` / ``hybrid_mldsa_pub`` = base64 public keys so a
      verifier can check both legs,
    * ``content_hash`` = SHA-256 of the canonical bytes (unchanged tamper
      pre-check).

    Args:
        keypair: A :class:`skcomms.pqsig.HybridSigKeypair`. If ``None``, one is
            loaded-or-created for ``signer_id`` via
            :func:`skcomms.pqsig.load_or_create_signer_keypair`.
        signer_id: Stable id used for key persistence + as the
            ``signer_fingerprint`` label (defaults to the ML-DSA pubkey hash).
    """

    def __init__(self, keypair=None, signer_id: str = "") -> None:
        from . import pqsig

        self._pqsig = pqsig
        if keypair is None:
            if not signer_id:
                raise ValueError(
                    "HybridEnvelopeSigner needs a keypair or a signer_id"
                )
            keypair = pqsig.load_or_create_signer_keypair(signer_id)
        self._kp = keypair
        # A stable signer label: caller id if given, else a short hash of the
        # ML-DSA public key (so the verifier can index it).
        self._signer_id = signer_id or (
            "mldsa65:" + hashlib.sha256(keypair.mldsa_pub).hexdigest()[:32]
        )

    @property
    def signer_id(self) -> str:
        """The stable signer label recorded as ``signer_fingerprint``."""
        return self._signer_id

    def sign(self, envelope: Envelope) -> SignedEnvelope:
        """Hybrid-sign an Envelope v1.

        Args:
            envelope: The :class:`~skcomms.envelope.Envelope` to sign.

        Returns:
            SignedEnvelope with the hybrid composite signature + public keys.
        """
        canonical = envelope.canonical_bytes()
        content_hash = hashlib.sha256(canonical).hexdigest()
        composite = self._pqsig.hybrid_sign(
            canonical, self._kp.ed25519_priv, self._kp.mldsa_priv
        )
        return SignedEnvelope(
            envelope=envelope,
            signature=base64.b64encode(composite).decode("ascii"),
            signer_fingerprint=self._signer_id,
            content_hash=content_hash,
            sig_suite=HYBRID_SIG_SUITE,
            hybrid_ed25519_pub=base64.b64encode(self._kp.ed25519_pub).decode("ascii"),
            hybrid_mldsa_pub=base64.b64encode(self._kp.mldsa_pub).decode("ascii"),
        )


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class EnvelopeVerifier:
    """Verifies PGP signatures on incoming signed envelopes.

    Maintains a keyring of known sender public keys, indexed both by
    fingerprint and by registered identity (FQID or name). Verifies the
    Envelope v1 :class:`~skcomms.envelope.SignedEnvelope` schema and, for
    backward compatibility, the legacy ``LegacySignedEnvelope``.

    Usage:
        verifier = EnvelopeVerifier()
        verifier.add_key("lumina@chef.skworld", pub_armor)
        result = verifier.verify(signed_envelope)
    """

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}

    def add_key(self, identity: str, public_key_armor: str) -> str:
        """Register a sender's public key.

        Args:
            identity: Sender FQID, name, or fingerprint.
            public_key_armor: ASCII-armored PGP public key.

        Returns:
            str: The key's 40-char hex fingerprint.
        """
        import pgpy

        key, _ = pgpy.PGPKey.from_blob(public_key_armor)
        fp = str(key.fingerprint).replace(" ", "")
        self._keys[fp] = public_key_armor
        self._keys[identity] = public_key_armor
        return fp

    def has_key(self, identity_or_fingerprint: str) -> bool:
        """Whether a sender's key is registered."""
        return identity_or_fingerprint in self._keys

    @property
    def key_count(self) -> int:
        """Number of unique keys registered (counted by fingerprint)."""
        return len({k for k in self._keys if len(k) == 40})

    def verify(
        self, signed: Union[SignedEnvelope, "LegacySignedEnvelope"]
    ) -> "VerificationResult":
        """Verify the PGP signature on a signed envelope.

        Checks: signature present -> signer key known -> content hash
        matches -> PGP signature cryptographically valid.

        Args:
            signed: The signed envelope (v1 or legacy).

        Returns:
            VerificationResult: Detailed verification outcome.
        """
        if not signed.is_signed:
            return VerificationResult(valid=False, reason="No signature present")

        # Hybrid post-quantum path (PQC Q7) — additive + negotiated. A hybrid
        # envelope (sig_suite == mldsa65-ed25519-v2 with both hybrid pubkeys)
        # is verified with skcomms.pqsig (BOTH Ed25519 AND ML-DSA-65 legs must
        # verify). Classical envelopes never enter here (is_hybrid is False),
        # so the legacy PGP path below is byte-for-byte unchanged.
        if getattr(signed, "sig_suite", CLASSICAL_SIG_SUITE) == HYBRID_SIG_SUITE:
            return self._verify_hybrid(signed)

        pub_armor = self._find_key(signed)
        if not pub_armor:
            return VerificationResult(
                valid=False,
                reason=f"Unknown signer: {signed.signer_fingerprint[:16]}",
                fingerprint=signed.signer_fingerprint,
            )

        canonical = _canonical_bytes(signed.envelope)
        actual_hash = hashlib.sha256(canonical).hexdigest()

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
            pgp_message = pgpy.PGPMessage.new(canonical, cleartext=False)
            pgp_message |= sig

            is_valid = bool(pub_key.verify(pgp_message))
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

    def _verify_hybrid(self, signed: SignedEnvelope) -> "VerificationResult":
        """Verify a hybrid Ed25519 + ML-DSA-65 SignedEnvelope (PQC Q7).

        The envelope carries the two hybrid public keys inline; both legs must
        verify (skcomms.pqsig AND gate) over the canonical bytes. A
        content-hash mismatch is rejected first (cheap tamper pre-check), same
        as the classical path. Honest failure modes: a non-hybrid or malformed
        hybrid envelope (missing pubkeys / bad framing) is reported invalid, not
        crashed; a missing liboqs backend is surfaced as an error reason.
        """
        if not getattr(signed, "is_hybrid", False):
            return VerificationResult(
                valid=False,
                reason="sig_suite is hybrid but hybrid public keys are missing",
                fingerprint=signed.signer_fingerprint,
            )

        canonical = _canonical_bytes(signed.envelope)
        actual_hash = hashlib.sha256(canonical).hexdigest()
        if signed.content_hash and actual_hash != signed.content_hash:
            return VerificationResult(
                valid=False,
                reason="Content hash mismatch (envelope tampered)",
                fingerprint=signed.signer_fingerprint,
            )

        try:
            from . import pqsig

            composite = base64.b64decode(signed.signature)
            ed_pub = base64.b64decode(signed.hybrid_ed25519_pub)
            mldsa_pub = base64.b64decode(signed.hybrid_mldsa_pub)
            ok = pqsig.hybrid_verify(canonical, composite, ed_pub, mldsa_pub)
            return VerificationResult(
                valid=bool(ok),
                reason=(
                    "Hybrid signature valid (Ed25519 + ML-DSA-65, FIPS 204)"
                    if ok
                    else "Hybrid signature invalid (a leg failed; both required)"
                ),
                fingerprint=signed.signer_fingerprint,
            )
        except Exception as exc:
            logger.warning("signing.py hybrid: %s", exc)
            return VerificationResult(
                valid=False,
                reason=f"Hybrid verification error: {exc}",
                fingerprint=signed.signer_fingerprint,
            )

    def verify_bytes(
        self,
        canonical: bytes,
        signature_armor: str,
        *,
        identity: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> bool:
        """Verify an armored detached PGP signature over arbitrary *canonical* bytes.

        The symmetric counterpart to :meth:`EnvelopeSigner.sign_bytes`. The
        verifying key is resolved from this verifier's keyring by *fingerprint*
        first, then by *identity*. Fails closed (returns ``False``) when no key
        is registered or the signature does not cryptographically verify.

        Args:
            canonical: The exact bytes the signature is expected to cover.
            signature_armor: ASCII-armored PGP detached signature.
            identity: Registered identity label (e.g. operator name/fqid).
            fingerprint: Signer's 40-char hex fingerprint.

        Returns:
            bool: ``True`` only if a known key validly signed *canonical*.
        """
        pub_armor: Optional[str] = None
        if fingerprint and fingerprint in self._keys:
            pub_armor = self._keys[fingerprint]
        elif identity and identity in self._keys:
            pub_armor = self._keys[identity]
        if not pub_armor:
            return False
        try:
            import pgpy

            pub_key, _ = pgpy.PGPKey.from_blob(pub_armor)
            sig = pgpy.PGPSignature.from_blob(signature_armor)
            pgp_message = pgpy.PGPMessage.new(canonical, cleartext=False)
            pgp_message |= sig
            return bool(pub_key.verify(pgp_message))
        except Exception as exc:
            logger.warning("signing.py verify_bytes: %s", exc)
            return False

    def _find_key(
        self, signed: Union[SignedEnvelope, "LegacySignedEnvelope"]
    ) -> Optional[str]:
        """Look up the public key for a signed envelope's signer."""
        if signed.signer_fingerprint in self._keys:
            return self._keys[signed.signer_fingerprint]

        env = signed.envelope
        # Envelope v1 uses from_fqid; legacy uses .sender
        sender = getattr(env, "from_fqid", None) or getattr(env, "sender", None)
        if sender and sender in self._keys:
            return self._keys[sender]
        return None


# ---------------------------------------------------------------------------
# Legacy signed wrapper (transport MessageEnvelope) — backward compat
# ---------------------------------------------------------------------------


class LegacySignedEnvelope(BaseModel):
    """A legacy transport ``MessageEnvelope`` with a PGP signature.

    Retained so older transport code keeps working while Envelope v1 becomes
    the canonical schema. New code should use
    :class:`skcomms.envelope.SignedEnvelope`.
    """

    envelope: MessageEnvelope
    signature: str = ""
    signer_fingerprint: str = ""
    signed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str = ""

    @property
    def is_signed(self) -> bool:
        return bool(self.signature)

    def to_bytes(self) -> bytes:
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "LegacySignedEnvelope":
        return cls.model_validate_json(data)


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
