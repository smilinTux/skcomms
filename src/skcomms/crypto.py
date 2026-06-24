"""
SKComms envelope encryption — PGP encrypt and sign via CapAuth.

Provides a middleware layer that encrypts envelope payloads before
transport and decrypts them on receive. Uses PGPy for crypto
operations and reads keys from the CapAuth sovereign profile.

Design:
    - Encryption uses the RECIPIENT's public key (only they can read it)
    - Signing uses the SENDER's private key (proves who sent it)
    - Both operations are optional and controlled by config
    - Falls back gracefully to plaintext if keys are unavailable
"""

from __future__ import annotations

import base64
import contextlib
import logging
from pathlib import Path
from typing import Optional

from .models import MessageEnvelope, MessagePayload

logger = logging.getLogger("skcomms.crypto")

#: Wire marker for a hybrid-PQ sealed payload stored in ``payload.content``.
#: Classical PGP payloads start with ``-----BEGIN PGP``; hybrid payloads start
#: with this prefix so the two coexist in the same string field without any
#: model change (back-compat: classical content is byte-for-byte unchanged).
PQDM_SCHEME = "pqdm1:"


class EnvelopeCrypto:
    """PGP encryption and signing engine for SKComms envelopes.

    Loads keys from CapAuth sovereign profiles. Encrypt/sign operations
    are applied to the envelope payload content before it touches any
    transport. Decrypt/verify operations are applied after receive.

    Args:
        private_key_armor: ASCII-armored PGP private key for signing.
        passphrase: Passphrase to unlock the private key.
        own_fingerprint: PGP fingerprint of this agent.
    """

    def __init__(
        self,
        private_key_armor: str,
        passphrase: str,
        own_fingerprint: str = "",
        hybrid_provider: "Optional[object]" = None,
    ) -> None:
        self._private_armor = private_key_armor
        self._passphrase = passphrase
        self._fingerprint = own_fingerprint
        self._pgp_available = _check_pgpy()
        # PQC cut-over (optional). A ``hybrid_provider`` lets the transport
        # negotiate hybrid X25519+ML-KEM-768 confidentiality BY DEFAULT when the
        # recipient advertises a hybrid prekey, and open hybrid inbound payloads.
        # It is a small duck-typed object exposing:
        #   * ``resolve_bundle(identity) -> dict | None`` — the recipient's
        #     published prekey bundle (``{suite, hybrid_public_hex, ...}``), or
        #     None if unknown (→ classical, negotiated downgrade).
        #   * ``own_private() -> bytes | None`` — this agent's hybrid private key
        #     for opening ``pqdm1:`` inbound payloads, or None.
        #   * ``own_short() -> str`` / ``short(identity) -> str`` — short-name
        #     normalisers used in the downgrade-lock AAD (optional; fall back to
        #     the raw identity).
        # When None (the default) EVERYTHING stays classical, byte-for-byte —
        # so existing deployments without a prekey store are unchanged.
        self._hybrid = hybrid_provider

    @classmethod
    def from_capauth(cls, capauth_dir: Optional[Path] = None) -> Optional[EnvelopeCrypto]:
        """Create an EnvelopeCrypto from the local CapAuth profile.

        Reads the private key from ~/.capauth/identity/private.asc.
        Returns None if CapAuth is not set up or keys are missing.

        Args:
            capauth_dir: Override CapAuth directory. Defaults to ~/.capauth/.

        Returns:
            EnvelopeCrypto instance, or None if keys are unavailable.
        """
        base = capauth_dir or Path.home() / ".capauth"
        priv_path = base / "identity" / "private.asc"
        base / "identity" / "public.asc"
        profile_path = base / "identity" / "profile.json"

        if not priv_path.exists():
            logger.info("No CapAuth private key at %s — encryption disabled", priv_path)
            return None

        try:
            private_armor = priv_path.read_text(encoding="utf-8")
            fingerprint = ""
            if profile_path.exists():
                import json

                data = json.loads(profile_path.read_text(encoding="utf-8"))
                key_info = data.get("key_info", {})
                fingerprint = key_info.get("fingerprint", "")

            # PQC cut-over: attach the shared-store hybrid prekey provider so the
            # transport negotiates hybrid X25519+ML-KEM-768 BY DEFAULT when the
            # recipient advertises a hybrid prekey. None when liboqs is absent
            # (→ classical, unchanged).
            hybrid_provider = None
            try:
                from .pq_provider import default_provider

                hybrid_provider = default_provider()
            except Exception:
                hybrid_provider = None

            return cls(
                private_key_armor=private_armor,
                passphrase="",
                own_fingerprint=fingerprint,
                hybrid_provider=hybrid_provider,
            )
        except Exception as exc:
            logger.warning("Failed to load CapAuth keys: %s", exc)
            return None

    @property
    def fingerprint(self) -> str:
        """This agent's PGP fingerprint.

        Returns:
            str: 40-char hex fingerprint, or empty string.
        """
        return self._fingerprint

    def envelope_signer(self):
        """Return an :class:`~skcomms.signing.EnvelopeSigner` for Envelope v1.

        Builds the canonical-envelope signer from this agent's loaded private
        key — the federation send path signs the canonical ``SignedEnvelope``
        with it (vs. the legacy ``sign_payload`` on ``MessageEnvelope``).
        """
        from .signing import EnvelopeSigner

        return EnvelopeSigner(self._private_armor, self._passphrase)

    def encrypt_payload(
        self,
        envelope: MessageEnvelope,
        recipient_public_armor: str,
    ) -> MessageEnvelope:
        """Encrypt an envelope's payload content with the recipient's public key.

        Creates a new envelope with the payload content replaced by
        PGP ciphertext. The encrypted flag is set to True.

        Args:
            envelope: The envelope with plaintext payload.
            recipient_public_armor: ASCII-armored public key of the recipient.

        Returns:
            MessageEnvelope: Copy with encrypted payload.
        """
        if envelope.payload.encrypted:
            return envelope
        if not self._pgp_available:
            logger.debug("PGPy not available — skipping encryption")
            return envelope

        try:
            import pgpy
            from pgpy.constants import SymmetricKeyAlgorithm

            recipient_key, _ = pgpy.PGPKey.from_blob(recipient_public_armor)
            pgp_message = pgpy.PGPMessage.new(envelope.payload.content.encode("utf-8"))
            encrypted = recipient_key.encrypt(
                pgp_message,
                cipher=SymmetricKeyAlgorithm.AES256,
            )

            new_payload = MessagePayload(
                content=str(encrypted),
                content_type=envelope.payload.content_type,
                encrypted=True,
                compressed=envelope.payload.compressed,
                signature=envelope.payload.signature,
            )

            return envelope.model_copy(update={"payload": new_payload})

        except Exception as exc:
            logger.warning("Encryption failed: %s — sending plaintext", exc)
            return envelope

    def decrypt_payload(self, envelope: MessageEnvelope) -> MessageEnvelope:
        """Decrypt an envelope's payload content with our private key.

        Args:
            envelope: The envelope with PGP-encrypted payload.

        Returns:
            MessageEnvelope: Copy with decrypted plaintext payload.
        """
        if not envelope.payload.encrypted:
            return envelope

        # PQC cut-over: route hybrid-sealed (``pqdm1:``) payloads to the hybrid
        # opener with our hybrid private key. Classical PGP payloads fall through
        # unchanged.
        if self.is_hybrid_payload(envelope) and self._hybrid is not None:
            priv = None
            try:
                priv = self._hybrid.own_private()
            except Exception:
                priv = None
            if priv is not None:
                try:
                    sender = self._hybrid_short(envelope.sender)
                    recipient = self._hybrid_short(envelope.recipient or self._fingerprint)
                    return self.decrypt_payload_hybrid(
                        envelope, priv, sender=sender, recipient=recipient
                    )
                except Exception as exc:
                    logger.warning("hybrid payload decrypt failed: %s", exc)
                    return envelope

        if not self._pgp_available:
            logger.debug("PGPy not available — cannot decrypt")
            return envelope

        try:
            import pgpy

            private_key, _ = pgpy.PGPKey.from_blob(self._private_armor)
            pgp_message = pgpy.PGPMessage.from_blob(envelope.payload.content)

            _ctx = (
                private_key.unlock(self._passphrase)
                if private_key.is_protected
                else contextlib.nullcontext()
            )
            with _ctx:
                decrypted = private_key.decrypt(pgp_message)

            plaintext = decrypted.message
            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode("utf-8")

            new_payload = MessagePayload(
                content=plaintext,
                content_type=envelope.payload.content_type,
                encrypted=False,
                compressed=envelope.payload.compressed,
                signature=envelope.payload.signature,
            )

            return envelope.model_copy(update={"payload": new_payload})

        except Exception as exc:
            logger.warning("Decryption failed: %s", exc)
            return envelope

    def sign_payload(self, envelope: MessageEnvelope) -> MessageEnvelope:
        """Sign an envelope's payload content with our private key.

        Creates a detached PGP signature over the payload content and
        stores it in the payload's signature field.

        Args:
            envelope: The envelope to sign.

        Returns:
            MessageEnvelope: Copy with signature field populated.
        """
        if envelope.payload.signature:
            return envelope
        if not self._pgp_available:
            return envelope

        try:
            import pgpy

            private_key, _ = pgpy.PGPKey.from_blob(self._private_armor)
            pgp_message = pgpy.PGPMessage.new(
                envelope.payload.content.encode("utf-8"),
                cleartext=False,
            )

            _ctx = (
                private_key.unlock(self._passphrase)
                if private_key.is_protected
                else contextlib.nullcontext()
            )
            with _ctx:
                sig = private_key.sign(pgp_message)

            new_payload = envelope.payload.model_copy(update={"signature": str(sig)})
            return envelope.model_copy(update={"payload": new_payload})

        except Exception as exc:
            logger.warning("Signing failed: %s — sending unsigned", exc)
            return envelope

    def verify_signature(
        self,
        envelope: MessageEnvelope,
        sender_public_armor: str,
    ) -> bool:
        """Verify the PGP signature on an envelope's payload.

        Args:
            envelope: The envelope with a signed payload.
            sender_public_armor: ASCII-armored public key of the sender.

        Returns:
            bool: True if the signature is valid.
        """
        if not envelope.payload.signature:
            return False
        if not self._pgp_available:
            return False

        try:
            import pgpy

            pub_key, _ = pgpy.PGPKey.from_blob(sender_public_armor)
            sig = pgpy.PGPSignature.from_blob(envelope.payload.signature)

            content_bytes = envelope.payload.content.encode("utf-8")
            pgp_message = pgpy.PGPMessage.new(content_bytes, cleartext=False)
            pgp_message |= sig

            verification = pub_key.verify(pgp_message)
            return bool(verification)

        except Exception as exc:
            logger.warning("Signature verification failed: %s", exc)
            return False


    # ------------------------------------------------------------------
    # PQC Q3 — hybrid post-quantum payload sealing (HNDL fix, opt-in).
    #
    # These methods add a NEGOTIATED hybrid-KEM path *alongside* the classical
    # PGP path above. ``encrypt_payload``/``decrypt_payload`` are untouched, so
    # classical peers are byte-for-byte unchanged. Hybrid engages only when the
    # recipient advertises a hybrid prekey bundle (``PrekeyBundle.is_hybrid``).
    # The negotiated suite is recorded for the per-conversation self-report.
    # ------------------------------------------------------------------

    @staticmethod
    def supports_hybrid() -> bool:
        """Whether this build can do hybrid sealing (liboqs reachable)."""
        try:
            from .pqkem import is_available

            return is_available()
        except Exception:
            return False

    def negotiated_suite(self, recipient_bundle) -> str:
        """Resolve the suite for a conversation with ``recipient_bundle``.

        Hybrid (``x25519-mlkem768``) only when this side supports hybrid AND the
        recipient advertises a hybrid prekey; otherwise the classical suite
        (negotiated downgrade). This is the single honest gate the self-report
        and ``encrypt_payload_auto`` both use.

        Args:
            recipient_bundle: A ``skcomms.pqdm.PrekeyBundle`` (or a dict / None,
                coerced via ``PrekeyBundle.from_dict``).

        Returns:
            The negotiated suite id.
        """
        from .pqdm import PrekeyBundle, negotiate_suite

        bundle = (
            recipient_bundle
            if isinstance(recipient_bundle, PrekeyBundle)
            else PrekeyBundle.from_dict(recipient_bundle)
        )
        return negotiate_suite(self.supports_hybrid(), bundle)

    def encrypt_payload_hybrid(
        self,
        envelope: MessageEnvelope,
        recipient_bundle,
        sender: str = "",
        recipient: str = "",
    ) -> MessageEnvelope:
        """Hybrid-seal an envelope payload to a recipient's hybrid prekey.

        The recipient bundle MUST be hybrid (caller gates via
        :meth:`negotiated_suite`). Encapsulates to the hybrid prekey, AES-256-GCM
        seals the payload content, binds the negotiated suite into the AAD
        (downgrade-lock), and stores ``PQDM_SCHEME + suite : base64(sealed)`` in
        ``payload.content`` with ``encrypted=True``. The model is unchanged — the
        scheme prefix distinguishes hybrid from classical PGP content.

        Args:
            envelope: Envelope with plaintext payload.
            recipient_bundle: The recipient's ``PrekeyBundle`` (hybrid).
            sender / recipient: Party identifiers bound into the downgrade-lock AAD.

        Returns:
            MessageEnvelope: Copy with a hybrid-sealed payload.

        Raises:
            PqDmFormatError / PqKemError: propagated (never a silent downgrade).
        """
        from .pqdm import HYBRID_SUITE, PrekeyBundle, seal

        if envelope.payload.encrypted:
            return envelope
        bundle = (
            recipient_bundle
            if isinstance(recipient_bundle, PrekeyBundle)
            else PrekeyBundle.from_dict(recipient_bundle)
        )
        sealed = seal(
            envelope.payload.content.encode("utf-8"),
            bundle,
            sender=sender,
            recipient=recipient,
        )
        token = f"{PQDM_SCHEME}{HYBRID_SUITE}:" + base64.b64encode(sealed).decode("ascii")
        new_payload = MessagePayload(
            content=token,
            content_type=envelope.payload.content_type,
            encrypted=True,
            compressed=envelope.payload.compressed,
            signature=envelope.payload.signature,
        )
        return envelope.model_copy(update={"payload": new_payload})

    def encrypt_payload_auto(
        self,
        envelope: MessageEnvelope,
        recipient_public_armor: str,
        recipient_bundle=None,
        sender: str = "",
        recipient: str = "",
    ) -> tuple[MessageEnvelope, str]:
        """Encrypt honouring negotiation: hybrid if advertised, else classical.

        This is the crypto-agile entry point. If the recipient advertises a
        hybrid prekey AND this side supports hybrid, the payload is hybrid-sealed
        and the negotiated suite is ``x25519-mlkem768``. Otherwise it falls back
        to the *unchanged* classical PGP path (``encrypt_payload``) and the suite
        is the classical wrap — a genuine negotiated downgrade, recorded honestly.

        Returns:
            ``(envelope, negotiated_suite)`` — the suite for the self-report.
        """
        suite = self.negotiated_suite(recipient_bundle)
        from .pqdm import HYBRID_SUITE

        if suite == HYBRID_SUITE:
            return (
                self.encrypt_payload_hybrid(
                    envelope, recipient_bundle, sender=sender, recipient=recipient
                ),
                suite,
            )
        return self.encrypt_payload(envelope, recipient_public_armor), suite

    def _hybrid_short(self, identity: str) -> str:
        """Normalise an identity to the short name used in the downgrade AAD.

        Delegates to the hybrid provider's ``short`` if present (so both peers
        agree on the AAD), else strips the ``capauth:``/``@…`` decoration here.
        """
        if self._hybrid is not None:
            try:
                return self._hybrid.short(identity)
            except Exception:
                pass
        s = identity[len("capauth:") :] if identity.startswith("capauth:") else identity
        return s.split("@")[0]

    def encrypt_payload_provider(
        self,
        envelope: MessageEnvelope,
        recipient_public_armor: str,
    ) -> tuple[MessageEnvelope, str]:
        """Negotiate confidentiality using the configured hybrid provider.

        PQC cut-over default for the transport: when a ``hybrid_provider`` is
        configured AND the recipient advertises a hybrid prekey, the payload is
        hybrid-sealed (``x25519-mlkem768``); otherwise it falls back to the
        unchanged classical PGP wrap. With no provider this is exactly the
        classical path. Returns ``(envelope, negotiated_suite)``.
        """
        bundle = None
        if self._hybrid is not None:
            try:
                bundle = self._hybrid.resolve_bundle(envelope.recipient)
            except Exception:
                bundle = None
        sender = self._hybrid_short(envelope.sender or self._fingerprint)
        recipient = self._hybrid_short(envelope.recipient)
        return self.encrypt_payload_auto(
            envelope,
            recipient_public_armor,
            recipient_bundle=bundle,
            sender=sender,
            recipient=recipient,
        )

    @staticmethod
    def is_hybrid_payload(envelope: MessageEnvelope) -> bool:
        """Whether an envelope carries a hybrid-PQ sealed payload."""
        c = envelope.payload.content or ""
        return envelope.payload.encrypted and c.startswith(PQDM_SCHEME)

    def decrypt_payload_hybrid(
        self,
        envelope: MessageEnvelope,
        hybrid_private: bytes,
        sender: str = "",
        recipient: str = "",
    ) -> MessageEnvelope:
        """Open a hybrid-sealed payload with this agent's hybrid private key.

        Reconstructs the downgrade-lock AAD from the suite carried in the token
        and binds it on open; a stripped/downgraded payload fails to authenticate
        (:class:`~skcomms.pqdm.DowngradeDetected`).

        Args:
            envelope: Envelope with a hybrid-sealed payload.
            hybrid_private: This agent's 2432-byte hybrid private key.
            sender / recipient: Party identifiers (must match the seal call).

        Returns:
            MessageEnvelope: Copy with the decrypted plaintext payload.
        """
        from .pqdm import open_sealed

        c = envelope.payload.content or ""
        if not c.startswith(PQDM_SCHEME):
            raise ValueError("not a hybrid-sealed payload")
        rest = c[len(PQDM_SCHEME) :]
        suite, _, b64 = rest.partition(":")
        sealed = base64.b64decode(b64)
        plaintext = open_sealed(
            sealed,
            hybrid_private,
            sender=sender,
            recipient=recipient,
            expected_suite=suite,
        )
        new_payload = MessagePayload(
            content=plaintext.decode("utf-8"),
            content_type=envelope.payload.content_type,
            encrypted=False,
            compressed=envelope.payload.compressed,
            signature=envelope.payload.signature,
        )
        return envelope.model_copy(update={"payload": new_payload})


class KeyStore:
    """Manages peer public keys for encryption and verification.

    Stores ASCII-armored public keys indexed by agent name or fingerprint.
    Loads from ~/.skcapstone/skcomms/peers/ directory if available.

    Args:
        peers_dir: Path to the peers directory.
    """

    def __init__(self, peers_dir: Optional[Path] = None) -> None:
        self._keys: dict[str, str] = {}
        self._peers_dir = peers_dir or Path.home() / ".skcapstone" / "skcomms" / "peers"
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Load peer keys from disk on first access."""
        if self._loaded:
            return
        self._loaded = True

        if not self._peers_dir.exists():
            return

        import yaml

        for peer_file in self._peers_dir.glob("*.yml"):
            try:
                data = yaml.safe_load(peer_file.read_text()) or {}
                name = data.get("name", peer_file.stem)
                pubkey_path = data.get("public_key")
                if pubkey_path:
                    key_path = Path(pubkey_path).expanduser()
                    if key_path.exists():
                        self._keys[name] = key_path.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning("crypto.py: %s", e)
                continue

    def get_public_key(self, peer: str) -> Optional[str]:
        """Get a peer's ASCII-armored public key.

        Args:
            peer: Peer agent name or fingerprint.

        Returns:
            str: ASCII-armored public key, or None.
        """
        self._ensure_loaded()
        return self._keys.get(peer)

    def add_key(self, peer: str, public_armor: str) -> None:
        """Add or update a peer's public key.

        Args:
            peer: Peer agent name or fingerprint.
            public_armor: ASCII-armored PGP public key.
        """
        self._keys[peer] = public_armor

    def has_key(self, peer: str) -> bool:
        """Check if we have a peer's public key.

        Args:
            peer: Peer agent name or fingerprint.

        Returns:
            bool: True if the key is available.
        """
        self._ensure_loaded()
        return peer in self._keys

    @property
    def known_peers(self) -> list[str]:
        """List all peers we have keys for.

        Returns:
            list[str]: Peer names/fingerprints.
        """
        self._ensure_loaded()
        return list(self._keys.keys())


def _check_pgpy() -> bool:
    """Check if PGPy is importable.

    Returns:
        bool: True if pgpy is available.
    """
    try:
        import pgpy  # noqa: F401

        return True
    except ImportError:
        return False
