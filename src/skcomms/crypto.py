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

import contextlib
import logging
from pathlib import Path
from typing import Optional

from .models import MessageEnvelope, MessagePayload

logger = logging.getLogger("skcomms.crypto")


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
    ) -> None:
        self._private_armor = private_key_armor
        self._passphrase = passphrase
        self._fingerprint = own_fingerprint
        self._pgp_available = _check_pgpy()

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

            return cls(
                private_key_armor=private_armor,
                passphrase="",
                own_fingerprint=fingerprint,
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


class KeyStore:
    """Manages peer public keys for encryption and verification.

    Stores ASCII-armored public keys indexed by agent name or fingerprint.
    Loads from ~/.skcomms/peers/ directory if available.

    Args:
        peers_dir: Path to the peers directory.
    """

    def __init__(self, peers_dir: Optional[Path] = None) -> None:
        self._keys: dict[str, str] = {}
        self._peers_dir = peers_dir or Path.home() / ".skcomms" / "peers"
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
