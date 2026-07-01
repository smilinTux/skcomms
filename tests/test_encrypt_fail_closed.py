"""F6 regression — encryption MUST fail closed, never fall back to plaintext.

The historical bug (crypto.py:193) caught every exception on the encrypt path
and ``return envelope`` — handing back the ORIGINAL cleartext payload with
``encrypted=False``. Any hiccup in the PGP wrap (bad armor, missing dep,
pgpy internal error) therefore put the plaintext on the wire with only a log
line. This proves the invariant: an *attempted* encryption that fails raises
``CryptoError`` and never yields a plaintext envelope, while the *checked*
graceful-degradation path (PGP unavailable) is preserved.
"""

from __future__ import annotations

import pytest

from skcomms.crypto import CryptoError, EnvelopeCrypto
from skcomms.models import MessageEnvelope, MessagePayload


def _envelope(content: str = "TOP-SECRET body") -> MessageEnvelope:
    return MessageEnvelope(
        sender="capauth:alice@skworld.io",
        recipient="capauth:bob@skworld.io",
        payload=MessagePayload(content=content),
    )


def test_attempted_encryption_failure_raises_never_returns_plaintext():
    ec = EnvelopeCrypto(private_key_armor="", passphrase="")
    # Force the *attempted* path: PGP is considered available, a recipient key
    # is supplied — but the actual wrap will throw (garbage armor / no pgpy).
    ec._pgp_available = True
    env = _envelope("TOP-SECRET body")

    with pytest.raises(CryptoError):
        ec.encrypt_payload(env, recipient_public_armor="-----NOT A REAL KEY-----")


def test_graceful_degradation_still_returns_plaintext_when_pgp_unavailable():
    # The CHECKED path (PGP unavailable) is deliberate graceful degradation and
    # must remain a no-op return — not a raise.
    ec = EnvelopeCrypto(private_key_armor="", passphrase="")
    ec._pgp_available = False
    env = _envelope("plain")

    out = ec.encrypt_payload(env, recipient_public_armor="whatever")
    assert out.payload.content == "plain"
    assert out.payload.encrypted is False


def test_already_encrypted_envelope_is_untouched():
    ec = EnvelopeCrypto(private_key_armor="", passphrase="")
    ec._pgp_available = True
    env = MessageEnvelope(
        sender="capauth:alice@skworld.io",
        recipient="capauth:bob@skworld.io",
        payload=MessagePayload(content="ciphertext", encrypted=True),
    )
    out = ec.encrypt_payload(env, recipient_public_armor="-----NOT A REAL KEY-----")
    assert out is env
