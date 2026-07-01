"""Integrity sibling of F6 — signing MUST fail closed, never send UNSIGNED.

The bug (crypto.py:324-326) caught every exception on the sign path and
``return envelope`` — handing back an UNSIGNED envelope with only a
``logger.warning("... sending unsigned")``. With ``config.sign=True`` any
signing hiccup (locked key, wrong/empty passphrase, bad armor, pgpy error)
therefore put an unauthenticated message on the wire, silently defeating the
anti-spoofing/anti-tamper guarantee — and the legacy inbound path never
re-verifies it. This proves the invariant: an *attempted* signature that
fails raises ``CryptoError``; the *checked* graceful-degradation path (PGP
unavailable) is preserved.
"""

from __future__ import annotations

import pytest

from skcomms.crypto import CryptoError, EnvelopeCrypto
from skcomms.models import MessageEnvelope, MessagePayload


def _envelope(content: str = "authentic message") -> MessageEnvelope:
    return MessageEnvelope(
        sender="capauth:alice@skworld.io",
        recipient="capauth:bob@skworld.io",
        payload=MessagePayload(content=content),
    )


def test_attempted_signing_failure_raises_never_returns_unsigned():
    # PGP considered available + a (garbage) private key present → the *attempted*
    # sign path runs and throws. It must raise, not return an unsigned envelope.
    ec = EnvelopeCrypto(private_key_armor="-----NOT A REAL KEY-----", passphrase="")
    ec._pgp_available = True
    env = _envelope()

    with pytest.raises(CryptoError):
        ec.sign_payload(env)


def test_graceful_degradation_returns_unsigned_when_pgp_unavailable():
    # The CHECKED path (PGP unavailable) is deliberate graceful degradation and
    # must remain a no-op return — not a raise.
    ec = EnvelopeCrypto(private_key_armor="-----NOT A REAL KEY-----", passphrase="")
    ec._pgp_available = False
    env = _envelope("plain")

    out = ec.sign_payload(env)
    assert out.payload.signature in (None, "")


def test_already_signed_envelope_is_untouched():
    ec = EnvelopeCrypto(private_key_armor="-----NOT A REAL KEY-----", passphrase="")
    ec._pgp_available = True
    env = MessageEnvelope(
        sender="capauth:alice@skworld.io",
        recipient="capauth:bob@skworld.io",
        payload=MessagePayload(content="body", signature="EXISTING-SIG"),
    )
    out = ec.sign_payload(env)
    assert out is env
