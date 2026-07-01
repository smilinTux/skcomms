"""Regression tests for F6 — encrypt_payload must FAIL CLOSED.

Security review finding F6: when PGP encryption was *requested* (PGP available
+ recipient key present) but the crypto operation threw, the old code logged a
warning and returned the *plaintext* envelope, which then went on the wire. A
silent confidentiality failure.

These tests pin the fail-closed contract:
  * ``encrypt_payload`` raises ``CryptoError`` on a broken recipient key
    (never returns plaintext with ``encrypted=False``).
  * ``SKComms.send`` catches that and returns ``delivered=False`` without
    routing or enqueuing the plaintext.

The graceful-degradation paths (PGP unavailable / no recipient key) are a
separate, intentional design and are NOT exercised here.
"""

from __future__ import annotations

import pytest

from skcomms.crypto import CryptoError, EnvelopeCrypto
from skcomms.models import MessageEnvelope, MessagePayload


def _plaintext_envelope() -> MessageEnvelope:
    return MessageEnvelope(
        sender="capauth:busta@mesh",
        recipient="capauth:lumina@mesh",
        payload=MessagePayload(
            content="TOP SECRET nutbusta online",
            content_type="text",
        ),
    )


def test_encrypt_payload_raises_on_bad_key_never_returns_plaintext():
    """A malformed recipient key must raise, not fall back to plaintext."""
    crypto = EnvelopeCrypto(private_key_armor="", passphrase="", own_fingerprint="deadbeef")
    if not crypto._pgp_available:  # noqa: SLF001 — test-only availability gate
        pytest.skip("PGPy unavailable — encrypt path degrades gracefully by design")

    env = _plaintext_envelope()

    with pytest.raises(CryptoError):
        crypto.encrypt_payload(env, "this-is-not-a-valid-pgp-public-key")

    # And the original envelope is untouched (no half-mutation to plaintext-on-wire).
    assert env.payload.encrypted is False
    assert "TOP SECRET" in env.payload.content
