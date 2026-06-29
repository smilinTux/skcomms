"""Tests for the Envelope v1 unencrypted ``consent_token`` header (gate-4 loop).

The sender stashes per-contact capability tokens (skchat ``TokenWallet``); for the
recipient's gate-4 to read one, the token must ride on the OUTER envelope — NOT in
the body, because established-contact DMs are ratchet-sealed (the body is opaque to
the receiving node). These tests pin the contract:

* the field is optional and defaults absent (byte-for-byte legacy canonical bytes),
* it survives ``to_dict``/``from_dict`` and ``to_bytes``/``from_bytes`` round-trips,
* it is covered by the signature (sign → verify happy path, and tampering the token
  after signing fails verification — a forged/swapped token cannot survive).
"""

from __future__ import annotations

import pytest

from skcomms.envelope import Envelope, SignedEnvelope


def _gen_key(uid: str):
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid_obj = pgpy.PGPUID.new(uid)
    key.add_uid(
        uid_obj,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey)


@pytest.fixture(scope="module")
def alice_keys():
    return _gen_key("alice <alice@chef.skworld>")


def _env(**kw) -> Envelope:
    base = dict(
        from_fqid="alice@chef.skworld",
        to_fqid="lumina@chef.skworld",
        content_type="text/plain",
        body="established-contact DM",
        id="fixed-id",
        nonce="fixed-nonce",
        created_at="2026-01-01T00:00:00+00:00",
    )
    base.update(kw)
    return Envelope(**base)


class TestConsentTokenField:
    def test_defaults_absent(self):
        env = _env()
        assert env.consent_token is None

    def test_absent_token_is_byte_for_byte_legacy(self):
        # When no token is set, canonical bytes must be identical to an envelope
        # constructed the old way (no consent_token key present at all).
        env = _env()
        canonical = env.canonical_bytes()
        assert b"consent_token" not in canonical

    def test_present_token_enters_canonical(self):
        with_tok = _env(consent_token="deadbeef")
        without = _env()
        assert with_tok.canonical_bytes() != without.canonical_bytes()
        assert b"consent_token" in with_tok.canonical_bytes()

    def test_round_trip_to_from_dict(self):
        env = _env(consent_token="cafef00d")
        restored = Envelope.from_dict(env.to_dict())
        assert restored.consent_token == "cafef00d"
        assert restored.canonical_bytes() == env.canonical_bytes()

    def test_round_trip_to_from_bytes(self):
        env = _env(consent_token="cafef00d")
        restored = Envelope.from_bytes(env.to_bytes())
        assert restored.consent_token == "cafef00d"

    def test_signed_envelope_carries_token_through_bytes(self):
        env = _env(consent_token="0011aabb")
        signed = SignedEnvelope(envelope=env)
        restored = SignedEnvelope.from_bytes(signed.to_bytes())
        assert restored.envelope.consent_token == "0011aabb"


class TestConsentTokenSurvivesSignVerify:
    def test_sign_then_verify_with_token(self, alice_keys):
        from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

        priv, pub = alice_keys
        env = _env(consent_token="a" * 64)
        signed = EnvelopeSigner(priv).sign(env)

        verifier = EnvelopeVerifier()
        verifier.add_key("alice@chef.skworld", pub)
        result = verifier.verify(signed)
        assert result.valid, result.reason
        # And the token is still readable on the verified envelope.
        assert signed.envelope.consent_token == "a" * 64

    def test_tampered_token_fails_verify(self, alice_keys):
        from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

        priv, pub = alice_keys
        env = _env(consent_token="a" * 64)
        signed = EnvelopeSigner(priv).sign(env)

        # Forge: swap the token AFTER signing — the signature covers it, so verify must fail.
        forged_env = signed.envelope.model_copy(update={"consent_token": "b" * 64})
        forged = signed.model_copy(update={"envelope": forged_env})

        verifier = EnvelopeVerifier()
        verifier.add_key("alice@chef.skworld", pub)
        result = verifier.verify(forged)
        assert not result.valid
