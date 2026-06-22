"""Tests for Envelope v1 schema + signing (T5, ``38b146c6``).

Covers:
    - envelope.py: Envelope schema validation, canonical_bytes stability,
      to_dict/from_dict round-trip.
    - signing.py: sign Envelope v1 -> verify happy path, tamper -> fail,
      wrong-key -> fail.

PGP keys are generated in-process via pgpy (no live CapAuth needed).
"""

from __future__ import annotations

import pytest

from skcomms.envelope import Envelope, SignedEnvelope


# ---------------------------------------------------------------------------
# PGP key fixtures (generated in-process)
# ---------------------------------------------------------------------------


def _gen_key(uid: str):
    """Generate a fresh PGP keypair, return (private_armor, public_armor)."""
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


@pytest.fixture(scope="module")
def bob_keys():
    return _gen_key("bob <bob@chef.skworld>")


@pytest.fixture
def sample_envelope() -> Envelope:
    return Envelope(
        from_fqid="lumina@chef.skworld",
        to_fqid="opus@chef.skworld",
        content_type="text/plain",
        body="hello sovereign world",
        subject="greetings",
    )


# ---------------------------------------------------------------------------
# Envelope schema
# ---------------------------------------------------------------------------


class TestEnvelopeSchema:
    def test_defaults_populated(self, sample_envelope):
        env = sample_envelope
        assert env.version == "1"
        assert env.id  # uuid auto-assigned
        assert env.created_at  # iso timestamp auto-assigned
        assert env.from_fqid == "lumina@chef.skworld"
        assert env.to_fqid == "opus@chef.skworld"
        assert env.content_type == "text/plain"
        assert env.body == "hello sovereign world"
        assert env.subject == "greetings"
        # optionals default to None / empty
        assert env.thread_id is None
        assert env.reply_to is None
        assert env.headers == {}

    def test_requires_from_and_to(self):
        with pytest.raises(Exception):
            Envelope(to_fqid="opus@chef.skworld", body="x", content_type="text/plain")
        with pytest.raises(Exception):
            Envelope(from_fqid="lumina@chef.skworld", body="x", content_type="text/plain")

    def test_created_at_is_utc_iso(self, sample_envelope):
        # parseable ISO-8601 with timezone
        from datetime import datetime

        parsed = datetime.fromisoformat(sample_envelope.created_at)
        assert parsed.tzinfo is not None


class TestCanonicalBytes:
    def test_stable_across_calls(self, sample_envelope):
        assert sample_envelope.canonical_bytes() == sample_envelope.canonical_bytes()

    def test_independent_of_field_order(self):
        a = Envelope(
            from_fqid="a@chef.skworld",
            to_fqid="b@chef.skworld",
            content_type="text/plain",
            body="hi",
            id="fixed-id",
            nonce="fixed-nonce",
            created_at="2026-01-01T00:00:00+00:00",
        )
        b = Envelope(
            body="hi",
            to_fqid="b@chef.skworld",
            content_type="text/plain",
            from_fqid="a@chef.skworld",
            created_at="2026-01-01T00:00:00+00:00",
            nonce="fixed-nonce",
            id="fixed-id",
        )
        assert a.canonical_bytes() == b.canonical_bytes()

    def test_changes_when_body_changes(self, sample_envelope):
        other = sample_envelope.model_copy(update={"body": "tampered"})
        assert sample_envelope.canonical_bytes() != other.canonical_bytes()

    def test_round_trip_to_from_dict(self, sample_envelope):
        d = sample_envelope.to_dict()
        restored = Envelope.from_dict(d)
        assert restored.canonical_bytes() == sample_envelope.canonical_bytes()
        assert restored.id == sample_envelope.id


# ---------------------------------------------------------------------------
# Signing over Envelope v1
# ---------------------------------------------------------------------------


class TestSignVerify:
    def test_sign_then_verify_happy_path(self, sample_envelope, alice_keys):
        from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

        priv, pub = alice_keys
        signer = EnvelopeSigner(priv, "")
        signed = signer.sign(sample_envelope)

        assert isinstance(signed, SignedEnvelope)
        assert signed.signature
        assert signed.signer_fingerprint == signer.fingerprint

        verifier = EnvelopeVerifier()
        verifier.add_key("lumina@chef.skworld", pub)
        result = verifier.verify(signed)
        assert result.valid, result.reason

    def test_tamper_body_fails_verify(self, sample_envelope, alice_keys):
        from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

        priv, pub = alice_keys
        signer = EnvelopeSigner(priv, "")
        signed = signer.sign(sample_envelope)

        # tamper with the envelope body after signing
        tampered_env = signed.envelope.model_copy(update={"body": "evil payload"})
        tampered = signed.model_copy(update={"envelope": tampered_env})

        verifier = EnvelopeVerifier()
        verifier.add_key("lumina@chef.skworld", pub)
        result = verifier.verify(tampered)
        assert not result.valid

    def test_wrong_key_fails_verify(self, sample_envelope, alice_keys, bob_keys):
        from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

        alice_priv, _ = alice_keys
        _, bob_pub = bob_keys
        signer = EnvelopeSigner(alice_priv, "")
        signed = signer.sign(sample_envelope)

        # verifier only knows bob's key, registered under the sender's fqid
        verifier = EnvelopeVerifier()
        verifier.add_key("lumina@chef.skworld", bob_pub)
        result = verifier.verify(signed)
        assert not result.valid
