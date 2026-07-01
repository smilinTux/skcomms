"""Tests for hybrid SignedEnvelope signing/verification (PQC Q7) + back-compat.

Proves:
  * A HybridEnvelopeSigner produces a SignedEnvelope with sig_suite
    ``mldsa65-ed25519-v2`` that EnvelopeVerifier accepts (both legs).
  * The hybrid envelope survives a JSON serialization round-trip.
  * Tampering the body fails hybrid verification.
  * The CLASSICAL path is byte-for-byte unchanged: a classical SignedEnvelope's
    sig_suite default is ``ed25519-v1``, the new hybrid fields are ``None``, and
    ``is_hybrid`` is False (so it never enters the hybrid verify path).
"""

from __future__ import annotations

import pytest

from skcomms import pqsig
from skcomms.envelope import (
    CLASSICAL_SIG_SUITE,
    HYBRID_SIG_SUITE,
    Envelope,
    SignedEnvelope,
)
from skcomms.signing import EnvelopeVerifier, HybridEnvelopeSigner


def _env() -> Envelope:
    return Envelope(
        from_fqid="lumina@chef.skworld",
        to_fqid="opus@chef.skworld",
        body="quantum-resistant per-message auth",
    )


pq = pytest.mark.skipif(not pqsig.is_available(), reason="liboqs (oqs) not available")


# ---------------------------------------------------------------------------
# Hybrid path
# ---------------------------------------------------------------------------


def _bound_verifier(kp) -> EnvelopeVerifier:
    """A verifier with the hybrid signer pinned to the envelope's from_fqid."""
    v = EnvelopeVerifier()
    v.add_hybrid_key("lumina@chef.skworld", kp.mldsa_pub)
    return v


@pq
def test_hybrid_sign_and_verify():
    kp = pqsig.generate_keypair()
    signer = HybridEnvelopeSigner(keypair=kp, signer_id="lumina")
    signed = signer.sign(_env())
    assert signed.sig_suite == HYBRID_SIG_SUITE
    assert signed.is_hybrid is True
    assert signed.hybrid_ed25519_pub and signed.hybrid_mldsa_pub

    res = _bound_verifier(kp).verify(signed)
    assert res.valid is True
    assert "ML-DSA-65" in res.reason and "FIPS 204" in res.reason


@pq
def test_hybrid_survives_json_roundtrip():
    kp = pqsig.generate_keypair()
    signed = HybridEnvelopeSigner(keypair=kp, signer_id="lumina").sign(_env())
    restored = SignedEnvelope.from_bytes(signed.to_bytes())
    assert restored.is_hybrid is True
    assert _bound_verifier(kp).verify(restored).valid is True


@pq
def test_hybrid_tampered_body_fails():
    kp = pqsig.generate_keypair()
    signed = HybridEnvelopeSigner(keypair=kp, signer_id="lumina").sign(_env())
    tampered = SignedEnvelope.from_bytes(signed.to_bytes())
    tampered.envelope.body = "MALICIOUSLY ALTERED"
    assert _bound_verifier(kp).verify(tampered).valid is False


@pq
def test_hybrid_unpinned_identity_is_rejected():
    """A cryptographically-valid hybrid envelope from an identity with NO pinned
    hybrid key must FAIL CLOSED — the inline keys are attacker-controlled."""
    kp = pqsig.generate_keypair()
    signed = HybridEnvelopeSigner(keypair=kp, signer_id="lumina").sign(_env())
    res = EnvelopeVerifier().verify(signed)  # no add_hybrid_key
    assert res.valid is False
    assert "Unknown hybrid signer" in res.reason


@pq
def test_hybrid_forged_inline_keys_impersonation_is_rejected():
    """The core CRITICAL: attacker signs with THEIR OWN hybrid keypair but sets
    from_fqid to the victim. The verifier has the victim pinned to a DIFFERENT
    key. Verification must reject (no universal forgery)."""
    victim_kp = pqsig.generate_keypair()
    attacker_kp = pqsig.generate_keypair()
    # Attacker forges a message "from" the victim, signed with attacker's keys.
    forged = HybridEnvelopeSigner(keypair=attacker_kp, signer_id="attacker").sign(_env())
    v = EnvelopeVerifier()
    v.add_hybrid_key("lumina@chef.skworld", victim_kp.mldsa_pub)  # victim's real key
    res = v.verify(forged)
    assert res.valid is False
    assert "mismatch" in res.reason.lower()


@pq
def test_hybrid_envelope_missing_pubkeys_is_not_verified():
    """A hybrid sig_suite without the inline pubkeys is reported invalid (not a
    crash) — defends against a stripped/forged hybrid envelope."""
    kp = pqsig.generate_keypair()
    signed = HybridEnvelopeSigner(keypair=kp, signer_id="lumina").sign(_env())
    broken = SignedEnvelope.from_bytes(signed.to_bytes())
    broken.hybrid_mldsa_pub = None
    assert broken.is_hybrid is False
    res = EnvelopeVerifier().verify(broken)
    assert res.valid is False


# ---------------------------------------------------------------------------
# Classical back-compat — byte-for-byte unchanged
# ---------------------------------------------------------------------------


def test_classical_signed_envelope_defaults_unchanged():
    """A SignedEnvelope built the old way is classical, non-hybrid, and the new
    fields default to None — old serialized envelopes parse identically."""
    se = SignedEnvelope(
        envelope=_env(),
        signature="-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
        signer_fingerprint="A" * 40,
        content_hash="deadbeef",
    )
    assert se.sig_suite == CLASSICAL_SIG_SUITE == "ed25519-v1"
    assert se.hybrid_ed25519_pub is None
    assert se.hybrid_mldsa_pub is None
    assert se.is_hybrid is False


def test_old_serialized_envelope_without_new_fields_parses():
    """An envelope JSON predating the hybrid fields still deserializes (the new
    fields are optional with None defaults)."""
    old_json = (
        b'{"envelope":{"version":"1","id":"x","nonce":"n",'
        b'"from_fqid":"a@b.c","to_fqid":"d@e.f","created_at":"2026-01-01T00:00:00+00:00",'
        b'"content_type":"text/plain","body":"hi","subject":null,"thread_id":null,'
        b'"reply_to":null,"headers":{}},'
        b'"signature":"sig","signer_fingerprint":"FP","signed_at":"2026-01-01T00:00:00+00:00",'
        b'"content_hash":"hash","sig_suite":"ed25519-v1"}'
    )
    se = SignedEnvelope.from_bytes(old_json)
    assert se.is_hybrid is False
    assert se.sig_suite == "ed25519-v1"
    assert se.hybrid_ed25519_pub is None
