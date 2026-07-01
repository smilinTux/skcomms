"""CRITICAL regression — signature verification binds key↔identity.

The bug: EnvelopeVerifier._find_key resolved the pubkey by the envelope's
self-asserted ``signer_fingerprint`` FIRST. In a multi-peer verifier (e.g. the
access-plane's TOFU keyring), a holder of ANY pinned key could sign a message
with their own key while setting ``from_fqid`` to a privileged identity — the
signature verified against the attacker's own key, but authorization keyed off
the forged ``from_fqid`` → spoofing / privilege-escalation → exec (RCE).

The fix resolves the key from the CLAIMED IDENTITY and never falls back to the
fingerprint when an identity is present. A forged from_fqid now resolves the
victim's key, against which the attacker's signature fails.
"""

from __future__ import annotations

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from skcomms.envelope import Envelope
from skcomms.signing import EnvelopeSigner, EnvelopeVerifier


def _make_key(uid: str):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return key


def _env(from_fqid: str) -> Envelope:
    return Envelope(
        from_fqid=from_fqid,
        to_fqid="opus@chef.skworld",
        body="authorize: exec rm -rf /",
    )


def test_legit_sender_still_verifies():
    lumina = _make_key("lumina")
    signed = EnvelopeSigner(str(lumina), "").sign(_env("lumina@chef.skworld"))

    v = EnvelopeVerifier()
    v.add_key("lumina@chef.skworld", str(lumina.pubkey))
    assert v.verify(signed).valid is True


def test_forged_from_fqid_signed_with_own_key_is_rejected():
    # Attacker (bob) is a pinned peer. They sign with THEIR key but claim to be
    # lumina. A multi-peer verifier has both keys pinned.
    lumina = _make_key("lumina")
    bob = _make_key("bob")

    forged = EnvelopeSigner(str(bob), "").sign(_env("lumina@chef.skworld"))

    v = EnvelopeVerifier()
    v.add_key("lumina@chef.skworld", str(lumina.pubkey))  # victim, exec-granted
    v.add_key("bob@chef.skworld", str(bob.pubkey))        # attacker, low-priv

    res = v.verify(forged)
    assert res.valid is False  # must NOT verify against bob's key for a lumina claim


def test_claimed_identity_with_no_registered_key_is_unknown_signer():
    # Attacker's key is pinned (by fingerprint), but the forged identity is not
    # registered → unknown signer, never a fingerprint-fallback pass.
    bob = _make_key("bob")
    forged = EnvelopeSigner(str(bob), "").sign(_env("ghost@chef.skworld"))

    v = EnvelopeVerifier()
    v.add_key("bob@chef.skworld", str(bob.pubkey))

    res = v.verify(forged)
    assert res.valid is False
    assert "Unknown signer" in res.reason
