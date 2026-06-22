"""Tests for skcomms.federation — canonical envelope receive-side guards.

Covers the nonce field on Envelope v1 plus the federation accept gate
(signature + freshness + replay) that every rail's inbox runs. PGP keys are
generated in-process via pgpy (no live CapAuth needed).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from skcomms.envelope import Envelope, SignedEnvelope
from skcomms.signing import EnvelopeSigner, EnvelopeVerifier
from skcomms import federation as fed


def _gen_key(uid: str):
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm, HashAlgorithm, KeyFlags,
        PubKeyAlgorithm, SymmetricKeyAlgorithm,
    )
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey)


@pytest.fixture(scope="module")
def alice_keys():
    return _gen_key("alice <jarvis@chef.skworld>")


@pytest.fixture(scope="module")
def bob_keys():
    return _gen_key("bob <evil@attacker.realm>")


def _env(body="hi", **kw) -> Envelope:
    return Envelope(from_fqid="jarvis@chef.skworld", to_fqid="lumina@chef.skworld",
                    body=body, **kw)


# --- nonce field -----------------------------------------------------------

class TestNonce:
    def test_nonce_auto_and_unique(self):
        a, b = _env(), _env()
        assert a.nonce and b.nonce
        assert a.nonce != b.nonce          # fresh per message
        assert a.id != a.nonce             # distinct from id

    def test_nonce_in_canonical_bytes(self):
        e = _env()
        assert e.nonce.encode() in e.canonical_bytes()


# --- NonceCache ------------------------------------------------------------

class TestNonceCache:
    def test_first_seen_then_replay(self):
        c = fed.NonceCache()
        assert c.check_and_add("jarvis@chef.skworld", "n1") is True
        assert c.check_and_add("jarvis@chef.skworld", "n1") is False   # replay
        assert c.check_and_add("lumina@chef.skworld", "n1") is True    # per-sender

    def test_ttl_eviction(self):
        c = fed.NonceCache(ttl_s=10)
        assert c.check_and_add("a", "n", now=1000) is True
        # same nonce after TTL expiry is accepted again (entry evicted)
        assert c.check_and_add("a", "n", now=2000) is True


# --- freshness -------------------------------------------------------------

class TestFreshness:
    def test_fresh_ok(self):
        fed.check_freshness(_env())

    def test_too_old(self):
        old = (datetime.now(timezone.utc) - timedelta(seconds=999)).isoformat()
        with pytest.raises(fed.StaleError):
            fed.check_freshness(_env(created_at=old))

    def test_future_dated(self):
        future = (datetime.now(timezone.utc) + timedelta(seconds=999)).isoformat()
        with pytest.raises(fed.StaleError):
            fed.check_freshness(_env(created_at=future))


# --- accept_signed (full gate) --------------------------------------------

class TestAcceptSigned:
    def _signed(self, keys, **kw) -> SignedEnvelope:
        priv, _ = keys
        return EnvelopeSigner(priv, "").sign(_env(**kw))

    def test_happy_path(self, alice_keys):
        _, pub = alice_keys
        v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", pub)
        env = fed.accept_signed(self._signed(alice_keys), verifier=v,
                                nonce_cache=fed.NonceCache())
        assert env.from_fqid == "jarvis@chef.skworld" and env.body == "hi"

    def test_replay_rejected(self, alice_keys):
        _, pub = alice_keys
        v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", pub)
        nc = fed.NonceCache()
        signed = self._signed(alice_keys)
        fed.accept_signed(signed, verifier=v, nonce_cache=nc)
        with pytest.raises(fed.ReplayError):
            fed.accept_signed(signed, verifier=v, nonce_cache=nc)   # same nonce

    def test_unsigned_rejected(self, alice_keys):
        v = EnvelopeVerifier()
        bare = SignedEnvelope(envelope=_env())   # no signature
        with pytest.raises(fed.SignatureError):
            fed.accept_signed(bare, verifier=v, nonce_cache=fed.NonceCache())

    def test_untrusted_signer_rejected(self, alice_keys, bob_keys):
        # signed by bob, but verifier only knows alice's key for that fqid
        _, alice_pub = alice_keys
        v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", alice_pub)
        signed = self._signed(bob_keys)
        with pytest.raises(fed.SignatureError):
            fed.accept_signed(signed, verifier=v, nonce_cache=fed.NonceCache())

    def test_stale_rejected(self, alice_keys):
        _, pub = alice_keys
        v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", pub)
        old = (datetime.now(timezone.utc) - timedelta(seconds=999)).isoformat()
        with pytest.raises(fed.StaleError):
            fed.accept_signed(self._signed(alice_keys, created_at=old),
                              verifier=v, nonce_cache=fed.NonceCache())

    def test_accept_bytes_roundtrip(self, alice_keys):
        _, pub = alice_keys
        v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", pub)
        raw = self._signed(alice_keys).to_bytes()
        env = fed.accept_bytes(raw, verifier=v, nonce_cache=fed.NonceCache())
        assert env.to_fqid == "lumina@chef.skworld"
