"""Tests for subscribable signed ban/policy feeds (consent gate 3).

Matrix MSC2313 model: anyone publishes a signed ban feed, anyone
subscribes to + blends multiple feeds. No central blocklist. Each feed is
CapAuth-signed by its publisher (:class:`skcomms.signing.EnvelopeSigner`) and
verified per-publisher (fail-closed: an unverified feed is ignored entirely).

PGP keys are generated in-process via pgpy (no live CapAuth), mirroring
tests/test_skfed_directory.py.
"""

from __future__ import annotations

import pytest


# --- in-process key fixtures (mirror tests/test_skfed_directory.py) ---------


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
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey)


@pytest.fixture(scope="module")
def pub_a_keys():
    """Publisher A's ban-feed signing key."""
    return _gen_key("mod-a <mod@trust-a.skworld>")


@pytest.fixture(scope="module")
def pub_b_keys():
    """Publisher B's ban-feed signing key."""
    return _gen_key("mod-b <mod@trust-b.skworld>")


@pytest.fixture(scope="module")
def attacker_keys():
    return _gen_key("evil <evil@attacker.realm>")


PUB_A = "mod@trust-a.skworld"
PUB_B = "mod@trust-b.skworld"


def _build_feed(publisher, priv, entries):
    from skcomms.consent_banfeeds import BanFeed
    from skcomms.signing import EnvelopeSigner

    signer = EnvelopeSigner(priv)
    return BanFeed.build(publisher=publisher, entries=entries, signer=signer)


# --- build / sign / verify roundtrip ---------------------------------------


def test_build_sign_verify_roundtrip(pub_a_keys):
    priv, pub = pub_a_keys
    from skcomms.signing import EnvelopeVerifier

    feed = _build_feed(
        PUB_A,
        priv,
        [{"entity": "evil@attacker.realm", "recommendation": "ban", "reason": "spam"}],
    )
    assert feed.sig
    assert feed.signer_fingerprint
    assert len(feed.entries) == 1

    verifier = EnvelopeVerifier()
    verifier.add_key(PUB_A, pub)
    assert feed.verify(verifier) is True


def test_verify_fails_for_wrong_key(pub_a_keys, attacker_keys):
    priv, _pub = pub_a_keys
    _apriv, apub = attacker_keys
    from skcomms.signing import EnvelopeVerifier

    feed = _build_feed(PUB_A, priv, [{"entity": "x@y.z", "reason": "n"}])
    verifier = EnvelopeVerifier()
    verifier.add_key(PUB_A, apub)  # wrong key under publisher label
    assert feed.verify(verifier) is False


def test_verify_detects_tamper(pub_a_keys):
    priv, pub = pub_a_keys
    from skcomms.consent_banfeeds import BanEntry
    from skcomms.signing import EnvelopeVerifier

    feed = _build_feed(PUB_A, priv, [{"entity": "spammer@x.realm", "reason": "spam"}])
    # Tamper: widen the ban to a whole realm after signing.
    feed.entries[0] = BanEntry(entity="*@x.realm", recommendation="ban", reason="spam")
    verifier = EnvelopeVerifier()
    verifier.add_key(PUB_A, pub)
    assert feed.verify(verifier) is False


# --- glob matching ---------------------------------------------------------


def test_glob_match_star_and_question(pub_a_keys):
    priv, pub = pub_a_keys
    from skcomms.consent_banfeeds import FeedSubscription
    from skcomms.signing import EnvelopeVerifier

    feed = _build_feed(
        PUB_A,
        priv,
        [
            {"entity": "*@attacker.realm", "reason": "bad realm"},
            {"entity": "bot?@spam.io", "reason": "bot swarm"},
        ],
    )
    verifier = EnvelopeVerifier()
    verifier.add_key(PUB_A, pub)

    sub = FeedSubscription()
    assert sub.subscribe(feed, verifier) is True

    # glob '*' matches any agent in the realm
    assert sub.is_banned("evil@attacker.realm") is True
    assert sub.is_banned("anyone@attacker.realm") is True
    # glob '?' matches exactly one char
    assert sub.is_banned("bot7@spam.io") is True
    assert sub.is_banned("bot77@spam.io") is False  # two chars -> no match
    # unrelated fqid is clean
    assert sub.is_banned("friend@chef.skworld") is False


# --- blend across two feeds ------------------------------------------------


def test_blend_across_two_feeds(pub_a_keys, pub_b_keys):
    apriv, apub = pub_a_keys
    bpriv, bpub = pub_b_keys
    from skcomms.consent_banfeeds import FeedSubscription
    from skcomms.signing import EnvelopeVerifier

    feed_a = _build_feed(PUB_A, apriv, [{"entity": "a-bad@x.realm", "reason": "a"}])
    feed_b = _build_feed(PUB_B, bpriv, [{"entity": "b-bad@y.realm", "reason": "b"}])

    va = EnvelopeVerifier()
    va.add_key(PUB_A, apub)
    vb = EnvelopeVerifier()
    vb.add_key(PUB_B, bpub)

    sub = FeedSubscription()
    assert sub.subscribe(feed_a, va) is True
    assert sub.subscribe(feed_b, vb) is True

    # banned if on EITHER feed (blended)
    assert sub.is_banned("a-bad@x.realm") is True
    assert sub.is_banned("b-bad@y.realm") is True
    assert sub.is_banned("clean@z.realm") is False
    assert sub.feed_count == 2


# --- fail-closed: unverified feed ignored ----------------------------------


def test_unverified_feed_is_ignored(pub_a_keys, attacker_keys):
    priv, pub = pub_a_keys
    _apriv, apub = attacker_keys
    from skcomms.consent_banfeeds import FeedSubscription
    from skcomms.signing import EnvelopeVerifier

    feed = _build_feed(PUB_A, priv, [{"entity": "victim@x.realm", "reason": "fake"}])

    # Verifier pinned to the WRONG key for this publisher -> verification fails.
    bad_verifier = EnvelopeVerifier()
    bad_verifier.add_key(PUB_A, apub)

    sub = FeedSubscription()
    assert sub.subscribe(feed, bad_verifier) is False  # rejected
    assert sub.feed_count == 0
    # fail-closed: nothing from the unverified feed influences the blend
    assert sub.is_banned("victim@x.realm") is False


def test_unsigned_feed_is_ignored(pub_a_keys):
    priv, pub = pub_a_keys
    from skcomms.consent_banfeeds import BanFeed
    from skcomms.signing import EnvelopeVerifier

    # An unsigned feed (no build/sign) must never verify.
    feed = BanFeed(publisher=PUB_A, entries=[])
    verifier = EnvelopeVerifier()
    verifier.add_key(PUB_A, pub)
    assert feed.verify(verifier) is False

    from skcomms.consent_banfeeds import FeedSubscription

    sub = FeedSubscription()
    assert sub.subscribe(feed, verifier) is False
    assert sub.feed_count == 0
