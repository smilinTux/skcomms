"""Tests for SKFed P4 Nostr-relay store-and-forward (``skcomms.store_forward``).

Covers:
    - SEND: when the router's direct rails all fail, the S&F rail publishes an
      ENCRYPTED, recipient-addressed gift-wrap event (NIP-44) carrying the
      SignedEnvelope bytes, with the skfed S&F marker tag.
    - fqid → nostr_pubkey resolution off the discovery PeerStore.
    - PULL: the puller decrypts the gift wrap, parses the SignedEnvelope, runs
      federation.accept_signed (sig → freshness → nonce), and on success writes
      to the recipient inbox (same terminal step as POST /inbox).
    - IDEMPOTENCY: a replayed/redelivered event is delivered exactly once
      (relay event-id dedup + federation nonce cache).
    - OFFLINE → ONLINE: a deferred publish while the recipient is offline is
      delivered when the recipient later pulls.
    - SECURITY: an untrusted-signer / tampered envelope is rejected (not stored).
    - Router wiring: _try_store_forward selects the nostr-sf rail after direct
      rails fail; the S&F rail is excluded from direct candidate selection.

Relay I/O is faked (no network): a ``FakeRelay`` collects published events and
serves them back to queries, honoring ``kinds``, ``#p`` and ``#k`` filters.
"""

from __future__ import annotations

import pytest

from skcomms import federation as fed
from skcomms import store_forward as sf
from skcomms.envelope import Envelope, SignedEnvelope
from skcomms.signing import EnvelopeSigner, EnvelopeVerifier
from skcomms.transports.nostr import NOSTR_AVAILABLE, _pubkey_of, _random_secret

pytestmark = pytest.mark.skipif(
    not NOSTR_AVAILABLE, reason="nostr crypto deps (websockets/cryptography) not installed"
)


# ---------------------------------------------------------------------------
# PGP keys (real, in-process) so the federation accept gate is exercised end-to-end.
# ---------------------------------------------------------------------------


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
def alice_keys():
    return _gen_key("alice <jarvis@chef.skworld>")


@pytest.fixture(scope="module")
def mallory_keys():
    return _gen_key("mallory <evil@attacker.realm>")


FROM_FQID = "jarvis@chef.skworld"
TO_FQID = "lumina@chef.skworld"


def _signed(priv: str, body="hi", **kw) -> SignedEnvelope:
    env = Envelope(from_fqid=FROM_FQID, to_fqid=TO_FQID, body=body, **kw)
    return EnvelopeSigner(priv, "").sign(env)


# ---------------------------------------------------------------------------
# Fake relay (publish + query seams), honoring #p / #k / kinds filters.
# ---------------------------------------------------------------------------


class FakeRelay:
    def __init__(self):
        self.events: list[dict] = []

    def publish(self, event: dict) -> bool:
        self.events.append(event)
        return True

    def query(self, filters: dict) -> list:
        out = []
        kinds = filters.get("kinds")
        want_p = filters.get("#p")
        want_k = filters.get("#k")
        for ev in self.events:
            if kinds is not None and ev.get("kind") not in kinds:
                continue
            tags = ev.get("tags", [])
            if want_p is not None:
                ptags = [t[1] for t in tags if len(t) >= 2 and t[0] == "p"]
                if not any(p in want_p for p in ptags):
                    continue
            if want_k is not None:
                ktags = [t[1] for t in tags if len(t) >= 2 and t[0] == "k"]
                if not any(k in want_k for k in ktags):
                    continue
            out.append(ev)
        return out


@pytest.fixture
def relay():
    return FakeRelay()


@pytest.fixture
def recipient_secret():
    return _random_secret()


@pytest.fixture
def recipient_pubkey(recipient_secret):
    x, _ = _pubkey_of(recipient_secret)
    return x.hex()


# ---------------------------------------------------------------------------
# Event build / parse round-trip
# ---------------------------------------------------------------------------


class TestEventShape:
    def test_build_event_is_encrypted_and_addressed(self, alice_keys, recipient_pubkey):
        priv, _ = alice_keys
        signed = _signed(priv)
        ev = sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey)

        assert ev["kind"] == 1059  # gift wrap
        tags = ev["tags"]
        # addressed to the recipient (#p) + carries the skfed S&F marker (#k)
        assert ["p", recipient_pubkey] in tags
        assert ["k", sf.SKFED_SF_MARKER] in tags
        # content is opaque ciphertext, NOT the plaintext envelope
        assert FROM_FQID not in ev["content"]
        assert "signature" not in ev["content"]

    def test_parse_round_trip(self, alice_keys, recipient_secret, recipient_pubkey):
        priv, _ = alice_keys
        signed = _signed(priv, body="round-trip")
        ev = sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey)

        parsed = sf.parse_store_forward_event(ev, recipient_secret)
        assert isinstance(parsed, SignedEnvelope)
        assert parsed.envelope.body == "round-trip"
        assert parsed.envelope.from_fqid == FROM_FQID

    def test_wrong_recipient_cannot_decrypt(self, alice_keys, recipient_pubkey):
        priv, _ = alice_keys
        signed = _signed(priv)
        ev = sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey)
        # A different node's secret must not decrypt it.
        assert sf.parse_store_forward_event(ev, _random_secret()) is None


# ---------------------------------------------------------------------------
# fqid → pubkey resolution
# ---------------------------------------------------------------------------


class TestResolveNostrPubkey:
    def test_resolve_from_peerstore(self, tmp_path, monkeypatch, recipient_pubkey):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.discovery import PeerInfo, PeerStore

        store = PeerStore(peers_dir=tmp_path / "home" / "peers")
        store.add(PeerInfo(name="lumina", fqid=TO_FQID, nostr_pubkey=recipient_pubkey))

        assert sf.resolve_nostr_pubkey(TO_FQID, store=store) == recipient_pubkey
        assert sf.resolve_nostr_pubkey("lumina", store=store) == recipient_pubkey

    def test_literal_hex_passthrough(self, recipient_pubkey):
        assert sf.resolve_nostr_pubkey(recipient_pubkey) == recipient_pubkey

    def test_unknown_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.discovery import PeerStore

        store = PeerStore(peers_dir=tmp_path / "home" / "peers")
        assert sf.resolve_nostr_pubkey("ghost@nowhere.realm", store=store) is None


# ---------------------------------------------------------------------------
# Send rail
# ---------------------------------------------------------------------------


class TestSendRail:
    def test_send_publishes_addressed_encrypted_event(
        self, relay, tmp_path, monkeypatch, alice_keys, recipient_pubkey
    ):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.discovery import PeerInfo, PeerStore

        store = PeerStore(peers_dir=tmp_path / "home" / "peers")
        store.add(PeerInfo(name="lumina", fqid=TO_FQID, nostr_pubkey=recipient_pubkey))

        rail = sf.StoreForwardTransport(store=store, publish=relay.publish)
        priv, _ = alice_keys
        signed = _signed(priv)

        result = rail.send(signed.to_bytes(), TO_FQID)
        assert result.success
        assert len(relay.events) == 1
        assert ["p", recipient_pubkey] in relay.events[0]["tags"]

    def test_send_fails_when_pubkey_unknown(self, relay, tmp_path, monkeypatch, alice_keys):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.discovery import PeerStore

        store = PeerStore(peers_dir=tmp_path / "home" / "peers")
        rail = sf.StoreForwardTransport(store=store, publish=relay.publish)
        priv, _ = alice_keys
        result = rail.send(_signed(priv).to_bytes(), "ghost@nowhere.realm")
        assert not result.success
        assert "no nostr_pubkey" in (result.error or "")
        assert relay.events == []


# ---------------------------------------------------------------------------
# Pull side — accept_signed + inbox write + idempotency
# ---------------------------------------------------------------------------


def _puller(relay, recipient_secret, alice_pub, *, nonce_cache=None, sink=None):
    """Build a puller with a trusting verifier for alice + an in-memory sink."""
    delivered = sink if sink is not None else []

    def verifier_factory(from_fqid: str):
        v = EnvelopeVerifier()
        v.add_key(from_fqid, alice_pub)
        return v

    def deliver(env) -> str:
        delivered.append(env)
        return env.id

    p = sf.StoreForwardPuller(
        recipient_secret,
        relays=[],
        nonce_cache=nonce_cache or fed.NonceCache(),
        query=relay.query,
        deliver=deliver,
        verifier_factory=verifier_factory,
    )
    return p, delivered


class TestPull:
    def test_pull_decrypts_accepts_delivers(
        self, relay, recipient_secret, recipient_pubkey, alice_keys
    ):
        priv, pub = alice_keys
        signed = _signed(priv, body="deferred")
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))

        puller, delivered = _puller(relay, recipient_secret, pub)
        refs = puller.pull()

        assert len(refs) == 1
        assert len(delivered) == 1
        assert delivered[0].body == "deferred"
        assert delivered[0].from_fqid == FROM_FQID

    def test_offline_then_online_deferred_delivery(
        self, relay, recipient_secret, recipient_pubkey, alice_keys
    ):
        priv, pub = alice_keys
        # Sender publishes while the recipient is offline (no puller running).
        signed = _signed(priv, body="while-you-were-out")
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))

        # Recipient comes online later and pulls — gets the deferred message.
        puller, delivered = _puller(relay, recipient_secret, pub)
        assert puller.pull()
        assert delivered[0].body == "while-you-were-out"

    def test_idempotent_redelivery_same_puller(
        self, relay, recipient_secret, recipient_pubkey, alice_keys
    ):
        priv, pub = alice_keys
        signed = _signed(priv)
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))

        puller, delivered = _puller(relay, recipient_secret, pub)
        assert len(puller.pull()) == 1
        # Second sweep over the same relay state delivers nothing new (event-id dedup).
        assert puller.pull() == []
        assert len(delivered) == 1

    def test_idempotent_across_pullers_via_nonce_cache(
        self, relay, recipient_secret, recipient_pubkey, alice_keys
    ):
        priv, pub = alice_keys
        signed = _signed(priv)
        # Same envelope published twice as DISTINCT relay events (re-send/retry):
        # event-id dedup won't catch it, but the shared nonce cache must.
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))

        shared_nonce = fed.NonceCache()
        sink: list = []
        p1, _ = _puller(relay, recipient_secret, pub, nonce_cache=shared_nonce, sink=sink)
        p2, _ = _puller(relay, recipient_secret, pub, nonce_cache=shared_nonce, sink=sink)
        p1.pull()
        p2.pull()
        # Two relay events, same envelope nonce → delivered exactly once.
        assert len(sink) == 1


class TestPullSecurity:
    def test_untrusted_signer_rejected(
        self, relay, recipient_secret, recipient_pubkey, alice_keys, mallory_keys
    ):
        # Mallory signs but the verifier only trusts alice's key for FROM_FQID.
        mal_priv, _ = mallory_keys
        signed = _signed(mal_priv, body="forged")  # claims from_fqid = jarvis
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))

        _, alice_pub = alice_keys
        puller, delivered = _puller(relay, recipient_secret, alice_pub)
        assert puller.pull() == []
        assert delivered == []

    def test_tampered_envelope_rejected(
        self, relay, recipient_secret, recipient_pubkey, alice_keys
    ):
        priv, pub = alice_keys
        signed = _signed(priv, body="original")
        # Tamper with the body AFTER signing → signature no longer matches.
        signed.envelope.body = "tampered"
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))

        puller, delivered = _puller(relay, recipient_secret, pub)
        assert puller.pull() == []
        assert delivered == []

    def test_stale_envelope_rejected(
        self, relay, recipient_secret, recipient_pubkey, alice_keys
    ):
        from datetime import datetime, timedelta, timezone

        priv, pub = alice_keys
        old = (datetime.now(timezone.utc) - timedelta(seconds=99999)).isoformat()
        signed = _signed(priv, body="ancient", created_at=old)
        relay.publish(sf.build_store_forward_event(signed.to_bytes(), recipient_pubkey))

        puller, delivered = _puller(relay, recipient_secret, pub)
        assert puller.pull() == []
        assert delivered == []


# ---------------------------------------------------------------------------
# Router wiring — store-forward fallback selects the nostr-sf rail
# ---------------------------------------------------------------------------


class _DeadRail:
    """A direct rail that always fails (forces store-forward fallback)."""

    from skcomms.transport import TransportCategory as TC

    name = "https-s2s"
    priority = 1
    category = TC.REALTIME

    def configure(self, config):  # pragma: no cover - unused
        pass

    def is_available(self):
        return True

    def send(self, envelope_bytes, recipient):
        from skcomms.transport import SendResult

        return SendResult(success=False, transport_name=self.name, envelope_id="",
                          error="dead")

    def receive(self):
        return []

    def health_check(self):  # pragma: no cover - unused
        from skcomms.transport import HealthStatus, TransportStatus

        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


class TestRouterWiring:
    def test_store_forward_used_after_direct_rails_fail(
        self, relay, tmp_path, monkeypatch, alice_keys, recipient_pubkey
    ):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.discovery import PeerInfo, PeerStore
        from skcomms.router import Router

        store = PeerStore(peers_dir=tmp_path / "home" / "peers")
        store.add(PeerInfo(name="lumina", fqid=TO_FQID, nostr_pubkey=recipient_pubkey))

        sf_rail = sf.StoreForwardTransport(store=store, publish=relay.publish)
        router = Router(
            transports=[_DeadRail(), sf_rail],
            store_forward_transport=sf.STORE_FORWARD_RAIL,
        )

        priv, _ = alice_keys
        signed = _signed(priv)
        report = router.route_signed(signed)

        assert report.delivered
        assert report.successful_transport == sf.STORE_FORWARD_RAIL
        assert len(relay.events) == 1

    def test_sf_rail_excluded_from_direct_candidates(
        self, relay, tmp_path, monkeypatch, alice_keys, recipient_pubkey
    ):
        # With ONLY the S&F rail registered (no direct rails), a route still
        # succeeds — but via the store-forward fallback, proving the rail is not
        # used as a direct candidate (it would otherwise be the only candidate
        # and we could not distinguish). We assert it lands via _try_store_forward
        # by checking the rail is absent from the failover attempts.
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.discovery import PeerInfo, PeerStore
        from skcomms.router import Router

        store = PeerStore(peers_dir=tmp_path / "home" / "peers")
        store.add(PeerInfo(name="lumina", fqid=TO_FQID, nostr_pubkey=recipient_pubkey))

        sf_rail = sf.StoreForwardTransport(store=store, publish=relay.publish)
        router = Router(
            transports=[sf_rail], store_forward_transport=sf.STORE_FORWARD_RAIL
        )

        candidates = router._select_transports(
            router._default_mode,
            __import__("skcomms.models", fromlist=["MessageEnvelope"]).MessageEnvelope(
                sender="x", recipient=TO_FQID,
                payload=__import__("skcomms.models", fromlist=["MessagePayload"]).MessagePayload(content=""),
            ),
        )
        assert sf_rail not in candidates  # never a direct candidate

        priv, _ = alice_keys
        report = router.route_signed(_signed(priv))
        assert report.delivered
        assert report.successful_transport == sf.STORE_FORWARD_RAIL
