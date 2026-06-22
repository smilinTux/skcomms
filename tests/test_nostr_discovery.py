"""Tests for SKFed P3 Nostr auto-discovery (``skcomms.nostr_discovery``).

Covers:
    - build/parse directory event round-trip (kind 30079, d-tag = fqid).
    - publish_directory pushes a directory record through the (fake) relay.
    - resolve_peer parses a published record and UPSERTs a PeerInfo carrying the
      https-s2s inbox_url + the TOFU-pinned capauth pubkey.
    - discover_all auto-seeds multiple peers from the relay (idempotent re-sync).
    - TOFU: a *changed* capauth key for a known fqid is a CONFLICT → rejected,
      the pinned key left untouched.
    - replaceable semantics: the newest record per fqid wins.
    - ensure_peer: known peer returned as-is; unknown fqid triggers a resolve.

Relay I/O is faked (no network): a ``FakeRelay`` collects published events and
serves them back to queries, honoring ``kinds`` and ``#d`` filters.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Real PGP keys so TOFU fingerprint pinning exercises genuine armored blobs.
# Generated once per module — two distinct identities (A) and (A-changed).
# ---------------------------------------------------------------------------


def _gen_pubkey() -> str:
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = pgpy.PGPUID.new("skfed-test")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key.pubkey)


@pytest.fixture(scope="module")
def pubkey_a() -> str:
    return _gen_pubkey()


@pytest.fixture(scope="module")
def pubkey_a_changed() -> str:
    return _gen_pubkey()


@pytest.fixture(scope="module")
def pubkey_b() -> str:
    return _gen_pubkey()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolated SKCOMMS_HOME so PeerStore + TOFU store are per-test."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


class FakeRelay:
    """In-memory stand-in for a Nostr relay (publish seam + query seam)."""

    def __init__(self):
        self.events: list[dict] = []

    def publish(self, event: dict) -> bool:
        # Replaceable: drop any prior event with the same d-tag (per fqid).
        dtag = _dtag(event)
        if dtag is not None:
            self.events = [e for e in self.events if _dtag(e) != dtag]
        self.events.append(event)
        return True

    def query(self, filters: dict) -> list:
        out = []
        kinds = filters.get("kinds")
        want_d = filters.get("#d")
        for ev in self.events:
            if kinds is not None and ev.get("kind") not in kinds:
                continue
            if want_d is not None and _dtag(ev) not in want_d:
                continue
            out.append(ev)
        return out


def _dtag(event: dict):
    for tag in event.get("tags", []):
        if tag and tag[0] == "d":
            return tag[1]
    return None


def _store():
    """Env-aware PeerStore (honors SKCOMMS_HOME) — matches the module default."""
    from skcomms.nostr_discovery import _default_store

    return _default_store()


def _client(relay: FakeRelay):
    from skcomms.nostr_discovery import NostrDirectory

    return NostrDirectory(
        relays=[],
        store=_store(),
        publish=relay.publish,
        query=relay.query,
    )


def _record(fqid, node, pubkey, ts=1_750_000_000):
    return {
        "fqid": fqid,
        "node": node,
        "inbox_url": f"https://{node}/api/v1/inbox",
        "pubkey": pubkey,
        "rails": ["https-s2s", "syncthing", "nostr"],
        "ts": ts,
    }


# ---------------------------------------------------------------------------
# Event codec
# ---------------------------------------------------------------------------


class TestEventCodec:
    def test_build_parse_roundtrip(self, pubkey_a):
        from skcomms.nostr_discovery import (
            DIRECTORY_KIND,
            build_directory_event,
            parse_directory_event,
        )

        rec = _record("lumina@chef.skworld", "noroc2027", pubkey_a)
        ev = build_directory_event(rec)
        assert ev["kind"] == DIRECTORY_KIND
        assert _dtag(ev) == "lumina@chef.skworld"
        parsed = parse_directory_event(ev)
        assert parsed["fqid"] == "lumina@chef.skworld"
        assert parsed["inbox_url"] == "https://noroc2027/api/v1/inbox"

    def test_build_requires_fqid(self):
        from skcomms.nostr_discovery import build_directory_event

        with pytest.raises(ValueError):
            build_directory_event({"node": "x"})

    def test_parse_wrong_kind_returns_none(self):
        from skcomms.nostr_discovery import parse_directory_event

        assert parse_directory_event({"kind": 1, "content": "{}"}) is None

    def test_parse_malformed_content_returns_none(self):
        from skcomms.nostr_discovery import DIRECTORY_KIND, parse_directory_event

        assert parse_directory_event({"kind": DIRECTORY_KIND, "content": "not json"}) is None


# ---------------------------------------------------------------------------
# publish + resolve
# ---------------------------------------------------------------------------


class TestPublishResolve:
    def test_publish_then_resolve_upserts_peer(self, home, pubkey_a):
        relay = FakeRelay()
        client = _client(relay)

        assert client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))
        assert len(relay.events) == 1

        peer = client.resolve_peer("lumina@chef.skworld")
        assert peer is not None
        assert peer.fqid == "lumina@chef.skworld"
        assert peer.name == "lumina"
        assert peer.inbox_url() == "https://noroc2027/api/v1/inbox"
        assert peer.pubkey == pubkey_a
        assert peer.rails == ["https-s2s", "syncthing", "nostr"]
        assert peer.discovered_via == "nostr-directory"

        # persisted to the store under the bare agent name
        from skcomms.discovery import PeerStore

        stored = _store().get("lumina")
        assert stored is not None
        assert stored.inbox_url() == "https://noroc2027/api/v1/inbox"

    def test_resolve_pins_fingerprint_via_tofu(self, home, pubkey_a):
        from skcomms.tofu import fingerprint_for

        relay = FakeRelay()
        client = _client(relay)
        client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))
        client.resolve_peer("lumina@chef.skworld")

        # TOFU pinned the fingerprint for this fqid
        assert fingerprint_for("lumina@chef.skworld") is not None

    def test_resolve_unknown_returns_none(self, home):
        relay = FakeRelay()
        client = _client(relay)
        assert client.resolve_peer("ghost@nowhere.void") is None


# ---------------------------------------------------------------------------
# discover_all (auto-seed) + idempotency
# ---------------------------------------------------------------------------


class TestDiscoverAll:
    def test_discover_all_seeds_multiple(self, home, pubkey_a, pubkey_b):
        relay = FakeRelay()
        client = _client(relay)
        client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))
        client.publish_directory(_record("jarvis@chef.skworld", "skstack41", pubkey_b))

        seeded = client.discover_all()
        assert {p.fqid for p in seeded} == {"lumina@chef.skworld", "jarvis@chef.skworld"}

        from skcomms.discovery import PeerStore

        store = _store()
        assert store.get("lumina") is not None
        assert store.get("jarvis") is not None

    def test_discover_all_idempotent(self, home, pubkey_a, pubkey_b):
        relay = FakeRelay()
        client = _client(relay)
        client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))
        client.publish_directory(_record("jarvis@chef.skworld", "skstack41", pubkey_b))

        first = client.discover_all()
        second = client.discover_all()
        assert len(first) == len(second) == 2

        from skcomms.discovery import PeerStore

        # still exactly two peer files, no dupes
        peers = _store().list_all()
        assert len([p for p in peers if p.discovered_via == "nostr-directory"]) == 2

    def test_sync_directory_alias(self, home, pubkey_a):
        relay = FakeRelay()
        client = _client(relay)
        client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))
        assert client.sync_directory == client.discover_all
        assert len(client.sync_directory()) == 1


# ---------------------------------------------------------------------------
# TOFU conflict handling
# ---------------------------------------------------------------------------


class TestTofuConflict:
    def test_changed_key_for_known_fqid_rejected(self, home, pubkey_a, pubkey_a_changed):
        relay = FakeRelay()
        client = _client(relay)

        # first contact pins pubkey_a
        client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))
        first = client.resolve_peer("lumina@chef.skworld")
        assert first is not None and first.pubkey == pubkey_a

        from skcomms.tofu import fingerprint_for

        pinned = fingerprint_for("lumina@chef.skworld")

        # attacker republishes the SAME fqid with a DIFFERENT key
        client.publish_directory(
            _record("lumina@chef.skworld", "evil-node", pubkey_a_changed, ts=1_750_999_999)
        )
        rejected = client.resolve_peer("lumina@chef.skworld")
        assert rejected is None  # conflict → not upserted

        # pin unchanged; stored peer still points at the original honest node
        assert fingerprint_for("lumina@chef.skworld") == pinned
        from skcomms.discovery import PeerStore

        stored = _store().get("lumina")
        assert stored.inbox_url() == "https://noroc2027/api/v1/inbox"

    def test_discover_all_skips_conflict_keeps_others(
        self, home, pubkey_a, pubkey_a_changed, pubkey_b
    ):
        relay = FakeRelay()
        client = _client(relay)
        client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))
        client.discover_all()  # pin lumina = pubkey_a

        # now lumina conflicts, jarvis is fresh — jarvis must still seed
        relay.events.clear()
        client.publish_directory(_record("lumina@chef.skworld", "evil", pubkey_a_changed))
        client.publish_directory(_record("jarvis@chef.skworld", "skstack41", pubkey_b))
        seeded = client.discover_all()
        assert {p.fqid for p in seeded} == {"jarvis@chef.skworld"}


# ---------------------------------------------------------------------------
# replaceable semantics — newest wins
# ---------------------------------------------------------------------------


class TestReplaceable:
    def test_newest_record_wins(self, home, pubkey_a):
        from skcomms.nostr_discovery import build_directory_event

        relay = FakeRelay()
        client = _client(relay)

        # publish via the seam directly to control created_at ordering
        old = build_directory_event(
            {**_record("lumina@chef.skworld", "old-node", pubkey_a, ts=1000)}
        )
        old["created_at"] = 1000
        new = build_directory_event(
            {**_record("lumina@chef.skworld", "new-node", pubkey_a, ts=2000)}
        )
        new["created_at"] = 2000
        relay.publish(old)
        relay.publish(new)  # replaceable drop keeps only newest by d-tag anyway

        peer = client.resolve_peer("lumina@chef.skworld")
        assert peer.inbox_url() == "https://new-node/api/v1/inbox"


# ---------------------------------------------------------------------------
# ensure_peer send-path hook
# ---------------------------------------------------------------------------


class TestEnsurePeer:
    def test_known_peer_returned_without_discovery(self, home, pubkey_a):
        from skcomms.discovery import PeerInfo, PeerStore, PeerTransport
        from skcomms.nostr_discovery import ensure_peer

        store = _store()
        store.add(
            PeerInfo(
                name="lumina",
                fqid="lumina@chef.skworld",
                transports=[
                    PeerTransport(transport="https-s2s", settings={"inbox_url": "https://x/i"})
                ],
            )
        )
        # a relay that would error if queried — proves no discovery happened
        peer = ensure_peer("lumina@chef.skworld", store=store, directory=_boom_client())
        assert peer is not None
        assert peer.inbox_url() == "https://x/i"

    def test_unknown_fqid_triggers_discovery(self, home, pubkey_a):
        from skcomms.discovery import PeerStore
        from skcomms.nostr_discovery import ensure_peer

        relay = FakeRelay()
        client = _client(relay)
        client.publish_directory(_record("lumina@chef.skworld", "noroc2027", pubkey_a))

        peer = ensure_peer("lumina@chef.skworld", store=_store(), directory=client)
        assert peer is not None
        assert peer.inbox_url() == "https://noroc2027/api/v1/inbox"

    def test_bare_name_unknown_returns_none(self, home):
        from skcomms.discovery import PeerStore
        from skcomms.nostr_discovery import ensure_peer

        # no "@" → not resolvable off the relay
        assert ensure_peer("lumina", store=_store()) is None


class _Boom:
    def resolve_peer(self, fqid):
        raise AssertionError("discovery should not have been attempted")


def _boom_client():
    return _Boom()
