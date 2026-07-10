"""Durable nonce replay cache (coord 11e295a3).

The federation nonce replay cache used to be a module-level in-memory dict, so
every daemon restart opened a replay window on the public Funnel-exposed inbox.
These tests prove the fix:

* :class:`skcomms.federation.DurableNonceCache` keeps the ``check_and_add``
  contract but persists to SQLite, so a new instance on the same path (a
  restarted daemon, or a second process on the same node) rejects replays.
* Entries expire with the TTL so the store stays bounded.
* ``skcomms.api._get_nonce_cache`` is durable BY DEFAULT (the old in-memory
  behavior is opt-in via ``SKCOMMS_NONCE_CACHE=memory``), and it fails closed
  when the store cannot be opened.
* End to end: an envelope accepted by ``POST /api/v1/inbox`` is still rejected
  with 409 after a simulated daemon restart.
"""

from __future__ import annotations

import pytest

from skcomms.federation import DurableNonceCache, NonceCache

# --- contract ---------------------------------------------------------------


class TestDurableContract:
    def test_first_seen_then_replay(self, tmp_path):
        c = DurableNonceCache(tmp_path / "nonce.db")
        assert c.check_and_add("jarvis@chef.skworld", "n1") is True
        assert c.check_and_add("jarvis@chef.skworld", "n1") is False  # replay
        assert c.check_and_add("lumina@chef.skworld", "n1") is True  # per-sender

    def test_ttl_eviction_re_accepts_and_bounds_store(self, tmp_path):
        c = DurableNonceCache(tmp_path / "nonce.db", ttl_s=10)
        assert c.check_and_add("a", "n", now=1000) is True
        assert c.check_and_add("a", "n2", now=1001) is True
        assert len(c) == 2
        # Same nonce after TTL expiry is accepted again (row evicted), and the
        # expired rows are gone: the store is bounded by the window.
        assert c.check_and_add("a", "n", now=2000) is True
        assert len(c) == 1

    def test_creates_parent_dirs(self, tmp_path):
        db = tmp_path / "deep" / "er" / "nonce.db"
        DurableNonceCache(db)
        assert db.exists()


# --- durability: the actual fix ----------------------------------------------


class TestSurvivesRestart:
    def test_replay_rejected_by_new_instance(self, tmp_path):
        """A restarted daemon (new cache instance, same file) rejects replays."""
        db = tmp_path / "nonce.db"
        first = DurableNonceCache(db)
        assert first.check_and_add("jarvis@chef.skworld", "n1") is True
        first.close()

        reborn = DurableNonceCache(db)  # simulated restart
        assert reborn.check_and_add("jarvis@chef.skworld", "n1") is False
        assert reborn.check_and_add("jarvis@chef.skworld", "n2") is True

    def test_second_concurrent_instance_shares_state(self, tmp_path):
        """Two live handles on the same file (second process on the node)."""
        db = tmp_path / "nonce.db"
        a = DurableNonceCache(db)
        b = DurableNonceCache(db)
        assert a.check_and_add("jarvis@chef.skworld", "n1") is True
        assert b.check_and_add("jarvis@chef.skworld", "n1") is False
        assert b.check_and_add("jarvis@chef.skworld", "n2") is True
        assert a.check_and_add("jarvis@chef.skworld", "n2") is False


# --- api wiring ---------------------------------------------------------------


class TestApiWiring:
    def _fresh_api(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        monkeypatch.delenv("SKCOMMS_NONCE_DB", raising=False)
        monkeypatch.delenv("SKCOMMS_NONCE_CACHE", raising=False)
        import skcomms.api as api

        api._fed_nonce_cache = None
        api._fed_rate_limiter = None
        return api

    def test_default_is_durable_under_skcomms_home(self, monkeypatch, tmp_path):
        api = self._fresh_api(monkeypatch, tmp_path)
        cache = api._get_nonce_cache()
        assert isinstance(cache, DurableNonceCache)
        assert cache.path == tmp_path / "state" / "nonce_cache.db"
        assert cache.path.exists()

    def test_env_path_override(self, monkeypatch, tmp_path):
        api = self._fresh_api(monkeypatch, tmp_path)
        override = tmp_path / "elsewhere" / "replay.db"
        monkeypatch.setenv("SKCOMMS_NONCE_DB", str(override))
        cache = api._get_nonce_cache()
        assert isinstance(cache, DurableNonceCache)
        assert cache.path == override

    def test_memory_opt_out_is_explicit(self, monkeypatch, tmp_path):
        api = self._fresh_api(monkeypatch, tmp_path)
        monkeypatch.setenv("SKCOMMS_NONCE_CACHE", "memory")
        cache = api._get_nonce_cache()
        assert isinstance(cache, NonceCache)
        assert not (tmp_path / "state" / "nonce_cache.db").exists()

    def test_unopenable_store_fails_closed(self, monkeypatch, tmp_path):
        """No silent downgrade to in-memory when the durable store is broken."""
        api = self._fresh_api(monkeypatch, tmp_path)
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("file where a directory must go")
        monkeypatch.setenv("SKCOMMS_NONCE_DB", str(blocker / "nonce.db"))
        with pytest.raises(Exception):
            api._get_nonce_cache()
        assert api._fed_nonce_cache is None  # nothing half-built cached

    def test_state_dir_is_syncthing_ignored(self):
        """The per-node state/ tree must never sync between nodes."""
        from skcomms.home import STIGNORE_CONTENT

        assert "state/" in STIGNORE_CONTENT.splitlines()

    def test_default_path_heals_preexisting_stignore(self, monkeypatch, tmp_path):
        """Existing deploys (.158/.41): the skcomms home already has an
        .stignore that predates the durable cache. Resolving the default
        nonce-db path must append the state/ ignore so the live WAL SQLite
        never syncs between nodes, without waiting for a re-scaffold."""
        api = self._fresh_api(monkeypatch, tmp_path)
        (tmp_path / ".stignore").write_text("*.tmp\n*.lock\n")
        cache = api._get_nonce_cache()
        assert isinstance(cache, DurableNonceCache)
        lines = [ln.strip() for ln in (tmp_path / ".stignore").read_text().splitlines()]
        assert "state/" in lines
        assert "*.tmp" in lines  # existing content preserved

    def test_default_path_writes_stignore_when_absent(self, monkeypatch, tmp_path):
        """A bare home dir (no scaffold ever ran) still gets the ignore file
        before the durable store is created inside the synced tree."""
        api = self._fresh_api(monkeypatch, tmp_path)
        assert not (tmp_path / ".stignore").exists()
        api._get_nonce_cache()
        lines = [ln.strip() for ln in (tmp_path / ".stignore").read_text().splitlines()]
        assert "state/" in lines

    def test_env_override_path_leaves_stignore_alone(self, monkeypatch, tmp_path):
        """SKCOMMS_NONCE_DB outside the synced tree needs no .stignore edit."""
        api = self._fresh_api(monkeypatch, tmp_path)
        monkeypatch.setenv("SKCOMMS_NONCE_DB", str(tmp_path / "outside" / "replay.db"))
        api._get_nonce_cache()
        assert not (tmp_path / ".stignore").exists()


# --- end to end: restart does not open a replay window ------------------------


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


JARVIS_FQID = "jarvis@chef.skworld"
LUMINA_FQID = "lumina@chef.skworld"


class TestInboxReplayAcrossRestart:
    def test_replay_after_restart_is_409(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        monkeypatch.delenv("SKCOMMS_NONCE_DB", raising=False)
        monkeypatch.delenv("SKCOMMS_NONCE_CACHE", raising=False)

        import importlib

        import skcomms.api as api

        importlib.reload(api)
        api._fed_nonce_cache = None
        api._fed_rate_limiter = None

        priv, pub = _gen_key("jarvis <jarvis@chef.skworld>")

        # Pin the sender's pubkey TOFU-style so the inbox verifier trusts it.
        from skcomms import tofu
        from skcomms.peers import fingerprint_from_pubkey

        tofu.record_fingerprint(JARVIS_FQID, "0" * 40, pubkey=pub)
        tofu.record_fingerprint(
            JARVIS_FQID, fingerprint_from_pubkey(pub), pubkey=pub
        )

        # Isolate HOME: per-recipient routing writes into the recipient
        # agent's canonical comms inbox under ~/.skcapstone.
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))

        from skcomms.envelope import Envelope
        from skcomms.signing import EnvelopeSigner

        env = Envelope(from_fqid=JARVIS_FQID, to_fqid=LUMINA_FQID, body="once only")
        raw = EnvelopeSigner(priv).sign(env).to_bytes()

        client = TestClient(api.app)
        resp = client.post(
            "/api/v1/inbox",
            content=raw,
            headers={"content-type": "application/octet-stream"},
        )
        assert resp.status_code == 200, resp.text

        # Simulate a daemon restart: the per-process singletons are wiped
        # exactly as a fresh process would start. Same SKCOMMS_HOME, so the
        # durable store is picked back up.
        api._fed_nonce_cache = None
        api._fed_rate_limiter = None
        client2 = TestClient(api.app)

        replay = client2.post(
            "/api/v1/inbox",
            content=raw,
            headers={"content-type": "application/octet-stream"},
        )
        assert replay.status_code == 409, (
            "replay after restart must be rejected, got "
            f"{replay.status_code}: {replay.text}"
        )

        # And a genuinely new envelope still flows.
        env2 = Envelope(from_fqid=JARVIS_FQID, to_fqid=LUMINA_FQID, body="fresh")
        raw2 = EnvelopeSigner(priv).sign(env2).to_bytes()
        resp2 = client2.post(
            "/api/v1/inbox",
            content=raw2,
            headers={"content-type": "application/octet-stream"},
        )
        assert resp2.status_code == 200, resp2.text
