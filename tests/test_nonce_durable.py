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
* The store is NODE-LOCAL: it resolves outside the Syncthing-shared skcomms
  home (``SKCOMMS_NONCE_CACHE_DIR`` > ``$XDG_STATE_HOME/skcomms`` >
  ``~/.local/state/skcomms``), and a healthy legacy synced DB is migrated
  once while a corrupt one falls back to a fresh cache instead of bricking.
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
        """Isolated wiring: a fake SYNCED home and a separate LOCAL cache dir."""
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "synced-home"))
        monkeypatch.setenv("SKCOMMS_NONCE_CACHE_DIR", str(tmp_path / "local-state"))
        monkeypatch.delenv("SKCOMMS_NONCE_DB", raising=False)
        monkeypatch.delenv("SKCOMMS_NONCE_CACHE", raising=False)
        import skcomms.api as api

        api._fed_nonce_cache = None
        api._fed_rate_limiter = None
        return api

    def test_default_is_durable_and_node_local(self, monkeypatch, tmp_path):
        """The replay cache resolves OUTSIDE the synced skcomms home."""
        api = self._fresh_api(monkeypatch, tmp_path)
        cache = api._get_nonce_cache()
        assert isinstance(cache, DurableNonceCache)
        assert cache.path == tmp_path / "local-state" / "nonce_cache.db"
        assert cache.path.exists()
        # NEVER inside the Syncthing-shared home tree.
        home = (tmp_path / "synced-home").resolve()
        assert home not in cache.path.resolve().parents
        assert not (tmp_path / "synced-home" / "state" / "nonce_cache.db").exists()

    def test_dir_env_override_honored(self, monkeypatch, tmp_path):
        api = self._fresh_api(monkeypatch, tmp_path)
        pinned = tmp_path / "ops-pinned"
        monkeypatch.setenv("SKCOMMS_NONCE_CACHE_DIR", str(pinned))
        cache = api._get_nonce_cache()
        assert cache.path == pinned / "nonce_cache.db"

    def test_xdg_state_home_default(self, monkeypatch, tmp_path):
        """Without the dir override, $XDG_STATE_HOME/skcomms/ is the default."""
        api = self._fresh_api(monkeypatch, tmp_path)
        monkeypatch.delenv("SKCOMMS_NONCE_CACHE_DIR", raising=False)
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
        cache = api._get_nonce_cache()
        assert cache.path == tmp_path / "xdg-state" / "skcomms" / "nonce_cache.db"

    def test_local_state_default_without_xdg(self, monkeypatch, tmp_path):
        """Bare default is ~/.local/state/skcomms/ (node-local, never synced)."""
        api = self._fresh_api(monkeypatch, tmp_path)
        monkeypatch.delenv("SKCOMMS_NONCE_CACHE_DIR", raising=False)
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path / "fake-home"))
        cache = api._get_nonce_cache()
        expected = tmp_path / "fake-home" / ".local" / "state" / "skcomms" / "nonce_cache.db"
        assert cache.path == expected

    def test_file_env_override_beats_dir_override(self, monkeypatch, tmp_path):
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
        assert not (tmp_path / "local-state" / "nonce_cache.db").exists()
        assert not (tmp_path / "synced-home" / "state" / "nonce_cache.db").exists()

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
        """Legacy healing: state/ stays in the scaffold's .stignore so any
        leftover legacy DB stops syncing on fleets whose Syncthing folder is
        rooted at the skcomms home itself."""
        from skcomms.home import STIGNORE_CONTENT

        assert "state/" in STIGNORE_CONTENT.splitlines()

    def test_default_path_heals_preexisting_stignore(self, monkeypatch, tmp_path):
        """Existing deploys (.158/.41): resolving the default nonce-db path
        still appends the state/ ignore, so the LEFTOVER legacy DB stops
        syncing between nodes until ops remove it."""
        api = self._fresh_api(monkeypatch, tmp_path)
        home = tmp_path / "synced-home"
        home.mkdir(parents=True)
        (home / ".stignore").write_text("*.tmp\n*.lock\n")
        cache = api._get_nonce_cache()
        assert isinstance(cache, DurableNonceCache)
        lines = [ln.strip() for ln in (home / ".stignore").read_text().splitlines()]
        assert "state/" in lines
        assert "*.tmp" in lines  # existing content preserved

    def test_env_override_path_leaves_stignore_alone(self, monkeypatch, tmp_path):
        """SKCOMMS_NONCE_DB outside the synced tree needs no .stignore edit."""
        api = self._fresh_api(monkeypatch, tmp_path)
        monkeypatch.setenv("SKCOMMS_NONCE_DB", str(tmp_path / "outside" / "replay.db"))
        api._get_nonce_cache()
        assert not (tmp_path / "synced-home" / ".stignore").exists()


# --- legacy migration: old synced DB -> node-local path ------------------------


class TestLegacyMigration:
    def _fresh_api(self, monkeypatch, tmp_path):
        return TestApiWiring()._fresh_api(monkeypatch, tmp_path)

    def test_healthy_legacy_db_migrated_once(self, monkeypatch, tmp_path):
        """Replay history carries over: a nonce seen by the OLD synced store
        is still rejected by the new node-local store."""
        api = self._fresh_api(monkeypatch, tmp_path)
        legacy = DurableNonceCache(tmp_path / "synced-home" / "state" / "nonce_cache.db")
        assert legacy.check_and_add("jarvis@chef.skworld", "n-legacy") is True
        legacy.close()

        cache = api._get_nonce_cache()
        assert cache.path == tmp_path / "local-state" / "nonce_cache.db"
        assert cache.check_and_add("jarvis@chef.skworld", "n-legacy") is False
        # Legacy file is left in place (ops cleanup), just never written again.
        assert (tmp_path / "synced-home" / "state" / "nonce_cache.db").exists()

    def test_corrupt_legacy_db_starts_fresh_not_bricked(self, monkeypatch, tmp_path):
        """A sync-conflict-mangled legacy file must not brick daemon start:
        migration is skipped and a FRESH local cache opens (replay exposure
        bounded by the envelope freshness window)."""
        api = self._fresh_api(monkeypatch, tmp_path)
        state = tmp_path / "synced-home" / "state"
        state.mkdir(parents=True)
        (state / "nonce_cache.db").write_text("this is not a sqlite database")

        cache = api._get_nonce_cache()  # must not raise
        assert isinstance(cache, DurableNonceCache)
        assert cache.path == tmp_path / "local-state" / "nonce_cache.db"
        assert cache.check_and_add("jarvis@chef.skworld", "n-fresh") is True

    def test_existing_local_db_wins_no_remigration(self, monkeypatch, tmp_path):
        """Once a local store exists, the legacy file is never consulted again
        (no history clobbering on subsequent restarts)."""
        api = self._fresh_api(monkeypatch, tmp_path)
        local = DurableNonceCache(tmp_path / "local-state" / "nonce_cache.db")
        assert local.check_and_add("a", "n-local") is True
        local.close()
        legacy = DurableNonceCache(tmp_path / "synced-home" / "state" / "nonce_cache.db")
        assert legacy.check_and_add("a", "n-legacy") is True
        legacy.close()

        cache = api._get_nonce_cache()
        assert cache.check_and_add("a", "n-local") is False  # local history kept
        assert cache.check_and_add("a", "n-legacy") is True  # legacy NOT merged


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
