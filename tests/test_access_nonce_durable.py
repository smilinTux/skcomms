"""sk-access durable nonce replay cache (coord f465b407).

AccessServer used to build its own in-memory ``fed.NonceCache()``, so a
daemon restart forgot every seen nonce and a captured capauth-signed call
could be replayed against the sk-access surface. These tests prove the fix,
mirroring tests/test_nonce_durable.py for the federation inbox:

* AccessServer is durable BY DEFAULT: its replay guard is a
  :class:`skcomms.federation.DurableNonceCache` at the NODE-LOCAL
  ``access_nonce_cache.db`` (``SKCOMMS_NONCE_CACHE_DIR`` >
  ``$XDG_STATE_HOME/skcomms`` > ``~/.local/state/skcomms``; never inside the
  Syncthing-shared skcomms home). Its own file, separate from the inbox
  cache, so the two surfaces do not share replay history.
* ``SKCOMMS_NONCE_CACHE=memory`` is the explicit opt-out;
  ``SKCOMMS_ACCESS_NONCE_DB`` overrides the path; an injected cache wins.
* Fail closed: if the durable store cannot be opened, AccessServer
  construction raises instead of silently downgrading to in-memory.
* End to end: a signed call accepted before a simulated restart is rejected
  by the reborn server (same node, new process).
"""

from __future__ import annotations

import json

import pytest

from skcomms.envelope import Envelope
from skcomms.federation import DurableNonceCache, NonceCache
from skcomms.signing import EnvelopeSigner
from skcomms.access import (
    AccessAuthError,
    AccessConfig,
    AccessRegistry,
    AccessServer,
    Scope,
)


# --- helpers (same pattern as test_access_server.py) ------------------------


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
def caller_keys():
    return _gen_key("caller <lumina@chef.skworld>")


def _config() -> AccessConfig:
    return AccessConfig(
        host="127.0.0.1",
        port=9386,
        scope_grants={"lumina@chef.skworld": {Scope.READ}},
        node_name="testnode",
        node_fqid="testnode@chef.skworld",
    )


def _server(**kw) -> AccessServer:
    return AccessServer(config=_config(), registry=AccessRegistry(), **kw)


def _signed_token(keys, *, tool="health"):
    priv, _ = keys
    env = Envelope(
        from_fqid="lumina@chef.skworld",
        to_fqid="testnode@chef.skworld",
        content_type="application/x-skaccess-call",
        body=json.dumps({"tool": tool, "arguments": {}}),
    )
    return EnvelopeSigner(priv, "").sign(env)


@pytest.fixture()
def home(monkeypatch, tmp_path):
    """Isolated skcomms home + node-local cache dir; no env overrides leak in."""
    h = tmp_path / "skcomms-home"
    monkeypatch.setenv("SKCOMMS_HOME", str(h))
    monkeypatch.setenv("SKCOMMS_NONCE_CACHE_DIR", str(tmp_path / "local-state"))
    monkeypatch.delenv("SKCOMMS_NONCE_CACHE", raising=False)
    monkeypatch.delenv("SKCOMMS_ACCESS_NONCE_DB", raising=False)
    return h


@pytest.fixture()
def local_state(home, tmp_path):
    """The node-local nonce-cache dir paired with the ``home`` fixture."""
    return tmp_path / "local-state"


# --- default wiring ----------------------------------------------------------


class TestDefaultWiring:
    def test_default_is_durable_and_node_local(self, home, local_state):
        srv = _server()
        assert isinstance(srv.nonce_cache, DurableNonceCache)
        assert srv.nonce_cache.path == local_state / "access_nonce_cache.db"
        assert srv.nonce_cache.path.exists()
        # NEVER inside the Syncthing-shared skcomms home tree.
        assert home.resolve() not in srv.nonce_cache.path.resolve().parents
        assert not (home / "state" / "access_nonce_cache.db").exists()

    def test_own_db_file_separate_from_inbox_cache(self, home):
        srv = _server()
        assert srv.nonce_cache.path.name != "nonce_cache.db"

    def test_state_dir_is_syncthing_ignored(self, home):
        """Legacy healing: the synced home's .stignore still gains state/ so
        any LEFTOVER legacy DB stops syncing until ops remove it."""
        _server()
        stignore = home / ".stignore"
        assert stignore.exists()
        assert "state/" in stignore.read_text()

    def test_memory_opt_out_is_explicit(self, home, local_state, monkeypatch):
        monkeypatch.setenv("SKCOMMS_NONCE_CACHE", "memory")
        srv = _server()
        assert isinstance(srv.nonce_cache, NonceCache)
        assert not (local_state / "access_nonce_cache.db").exists()
        assert not (home / "state" / "access_nonce_cache.db").exists()

    def test_env_path_override(self, home, monkeypatch):
        override = home.parent / "elsewhere" / "replay.db"
        monkeypatch.setenv("SKCOMMS_ACCESS_NONCE_DB", str(override))
        srv = _server()
        assert isinstance(srv.nonce_cache, DurableNonceCache)
        assert srv.nonce_cache.path == override

    def test_dir_env_override_honored(self, home, monkeypatch, tmp_path):
        pinned = tmp_path / "ops-pinned"
        monkeypatch.setenv("SKCOMMS_NONCE_CACHE_DIR", str(pinned))
        srv = _server()
        assert srv.nonce_cache.path == pinned / "access_nonce_cache.db"

    def test_injected_cache_wins(self, home, local_state):
        mem = NonceCache()
        srv = _server(nonce_cache=mem)
        assert srv.nonce_cache is mem
        assert not (local_state / "access_nonce_cache.db").exists()
        assert not (home / "state" / "access_nonce_cache.db").exists()

    def test_legacy_synced_db_migrated_once(self, home, local_state):
        """Replay history from the old synced location carries over."""
        legacy = DurableNonceCache(home / "state" / "access_nonce_cache.db")
        assert legacy.check_and_add("lumina@chef.skworld", "n-legacy") is True
        legacy.close()

        srv = _server()
        assert srv.nonce_cache.path == local_state / "access_nonce_cache.db"
        assert srv.nonce_cache.check_and_add("lumina@chef.skworld", "n-legacy") is False

    def test_unopenable_store_fails_closed(self, home, monkeypatch):
        """No silent downgrade to in-memory when the durable store is broken."""
        blocker = home.parent / "not-a-dir"
        blocker.parent.mkdir(parents=True, exist_ok=True)
        blocker.write_text("file where a directory must go")
        monkeypatch.setenv("SKCOMMS_ACCESS_NONCE_DB", str(blocker / "nonce.db"))
        with pytest.raises(Exception):
            _server()


# --- the actual fix: replay across restart ------------------------------------


class TestReplayAcrossRestart:
    def test_replay_rejected_by_reborn_server(self, home, caller_keys):
        _, pub = caller_keys
        token = _signed_token(caller_keys)

        first = _server()
        first.trust_key("lumina@chef.skworld", pub)
        ctx = first.authenticate(token)
        assert ctx.identity == "lumina@chef.skworld"
        first.nonce_cache.close()

        # Simulated daemon restart: fresh server, same node (same home).
        reborn = _server()
        reborn.trust_key("lumina@chef.skworld", pub)
        with pytest.raises(AccessAuthError):
            reborn.authenticate(token)
        # A genuinely fresh call still passes.
        assert reborn.authenticate(_signed_token(caller_keys)).identity == (
            "lumina@chef.skworld"
        )

    def test_memory_mode_still_replays_after_restart(self, home, caller_keys, monkeypatch):
        """Documents WHY memory mode is opt-in only: restart forgets nonces."""
        monkeypatch.setenv("SKCOMMS_NONCE_CACHE", "memory")
        _, pub = caller_keys
        token = _signed_token(caller_keys)

        first = _server()
        first.trust_key("lumina@chef.skworld", pub)
        first.authenticate(token)

        reborn = _server()
        reborn.trust_key("lumina@chef.skworld", pub)
        # In-memory cache forgot the nonce: replay sails through.
        assert reborn.authenticate(token).identity == "lumina@chef.skworld"
