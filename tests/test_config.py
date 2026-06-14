"""Tests for skcomms.config — YAML loading + the legacy ``skcomm:`` key.

config.py had no test home before this. The headline case is the real-world
bug: a top-level config wrapped in ``skcomm:`` (the OLD package name) must still
load transports, and the home root must default to ``~/.skcapstone/skcomms``.
Both ``skcomm:`` and ``skcomms:`` sections must parse identically.

All standalone: tmp YAML files + env, no live transports/network.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from skcomms.config import (
    SKCOMMS_HOME,
    SKCommsConfig,
    TransportConfig,
    load_config,
)
from skcomms.models import RoutingMode


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.yml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# The legacy skcomm: vs skcomms: key (the locked-in regression)
# ---------------------------------------------------------------------------


class TestLegacyKey:
    def test_skcomm_wrapped_config_loads_transports(self, tmp_path):
        """A config nested under the OLD ``skcomm:`` key must still parse — and
        load its transports. This was a real bug (skcomm→skcomms rename)."""
        cfg_path = _write(
            tmp_path,
            """
            skcomm:
              version: "2.0.0"
              transports:
                syncthing:
                  enabled: true
                  priority: 10
                tailscale:
                  enabled: false
            """,
        )
        cfg = SKCommsConfig.from_yaml(cfg_path)
        assert cfg.version == "2.0.0"
        assert set(cfg.transports) == {"syncthing", "tailscale"}
        assert cfg.transports["syncthing"].enabled is True
        assert cfg.transports["syncthing"].priority == 10
        assert cfg.transports["tailscale"].enabled is False

    def test_skcomms_wrapped_config_loads_transports(self, tmp_path):
        cfg_path = _write(
            tmp_path,
            """
            skcomms:
              version: "2.0.0"
              transports:
                syncthing: {enabled: true, priority: 10}
            """,
        )
        cfg = SKCommsConfig.from_yaml(cfg_path)
        assert cfg.version == "2.0.0"
        assert cfg.transports["syncthing"].enabled is True

    def test_skcomm_and_skcomms_parse_identically(self, tmp_path):
        body = """
              version: "3.1.4"
              transports:
                file: {enabled: true, priority: 5}
              defaults:
                mode: broadcast
                encrypt: false
        """
        old = SKCommsConfig.from_yaml(_write(tmp_path, "skcomm:" + body))
        (tmp_path / "config.yml").unlink()
        new = SKCommsConfig.from_yaml(_write(tmp_path, "skcomms:" + body))
        assert old.version == new.version == "3.1.4"
        assert old.default_mode == new.default_mode == RoutingMode.BROADCAST
        assert old.encrypt is new.encrypt is False
        assert (old.transports["file"].priority
                == new.transports["file"].priority == 5)

    def test_skcomms_wins_when_both_keys_present(self, tmp_path):
        """If both keys exist, ``skcomms:`` takes precedence (``or`` short-circuit)."""
        cfg_path = _write(
            tmp_path,
            """
            skcomms:
              version: "new"
            skcomm:
              version: "old"
            """,
        )
        assert SKCommsConfig.from_yaml(cfg_path).version == "new"


# ---------------------------------------------------------------------------
# SKCOMMS_HOME default
# ---------------------------------------------------------------------------


class TestHomeDefault:
    def test_skcomms_home_constant_default(self):
        # The config module's canonical home root is ~/.skcapstone/skcomms.
        assert SKCOMMS_HOME == "~/.skcapstone/skcomms"

    def test_load_config_default_path_is_skcomms_home(self, monkeypatch, tmp_path):
        """load_config() with no override resolves under ~/.skcapstone/skcomms."""
        captured = {}
        real_from_yaml = SKCommsConfig.from_yaml

        @classmethod
        def _spy(cls, path):
            captured["path"] = path
            return real_from_yaml(path)

        monkeypatch.setattr(SKCommsConfig, "from_yaml", _spy)
        load_config()
        assert captured["path"] == Path(SKCOMMS_HOME) / "config.yml"

    def test_skcomms_home_resolution_via_home_module_default(self, monkeypatch):
        """The home module resolves the SAME default root used by config."""
        monkeypatch.delenv("SKCOMMS_HOME", raising=False)
        from skcomms.home import skcomms_home

        assert skcomms_home() == Path(SKCOMMS_HOME).expanduser()
        assert skcomms_home() == Path.home() / ".skcapstone" / "skcomms"


# ---------------------------------------------------------------------------
# Defaults / robustness
# ---------------------------------------------------------------------------


class TestDefaultsAndRobustness:
    def test_missing_file_returns_defaults(self, tmp_path):
        cfg = SKCommsConfig.from_yaml(tmp_path / "nope.yml")
        assert cfg.version == "1.0.0"
        assert cfg.encrypt is True and cfg.sign is True
        assert cfg.default_mode == RoutingMode.FAILOVER
        assert cfg.transports == {}

    def test_unwrapped_config_loads_at_top_level(self, tmp_path):
        """No ``skcomm(s):`` wrapper at all → the raw mapping is the section."""
        cfg_path = _write(
            tmp_path,
            """
            version: "9.9.9"
            transports:
              file: {enabled: true}
            """,
        )
        cfg = SKCommsConfig.from_yaml(cfg_path)
        assert cfg.version == "9.9.9"
        assert cfg.transports["file"].enabled is True

    def test_transport_as_bare_bool(self, tmp_path):
        """A transport given as a bare bool becomes TransportConfig(enabled=bool)."""
        cfg_path = _write(
            tmp_path,
            """
            skcomms:
              transports:
                file: true
                nostr: false
            """,
        )
        cfg = SKCommsConfig.from_yaml(cfg_path)
        assert isinstance(cfg.transports["file"], TransportConfig)
        assert cfg.transports["file"].enabled is True
        assert cfg.transports["nostr"].enabled is False

    def test_defaults_block_overrides(self, tmp_path):
        cfg_path = _write(
            tmp_path,
            """
            skcomms:
              defaults:
                mode: broadcast
                encrypt: false
                sign: false
                ack: false
                retry_max: 2
                ttl: 60
            """,
        )
        cfg = SKCommsConfig.from_yaml(cfg_path)
        assert cfg.default_mode == RoutingMode.BROADCAST
        assert cfg.encrypt is False
        assert cfg.sign is False
        assert cfg.ack is False
        assert cfg.retry_max == 2
        assert cfg.ttl == 60

    def test_identity_and_daemon_sections(self, tmp_path):
        cfg_path = _write(
            tmp_path,
            """
            skcomms:
              identity:
                name: lumina
                fingerprint: DEADBEEF
              daemon:
                enabled: false
                poll_interval_s: 30
            """,
        )
        cfg = SKCommsConfig.from_yaml(cfg_path)
        assert cfg.identity.name == "lumina"
        assert cfg.identity.fingerprint == "DEADBEEF"
        assert cfg.daemon.enabled is False
        assert cfg.daemon.poll_interval_s == 30

    def test_malformed_yaml_falls_back_to_defaults(self, tmp_path):
        cfg_path = tmp_path / "config.yml"
        cfg_path.write_text("skcomms:\n  transports: [unbalanced\n", encoding="utf-8")
        cfg = SKCommsConfig.from_yaml(cfg_path)
        # parse error is swallowed → defaults, never a crash
        assert cfg.version == "1.0.0"
        assert cfg.transports == {}

    def test_empty_file_is_defaults(self, tmp_path):
        cfg_path = tmp_path / "config.yml"
        cfg_path.write_text("", encoding="utf-8")
        cfg = SKCommsConfig.from_yaml(cfg_path)
        assert cfg.version == "1.0.0"
