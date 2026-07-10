"""Tests for the ~/.skcapstone/skcomms/ scaffold (T4, ``479ce678``).

Covers:
    - skcomms_home() honors SKCOMMS_HOME override, defaults to ~/.skcapstone/skcomms.
    - scaffold() creates <realm>/<operator>/<agent>/{outbox,inbox} derived
      from cluster.json + resolve_identity.
    - .stignore written at the top level.
    - idempotent (safe to re-run).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Home resolution
# ---------------------------------------------------------------------------


class TestSkcommsHome:
    def test_default_home(self, monkeypatch):
        monkeypatch.delenv("SKCOMMS_HOME", raising=False)
        from skcomms.home import skcomms_home

        assert skcomms_home() == Path.home() / ".skcapstone" / "skcomms"

    def test_env_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "custom"))
        from skcomms.home import skcomms_home

        assert skcomms_home() == tmp_path / "custom"


# ---------------------------------------------------------------------------
# Scaffold
# ---------------------------------------------------------------------------


@pytest.fixture
def fixture_cluster(tmp_path):
    """A cluster.json fixture + patched cluster lookup."""
    cluster_file = tmp_path / "cluster.json"
    cluster_file.write_text(json.dumps({"realm": "skworld", "operator": "chef"}))
    from skcomms import cluster as cm

    original = cm._CLUSTER_LOOKUP
    cm._CLUSTER_LOOKUP = [cluster_file]
    yield cluster_file
    cm._CLUSTER_LOOKUP = original


@pytest.fixture
def mock_identity():
    """resolve_self_identity returns lumina with an fqid."""
    with patch(
        "skcomms.home.resolve_self_identity",
        return_value={
            "agent": "lumina",
            "capauth_uri": "capauth:lumina@skworld.io",
            "fqid": "lumina@chef.skworld",
            "fingerprint": "DEADBEEF",
        },
    ):
        yield


class TestScaffold:
    def test_creates_tree(self, monkeypatch, tmp_path, fixture_cluster, mock_identity):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.home import scaffold

        result = scaffold(agent="lumina")
        base = tmp_path / "home"
        agent_dir = base / "skworld" / "chef" / "lumina"
        assert (agent_dir / "outbox").is_dir()
        assert (agent_dir / "inbox").is_dir()
        assert result["agent_dir"] == agent_dir
        assert result["outbox"] == agent_dir / "outbox"
        assert result["inbox"] == agent_dir / "inbox"

    def test_writes_stignore(self, monkeypatch, tmp_path, fixture_cluster, mock_identity):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.home import scaffold

        scaffold(agent="lumina")
        stignore = tmp_path / "home" / ".stignore"
        assert stignore.exists()
        text = stignore.read_text()
        assert "*.tmp" in text
        assert "*.lock" in text
        assert "daemon.pid" in text

    def test_appends_state_ignore_to_preexisting_stignore(
        self, monkeypatch, tmp_path, fixture_cluster, mock_identity
    ):
        """A live deploy whose .stignore predates the durable nonce cache gets
        the state/ line appended (never left syncing a live WAL SQLite), and
        operator-added lines are preserved."""
        home = tmp_path / "home"
        home.mkdir(parents=True)
        legacy = "*.tmp\n*.lock\n// operator note\nmy-local-dir/\n"
        (home / ".stignore").write_text(legacy)
        monkeypatch.setenv("SKCOMMS_HOME", str(home))
        from skcomms.home import scaffold

        scaffold(agent="lumina")
        text = (home / ".stignore").read_text()
        lines = [ln.strip() for ln in text.splitlines()]
        assert "state/" in lines
        assert "my-local-dir/" in lines  # operator content preserved
        assert "// operator note" in lines

    def test_state_ignore_append_is_idempotent(
        self, monkeypatch, tmp_path, fixture_cluster, mock_identity
    ):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.home import scaffold

        scaffold(agent="lumina")
        first = (tmp_path / "home" / ".stignore").read_text()
        scaffold(agent="lumina")
        second = (tmp_path / "home" / ".stignore").read_text()
        assert first == second
        assert first.count("state/") == 1

    def test_preexisting_stignore_with_state_untouched(
        self, monkeypatch, tmp_path, fixture_cluster, mock_identity
    ):
        home = tmp_path / "home"
        home.mkdir(parents=True)
        original = "state/\n// mine\n"
        (home / ".stignore").write_text(original)
        monkeypatch.setenv("SKCOMMS_HOME", str(home))
        from skcomms.home import scaffold

        scaffold(agent="lumina")
        assert (home / ".stignore").read_text() == original

    def test_appends_newline_before_block_when_missing(
        self, monkeypatch, tmp_path, fixture_cluster, mock_identity
    ):
        """An existing .stignore without a trailing newline still gets a clean
        state/ line (no two patterns glued onto one line)."""
        home = tmp_path / "home"
        home.mkdir(parents=True)
        (home / ".stignore").write_text("*.tmp")  # no trailing newline
        monkeypatch.setenv("SKCOMMS_HOME", str(home))
        from skcomms.home import scaffold

        scaffold(agent="lumina")
        lines = [ln.strip() for ln in (home / ".stignore").read_text().splitlines()]
        assert "*.tmp" in lines
        assert "state/" in lines

    def test_idempotent(self, monkeypatch, tmp_path, fixture_cluster, mock_identity):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.home import scaffold

        r1 = scaffold(agent="lumina")
        # drop a file in inbox, re-run, ensure not clobbered
        (r1["inbox"] / "keep.json").write_text("{}")
        r2 = scaffold(agent="lumina")
        assert r2["agent_dir"] == r1["agent_dir"]
        assert (r1["inbox"] / "keep.json").exists()

    def test_derives_paths_from_cluster(self, monkeypatch, tmp_path):
        """A different cluster.json yields a different realm/operator tree."""
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(json.dumps({"realm": "douno", "operator": "casey"}))
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        cm._CLUSTER_LOOKUP = [cluster_file]
        try:
            monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
            with patch(
                "skcomms.home.resolve_self_identity",
                return_value={
                    "agent": "opus",
                    "fqid": "opus@casey.douno",
                    "fingerprint": "X",
                },
            ):
                from skcomms.home import scaffold

                result = scaffold(agent="opus")
                assert result["agent_dir"] == tmp_path / "home" / "douno" / "casey" / "opus"
        finally:
            cm._CLUSTER_LOOKUP = original

    def test_agent_name_falls_back_to_agent_field_when_no_fqid(
        self, monkeypatch, tmp_path, fixture_cluster
    ):
        """When the resolved identity has no fqid, _agent_name uses the agent
        field (the realm-tree name still resolves, no crash)."""
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        with patch(
            "skcomms.home.resolve_self_identity",
            return_value={"agent": "jarvis", "fingerprint": "Y"},  # no fqid
        ):
            from skcomms.home import scaffold

            result = scaffold()
            assert result["agent"] == "jarvis"
            assert result["agent_dir"].name == "jarvis"


# ---------------------------------------------------------------------------
# peer_inbox — sender-side inbox path mapping for a recipient FQID
# ---------------------------------------------------------------------------


class TestPeerInbox:
    def test_maps_fqid_to_realm_operator_agent_inbox(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.home import peer_inbox

        # <agent>@<operator>.<realm> -> <home>/<realm>/<operator>/<agent>/inbox
        path = peer_inbox("opus@casey.douno")
        assert path == tmp_path / "home" / "douno" / "casey" / "opus" / "inbox"

    def test_handles_multi_dot_realm(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        from skcomms.home import peer_inbox

        # realm component keeps everything after the first '.' (rsplit on operator)
        path = peer_inbox("lumina@chef.sk.world")
        assert path == tmp_path / "home" / "sk.world" / "chef" / "lumina" / "inbox"

    def test_rejects_fqid_without_at(self):
        import pytest

        from skcomms.home import peer_inbox

        with pytest.raises(ValueError, match="invalid fqid"):
            peer_inbox("not-a-fqid")

    def test_rejects_fqid_without_realm_dot(self):
        import pytest

        from skcomms.home import peer_inbox

        with pytest.raises(ValueError, match="invalid fqid"):
            peer_inbox("opus@casey")  # no '.' in the operator.realm part
