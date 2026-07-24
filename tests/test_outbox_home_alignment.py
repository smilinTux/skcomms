"""Send paths and the daemon must resolve the SAME outbox home (coord f07cf2de).

Regression tests for the orphaned-outbox bug: 402 signed envelopes to lumina
were stranded in a home nothing drained. Root cause class: a send/helper path
resolved "the outbox" through a resolver that did NOT honor ``SKAGENT`` while
the daemon's real queue was per-agent scoped, so the two named different trees.

These lock the invariant that every way of asking "where is the outbox?" agrees
under a given ``SKAGENT`` / ``SKCOMMS_HOME`` / ``SKCOMMS_OUTBOX_DIR``:

* ``config.load_config`` (what ``SKComms.from_config`` and the daemon BOTH call)
  points the file transport at ``paths.agent_comms_outbox(agent)``;
* ``outbox.default_outbox_dir`` == ``paths.retry_outbox_dir`` ==
  ``PersistentOutbox().root`` (the daemon's real retry store);
* the node default is ``skcomms_home()/outbox`` -- never the dead legacy bare
  ``~/.skcomms/outbox`` -- and is used ONLY when nothing else is set.
"""

from __future__ import annotations

import textwrap

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Start every test from a known-empty selector environment."""
    for var in ("SKAGENT", "SKCAPSTONE_AGENT", "SKCOMMS_HOME", "SKCOMMS_OUTBOX_DIR"):
        monkeypatch.delenv(var, raising=False)


def _write_min_config(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        textwrap.dedent(
            """
            skcomm:
              identity: {name: config_default_identity}
              transports:
                file: {enabled: true, priority: 2, settings: {archive: true}}
            """
        ),
        encoding="utf-8",
    )
    return cfg


def test_from_config_and_daemon_resolve_same_outbox_under_skagent(monkeypatch, tmp_path):
    """load_config (the from_config + daemon path) and the daemon's per-agent
    resolver name the SAME file-transport outbox under a given SKAGENT."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKAGENT", "lumina")

    from skcomms import paths
    from skcomms.config import load_config
    from skcomms.outbox import PersistentOutbox, default_outbox_dir

    cfg = _write_min_config(tmp_path)
    config = load_config(str(cfg))
    file_t = config.transports.get("file")

    daemon_outbox = paths.agent_comms_outbox("lumina")
    # The send path (from_config -> load_config) writes exactly where the
    # daemon's per-agent resolver reads.
    assert file_t.settings["outbox_path"] == str(daemon_outbox)
    # SKAGENT also re-homes the identity so agents never transmit as the
    # shared config file's name (a separate collision the same override fixes).
    assert config.identity.name == "lumina"

    # The retry-store helpers agree with each other and with a live outbox.
    assert default_outbox_dir() == paths.retry_outbox_dir()
    assert PersistentOutbox().root == default_outbox_dir()


def test_skcomms_outbox_dir_override_is_top_precedence(monkeypatch, tmp_path):
    """An explicit SKCOMMS_OUTBOX_DIR pins the retry store verbatim, above
    per-agent scoping -- for the helper, the resolver, and a live outbox."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKAGENT", "opus")
    override = tmp_path / "pinned"
    monkeypatch.setenv("SKCOMMS_OUTBOX_DIR", str(override))

    from skcomms import paths
    from skcomms.outbox import PersistentOutbox, default_outbox_dir

    assert paths.retry_outbox_dir() == override
    assert default_outbox_dir() == override
    assert PersistentOutbox().root == override


def test_node_default_when_nothing_set_is_not_bare_skcomms(monkeypatch, tmp_path):
    """With no SKAGENT / SKCOMMS_OUTBOX_DIR, the default is the node home's
    outbox (skcomms_home()/outbox), NEVER the dead legacy bare ~/.skcomms."""
    home = tmp_path / "nodehome"
    monkeypatch.setenv("SKCOMMS_HOME", str(home))

    from skcomms.home import skcomms_home
    from skcomms.outbox import default_outbox_dir

    resolved = default_outbox_dir()
    assert resolved == skcomms_home() / "outbox" == home / "outbox"
    # The pre-scaffold bare default must never reappear.
    assert ".skcomms/outbox" not in str(resolved)
