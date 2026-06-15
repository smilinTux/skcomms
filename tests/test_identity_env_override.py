"""Tests for the SKAGENT identity override in load_config.

The skcomms config home is a single shared path, so every agent loads the same
config.yml. Without this override, a non-lumina agent (e.g. opus) inherits the
shared 'lumina' identity and transmits as 'lumina' — colliding on the wire and
seeding agent<->agent reply loops. load_config must honor SKAGENT so each agent
transmits as itself.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from skcomms.config import load_config


def _write(tmp_path: Path, name: str) -> Path:
    p = tmp_path / "config.yml"
    p.write_text(
        textwrap.dedent(
            f"""
            skcomms:
              identity:
                name: "{name}"
            """
        ),
        encoding="utf-8",
    )
    return p


def test_skagent_overrides_shared_identity(tmp_path, monkeypatch):
    cfg = _write(tmp_path, "lumina")
    monkeypatch.setenv("SKAGENT", "opus")
    monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
    config = load_config(str(cfg))
    assert config.identity.name == "opus"


def test_no_env_keeps_config_identity(tmp_path, monkeypatch):
    cfg = _write(tmp_path, "lumina")
    monkeypatch.delenv("SKAGENT", raising=False)
    monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
    config = load_config(str(cfg))
    assert config.identity.name == "lumina"


def test_skcapstone_agent_is_fallback(tmp_path, monkeypatch):
    cfg = _write(tmp_path, "lumina")
    monkeypatch.delenv("SKAGENT", raising=False)
    monkeypatch.setenv("SKCAPSTONE_AGENT", "jarvis")
    config = load_config(str(cfg))
    assert config.identity.name == "jarvis"


def test_skagent_takes_precedence_over_fallback(tmp_path, monkeypatch):
    cfg = _write(tmp_path, "lumina")
    monkeypatch.setenv("SKAGENT", "opus")
    monkeypatch.setenv("SKCAPSTONE_AGENT", "jarvis")
    config = load_config(str(cfg))
    assert config.identity.name == "opus"


def test_matching_agent_is_noop(tmp_path, monkeypatch):
    cfg = _write(tmp_path, "lumina")
    monkeypatch.setenv("SKAGENT", "lumina")
    config = load_config(str(cfg))
    assert config.identity.name == "lumina"


def test_blank_env_does_not_override(tmp_path, monkeypatch):
    cfg = _write(tmp_path, "lumina")
    monkeypatch.setenv("SKAGENT", "   ")
    monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
    config = load_config(str(cfg))
    assert config.identity.name == "lumina"
