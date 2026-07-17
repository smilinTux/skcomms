"""CapAuth signing-key resolution: per-agent, consolidated operator, legacy.

The crypto resolver (:func:`skcomms.core.resolve_signing_capauth_dir`) and the
identity gate (:func:`skcomms.trustbackup.private_key_paths`) must agree on the
same ordered candidate set, or a node can pass the identity gate green while
running with dead crypto. These tests pin both to the same three-tier layout.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from skcomms.core import resolve_signing_capauth_dir
from skcomms.trustbackup import private_key_paths


@pytest.fixture
def fake_home(monkeypatch, tmp_path):
    """Point Path.home() at an empty tmp dir for the duration of the test."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert Path.home() == tmp_path
    return tmp_path


def _write_key(home: Path, rel: str) -> None:
    p = home / rel / "identity" / "private.asc"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("-----BEGIN PGP PRIVATE KEY BLOCK-----\n", encoding="utf-8")


def test_per_agent_key_wins(fake_home):
    _write_key(fake_home, ".skcapstone/agents/lumina/capauth")
    _write_key(fake_home, ".skcapstone/capauth")  # operator also present
    assert resolve_signing_capauth_dir("lumina") == (
        fake_home / ".skcapstone" / "agents" / "lumina" / "capauth"
    )


def test_falls_back_to_consolidated_operator(fake_home):
    _write_key(fake_home, ".skcapstone/capauth")  # only the operator key
    assert resolve_signing_capauth_dir("lumina") == (
        fake_home / ".skcapstone" / "capauth"
    )


def test_none_when_no_key_anywhere(fake_home):
    assert resolve_signing_capauth_dir("lumina") is None


def test_gate_and_resolver_agree_on_order(fake_home):
    """private_key_paths mirrors the resolver's three-tier order."""
    paths = private_key_paths("lumina")
    assert paths == [
        fake_home / ".skcapstone" / "agents" / "lumina" / "capauth" / "identity" / "private.asc",
        fake_home / ".skcapstone" / "capauth" / "identity" / "private.asc",
        fake_home / ".capauth" / "identity" / "private.asc",
    ]
