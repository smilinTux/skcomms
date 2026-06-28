"""cot_agent must be NAME-AGNOSTIC — callsign + package derive from SKAGENT so
multiple agents (lumina/opus/jarvis) can each join the shared CoT service."""
import os
from skcomms.cot_agent import _agent_defaults


def test_defaults_derive_from_skagent(monkeypatch):
    monkeypatch.setenv("SKAGENT", "jarvis")
    d = _agent_defaults()
    assert d["callsign"] == "JARVIS"
    assert d["package"].endswith("jarvis-box.zip")


def test_defaults_fallback_lumina(monkeypatch):
    monkeypatch.delenv("SKAGENT", raising=False)
    d = _agent_defaults()
    assert d["callsign"] == "LUMINA"
    assert d["package"].endswith("lumina-box.zip")
