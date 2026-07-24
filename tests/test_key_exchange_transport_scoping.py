"""key_exchange default-transport routing through the paths resolver (coord 48289e82).

``import_peer_bundle`` used to fall back to hardcoded node-shared transport
paths (``~/.skcapstone/comms`` for syncthing, ``~/.skcapstone/skcomms/inbox``
for file) when the imported bundle advertised no transports of its own. Those
literals bypassed :mod:`skcomms.paths`, the single resolver that
``config.load_config`` and the S2S inbox writer use, so an agent-scoped daemon
polling ``agents/<agent>/comms/inbox`` never saw envelopes dropped at the
node-shared inbox.

These tests prove the default transports now resolve through
:mod:`skcomms.paths`, honoring per-agent scoping (the file inbox and syncthing
comms_root point at the acting agent's OWN ``agents/<agent>/comms`` tree),
while an agentless import keeps the legacy node-shared locations.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skcomms.key_exchange import import_peer_bundle

# A minimal well-formed public key block (import_peer_bundle only checks for the
# armor marker; gpg_import is disabled so no real key material is needed).
_FAKE_PUBKEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    "\n"
    "mDMEfakekeyfakekeyfakekeyfakekeyfakekeyfakekeyfakekey\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n"
)


def _bundle_without_transports() -> dict:
    return {
        "skcomms_peer_bundle": "1.0",
        "name": "Remote Peer",
        "fingerprint": "A" * 40,
        "public_key": _FAKE_PUBKEY,
        # deliberately NO "transports" key -> exercises the default fallback
    }


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("SKCOMMS_HOME", "SKAGENT", "SKCAPSTONE_AGENT"):
        monkeypatch.delenv(var, raising=False)
    yield


def _settings_for(peer, transport_name: str) -> dict:
    for t in peer.transports:
        if t.transport == transport_name:
            return t.settings
    raise AssertionError(f"no {transport_name!r} transport on imported peer")


def test_scoped_agent_default_transports_use_resolver(monkeypatch, tmp_path):
    """With SKAGENT set, the default file/syncthing routes point at the acting
    agent's own agents/<agent>/comms tree, not the node-shared inbox."""
    home = tmp_path / "skcomms-home"
    monkeypatch.setenv("SKCOMMS_HOME", str(home))
    monkeypatch.setenv("SKAGENT", "lumina")

    peers_dir = tmp_path / "peers"
    peer = import_peer_bundle(
        _bundle_without_transports(), peers_dir=peers_dir, gpg_import=False
    )

    expected_comms = home / "agents" / "lumina" / "comms"

    assert _settings_for(peer, "syncthing")["comms_root"] == str(expected_comms)
    assert _settings_for(peer, "file")["inbox_path"] == str(expected_comms / "inbox")

    # The old hardcoded node-shared defaults must be gone.
    assert _settings_for(peer, "syncthing")["comms_root"] != "~/.skcapstone/comms"
    assert _settings_for(peer, "file")["inbox_path"] != "~/.skcapstone/skcomms/inbox"


def test_two_agents_get_separated_default_inboxes(monkeypatch, tmp_path):
    """Two agents importing the same bundle on one node resolve to their OWN,
    non-colliding comms inboxes (the divergence bug is dead)."""
    home = tmp_path / "skcomms-home"
    monkeypatch.setenv("SKCOMMS_HOME", str(home))

    monkeypatch.setenv("SKAGENT", "lumina")
    p_lumina = import_peer_bundle(
        _bundle_without_transports(), peers_dir=tmp_path / "pl", gpg_import=False
    )
    monkeypatch.setenv("SKAGENT", "jarvis")
    p_jarvis = import_peer_bundle(
        _bundle_without_transports(), peers_dir=tmp_path / "pj", gpg_import=False
    )

    lumina_inbox = _settings_for(p_lumina, "file")["inbox_path"]
    jarvis_inbox = _settings_for(p_jarvis, "file")["inbox_path"]

    assert lumina_inbox != jarvis_inbox
    assert lumina_inbox == str(home / "agents" / "lumina" / "comms" / "inbox")
    assert jarvis_inbox == str(home / "agents" / "jarvis" / "comms" / "inbox")


def test_agentless_default_transports_keep_legacy_paths(monkeypatch, tmp_path):
    """With no agent selector, the file inbox resolves to the recipient-less
    federation landing zone under the home (SKCOMMS_HOME honored) and syncthing
    keeps the legacy node-shared comms root."""
    home = tmp_path / "skcomms-home"
    monkeypatch.setenv("SKCOMMS_HOME", str(home))

    peer = import_peer_bundle(
        _bundle_without_transports(), peers_dir=tmp_path / "peers", gpg_import=False
    )

    assert _settings_for(peer, "syncthing")["comms_root"] == "~/.skcapstone/comms"
    # fed_inbox_base() == skcomms_home()/inbox, honoring SKCOMMS_HOME.
    assert _settings_for(peer, "file")["inbox_path"] == str(home / "inbox")


def test_bundle_supplied_transports_are_preserved(monkeypatch, tmp_path):
    """A bundle that DOES advertise transports keeps them verbatim (the default
    fallback only fires when the bundle is transport-less)."""
    monkeypatch.setenv("SKAGENT", "lumina")
    bundle = _bundle_without_transports()
    bundle["transports"] = [
        {"transport": "nostr", "settings": {"relay": "wss://relay.example"}}
    ]

    peer = import_peer_bundle(bundle, peers_dir=tmp_path / "peers", gpg_import=False)

    assert [t.transport for t in peer.transports] == ["nostr"]
    assert _settings_for(peer, "nostr")["relay"] == "wss://relay.example"
