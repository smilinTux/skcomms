"""Tests for the sovereign node registry (durable cross-node inbox addressing).

The cross-node ratchet historically HARDCODED tailscale IPs in each peer's
``transports[].settings.inbox_url``. When a node moved (new tailnet IP) every
peer file went stale. The :mod:`skcomms.node_registry` makes addressing durable:
a small ``node_registry.yml`` maps ``agent-short -> {ts_host|ts_ip, daemon_port}``
and a resolver emits a REACHABLE ``http://<ts-ip-or-host>:<port>/api/v1/inbox``
(the :8765 daemon-proxy serves both ``/api/v1/inbox`` and ``/api/v1/prekey``).

All tailscale-status access is INJECTED — no real ``tailscale`` call here.
"""

from __future__ import annotations

import pytest

from skcomms.node_registry import NodeEntry, NodeRegistry


# ---------------------------------------------------------------------------
# Resolver — ts_ip / ts_host / port
# ---------------------------------------------------------------------------


def test_ts_ip_resolves_to_inbox_url():
    reg = NodeRegistry(entries={"jarvis": NodeEntry(ts_ip="100.86.156.5")})
    assert reg.inbox_url("jarvis") == "http://100.86.156.5:8765/api/v1/inbox"


def test_default_daemon_port_is_8765():
    reg = NodeRegistry(entries={"jarvis": {"ts_ip": "100.0.0.9"}})
    assert reg.inbox_url("jarvis").endswith(":8765/api/v1/inbox")


def test_custom_daemon_port_honored():
    reg = NodeRegistry(entries={"jarvis": NodeEntry(ts_ip="100.0.0.9", daemon_port=9999)})
    assert reg.inbox_url("jarvis") == "http://100.0.0.9:9999/api/v1/inbox"


def test_prekey_url_shares_the_daemon_proxy_port():
    reg = NodeRegistry(entries={"jarvis": NodeEntry(ts_ip="100.0.0.9")})
    assert reg.prekey_url("jarvis") == "http://100.0.0.9:8765/api/v1/prekey"


def test_ts_host_used_literally_when_no_status_provider():
    # magicDNS host is reachable as-is; no subprocess in the hot path.
    reg = NodeRegistry(entries={"lumina": NodeEntry(ts_host="noroc2027")})
    assert reg.inbox_url("lumina") == "http://noroc2027:8765/api/v1/inbox"


def test_ts_host_derives_ip_from_injected_tailscale_status():
    status = {
        "Self": {"HostName": "thisbox", "TailscaleIPs": ["100.1.1.1"]},
        "Peer": {
            "nodekeyX": {"HostName": "noroc2027", "TailscaleIPs": ["100.64.0.7", "fd7a::7"]},
        },
    }
    reg = NodeRegistry(
        entries={"lumina": NodeEntry(ts_host="noroc2027")},
        status_provider=lambda: status,
    )
    assert reg.inbox_url("lumina") == "http://100.64.0.7:8765/api/v1/inbox"


def test_ts_host_falls_back_to_literal_when_status_has_no_match():
    reg = NodeRegistry(
        entries={"lumina": NodeEntry(ts_host="ghost")},
        status_provider=lambda: {"Peer": {}},
    )
    assert reg.inbox_url("lumina") == "http://ghost:8765/api/v1/inbox"


def test_ts_ip_takes_precedence_over_ts_host():
    reg = NodeRegistry(
        entries={"jarvis": NodeEntry(ts_ip="100.5.5.5", ts_host="somehost")},
    )
    assert reg.inbox_url("jarvis") == "http://100.5.5.5:8765/api/v1/inbox"


# ---------------------------------------------------------------------------
# Graceful degradation — never crash
# ---------------------------------------------------------------------------


def test_unknown_agent_returns_none():
    reg = NodeRegistry(entries={"jarvis": NodeEntry(ts_ip="100.0.0.1")})
    assert reg.inbox_url("nobody") is None


def test_entry_with_neither_ip_nor_host_returns_none():
    reg = NodeRegistry(entries={"hollow": NodeEntry()})
    assert reg.inbox_url("hollow") is None


def test_bad_status_provider_degrades_to_literal_host():
    def boom():
        raise RuntimeError("tailscale down")

    reg = NodeRegistry(
        entries={"lumina": NodeEntry(ts_host="noroc2027")},
        status_provider=boom,
    )
    # A failing tailscale lookup must not crash — fall back to the literal host.
    assert reg.inbox_url("lumina") == "http://noroc2027:8765/api/v1/inbox"


# ---------------------------------------------------------------------------
# YAML loading — file, missing file, malformed file
# ---------------------------------------------------------------------------


def test_load_from_yaml_nodes_section(tmp_path):
    p = tmp_path / "node_registry.yml"
    p.write_text(
        "nodes:\n"
        "  jarvis:\n"
        "    ts_ip: 100.86.156.5\n"
        "    daemon_port: 8765\n"
        "  lumina:\n"
        "    ts_host: noroc2027\n"
    )
    reg = NodeRegistry.load(path=p)
    assert reg.inbox_url("jarvis") == "http://100.86.156.5:8765/api/v1/inbox"
    assert reg.inbox_url("lumina") == "http://noroc2027:8765/api/v1/inbox"


def test_load_from_yaml_bare_mapping(tmp_path):
    p = tmp_path / "node_registry.yml"
    p.write_text("jarvis:\n  ts_ip: 100.0.0.2\n")
    reg = NodeRegistry.load(path=p)
    assert reg.inbox_url("jarvis") == "http://100.0.0.2:8765/api/v1/inbox"


def test_load_missing_file_is_empty_registry(tmp_path):
    reg = NodeRegistry.load(path=tmp_path / "does-not-exist.yml")
    assert reg.inbox_url("jarvis") is None


def test_load_malformed_file_degrades_gracefully(tmp_path):
    p = tmp_path / "node_registry.yml"
    p.write_text("this: is: not: valid: yaml: [")
    reg = NodeRegistry.load(path=p)  # must not raise
    assert reg.inbox_url("jarvis") is None


# ---------------------------------------------------------------------------
# inbox_url_for integration — PREFER registry, FALL BACK to transport, None
# ---------------------------------------------------------------------------


def _store_with_peer(tmp_path, inbox_url):
    from skcomms.discovery import PeerInfo, PeerStore, PeerTransport

    store = PeerStore(peers_dir=tmp_path / "peers")
    store.add(
        PeerInfo(
            name="jarvis",
            fqid="jarvis@chef.skworld",
            transports=[
                PeerTransport(transport="https-s2s", settings={"inbox_url": inbox_url})
            ],
        )
    )
    return store


def test_inbox_url_for_prefers_registry_over_transport(tmp_path):
    from skcomms.discovery import inbox_url_for

    store = _store_with_peer(tmp_path, inbox_url="http://10.0.0.99:8765/api/v1/inbox")
    reg = NodeRegistry(entries={"jarvis": NodeEntry(ts_ip="100.86.156.5")})
    url = inbox_url_for("jarvis@chef.skworld", store=store, registry=reg)
    assert url == "http://100.86.156.5:8765/api/v1/inbox"


def test_inbox_url_for_falls_back_to_transport_when_registry_silent(tmp_path):
    from skcomms.discovery import inbox_url_for

    store = _store_with_peer(tmp_path, inbox_url="http://10.0.0.99:8765/api/v1/inbox")
    reg = NodeRegistry(entries={})  # registry knows nothing
    url = inbox_url_for("jarvis@chef.skworld", store=store, registry=reg)
    assert url == "http://10.0.0.99:8765/api/v1/inbox"


def test_inbox_url_for_returns_none_when_neither_resolves(tmp_path):
    from skcomms.discovery import PeerStore, inbox_url_for

    empty_store = PeerStore(peers_dir=tmp_path / "peers")
    reg = NodeRegistry(entries={})
    assert inbox_url_for("ghost@chef.skworld", store=empty_store, registry=reg) is None


def test_inbox_url_for_registry_lookup_by_bare_name(tmp_path):
    from skcomms.discovery import PeerStore, inbox_url_for

    empty_store = PeerStore(peers_dir=tmp_path / "peers")
    reg = NodeRegistry(entries={"jarvis": NodeEntry(ts_ip="100.86.156.5")})
    url = inbox_url_for("jarvis", store=empty_store, registry=reg)
    assert url == "http://100.86.156.5:8765/api/v1/inbox"
