"""Tests for skcomms.capabilities — the honest capability document.

All standalone: a minimal :class:`SKComms` built from a tiny config, ``probe``
disabled so no sockets are opened. The headline cases:

  * the document has the documented shape (node / transports / services);
  * a transport NOT in this node's config reports ``unconfigured``;
  * a configured + registered transport reports a live status (not unconfigured);
  * services are derived from their underlying transports' status.
"""

from __future__ import annotations

from skcomms.capabilities import (
    API_VERSION,
    CONFIGURED,
    UNCONFIGURED,
    UP,
    build_capabilities,
)
from skcomms.config import SKCommsConfig, TransportConfig
from skcomms.core import SKComms


def _build_with_file_only(tmp_path) -> dict:
    """Build a capability doc for a node that only configures ``file``."""
    config = SKCommsConfig(
        encrypt=False,
        sign=False,
        ack=False,
        transports={"file": TransportConfig(enabled=True, priority=1)},
    )
    # Build the router the way from_config does, but inline so we control config
    # entirely (no on-disk config.yml dependency).
    from skcomms.core import _load_transport
    from skcomms.router import Router

    router = Router(default_mode=config.default_mode)
    transport = _load_transport(
        "file",
        1,
        {
            "outbox_path": str(tmp_path / "outbox"),
            "inbox_path": str(tmp_path / "inbox"),
        },
    )
    if transport is not None:
        router.register_transport(transport)
    comm = SKComms(config=config, router=router)
    return build_capabilities(comm, probe=False)


def test_shape(tmp_path):
    doc = _build_with_file_only(tmp_path)
    assert set(doc.keys()) == {"api", "node", "transports", "services", "modules"}

    node = doc["node"]
    assert set(node.keys()) >= {"id", "label", "host"}

    # Transports: every record has id/protocol/status/roles.
    ids = set()
    for t in doc["transports"]:
        assert {"id", "protocol", "status", "roles"} <= set(t.keys())
        assert isinstance(t["roles"], list)
        ids.add(t["id"])
    # The full catalog is advertised regardless of config.
    assert {
        "file",
        "syncthing",
        "https-s2s",
        "websocket",
        "tailscale",
        "webrtc",
        "p2p",
        "ble-mesh",
        "lora",
        "nostr",
    } <= ids

    # Services: every record has id/status (+ via).
    svc_ids = {s["id"] for s in doc["services"]}
    for s in doc["services"]:
        assert {"id", "status"} <= set(s.keys())
    assert {
        "text",
        "voice",
        "video",
        "file-transfer",
        "data-streaming",
        "federation",
        "access-plane",
        "geo-cot",
    } <= svc_ids


def test_webrtc_advertises_media(tmp_path):
    doc = _build_with_file_only(tmp_path)
    webrtc = next(t for t in doc["transports"] if t["id"] == "webrtc")
    assert webrtc["media"] == ["audio", "video"]


def test_unconfigured_transport_reports_unconfigured(tmp_path):
    """A transport absent from this node's config must report ``unconfigured``."""
    doc = _build_with_file_only(tmp_path)
    by_id = {t["id"]: t for t in doc["transports"]}

    # file IS configured + registered -> NOT unconfigured (live status).
    assert by_id["file"]["status"] != UNCONFIGURED

    # None of these were configured -> unconfigured.
    for tid in ("syncthing", "tailscale", "webrtc", "p2p", "ble-mesh", "lora", "nostr"):
        assert by_id[tid]["status"] == UNCONFIGURED, tid


def test_services_derive_from_transports(tmp_path):
    """Services are only as available as their best rail.

    With only ``file`` live (probe disabled), text is up (file backs it) while
    voice/video (webrtc/livekit only) are not up.
    """
    doc = _build_with_file_only(tmp_path)
    by_id = {s["id"]: s for s in doc["services"]}

    # file-transfer + text ride file -> up.
    assert by_id["text"]["status"] == UP
    assert by_id["file-transfer"]["status"] == UP

    # voice/video need webrtc/livekit, none configured + probe off -> not up.
    assert by_id["voice"]["status"] != UP
    assert by_id["video"]["status"] != UP

    # With probe disabled, probe-backed services fall back to configured.
    assert by_id["access-plane"]["status"] == CONFIGURED
    assert by_id["geo-cot"]["status"] == CONFIGURED


def test_no_skcomms_returns_wellformed_document():
    """With ``skcomms=None`` the helper self-loads from config and still returns
    a well-formed doc (statuses depend on the running node's config)."""
    doc = build_capabilities(skcomms=None, probe=False)
    assert set(doc.keys()) == {"api", "node", "transports", "services", "modules"}
    valid = {"up", "configured", "degraded", "down", "unconfigured"}
    assert len(doc["transports"]) == 10
    for t in doc["transports"]:
        assert t["status"] in valid


def test_explicit_empty_engine_all_unconfigured():
    """An engine with NO transports registered/configured -> all unconfigured."""
    config = SKCommsConfig(encrypt=False, sign=False, ack=False, transports={})
    from skcomms.router import Router

    comm = SKComms(config=config, router=Router(default_mode=config.default_mode))
    doc = build_capabilities(comm, probe=False)
    for t in doc["transports"]:
        assert t["status"] == UNCONFIGURED


def test_api_and_modules_block(tmp_path):
    """The doc carries an integer ``api`` version and a ``modules`` hint list.

    Both are additive (backward-compatible) — they enable client-side
    ``minDaemonApi`` gating and operator-policy module surfacing without
    restructuring the existing transports/services arrays.
    """
    doc = _build_with_file_only(tmp_path)

    # api: an integer, matching the module's declared version.
    assert isinstance(doc["api"], int)
    assert doc["api"] == API_VERSION

    # modules: a list of string ids including the skmap pilot + core surfaces.
    assert isinstance(doc["modules"], list)
    assert all(isinstance(m, str) for m in doc["modules"])
    assert "skmap" in doc["modules"]
    assert "chats" in doc["modules"]

    # Additive: the existing arrays are untouched and still present.
    assert isinstance(doc["transports"], list) and doc["transports"]
    assert isinstance(doc["services"], list) and doc["services"]
