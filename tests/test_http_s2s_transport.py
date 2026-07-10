"""Tests for the HTTP S2S federation transport (skfed S1).

Covers inbox_url resolution from the peer store, the HTTP status →
SendResult mapping (2xx → ok, 4xx → permanent failure, 5xx/timeout →
retryable failure), and the local structural gate: payloads that are not a
SignedEnvelope (the only shape the receiving inbox parses) are refused
locally as a permanent failure without any HTTP round trip. The HTTP POST is
mocked so no network is touched.
"""

from __future__ import annotations

import io
import urllib.error
import urllib.request

import pytest

from skcomms import discovery
from skcomms.discovery import PeerInfo, PeerStore, PeerTransport
from skcomms.transports import http_s2s
from skcomms.transports.http_s2s import (
    CONTENT_TYPE,
    HttpS2STransport,
    create_transport,
)

INBOX_URL = "https://noroc2027.ts.net/api/v1/inbox"
# The wire shape https-s2s carries: SignedEnvelope JSON (nested Envelope v1).
ENVELOPE = (
    b'{"envelope": {"id": "env-123", "from_fqid": "opus@chef.skworld", '
    b'"to_fqid": "jarvis@chef.skworld", "body": "hi"}, "signature": "sig"}'
)
# Legacy MessageEnvelope JSON: the inbox gate would 422 this shape.
LEGACY_ENVELOPE = (
    b'{"envelope_id": "env-legacy", "sender": "opus", "recipient": "jarvis", '
    b'"payload": {"content": "hi"}}'
)


@pytest.fixture
def peer_store(tmp_path, monkeypatch):
    """A PeerStore rooted in tmp_path, seeded with a peer that has an inbox_url.

    Both the discovery module symbol and the http_s2s late-import resolve to a
    factory bound to this temp dir, so the transport reads the seeded peer.
    """
    peers_dir = tmp_path / "peers"
    store = PeerStore(peers_dir=peers_dir)
    store.add(
        PeerInfo(
            name="jarvis",
            transports=[
                PeerTransport(transport="https-s2s", settings={"inbox_url": INBOX_URL}),
                PeerTransport(transport="tailscale", settings={"tailscale_ip": "100.1.2.3"}),
            ],
        )
    )

    def _factory(*args, **kwargs):
        return PeerStore(peers_dir=peers_dir)

    monkeypatch.setattr(discovery, "PeerStore", _factory)
    return store


class _FakeResponse:
    """Minimal stand-in for an http.client.HTTPResponse usable as a context manager."""

    def __init__(self, status: int):
        self.status = status

    def getcode(self):
        return self.status

    def read(self):
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _capturing_urlopen(status, captured):
    """Return a urlopen replacement that records the request and returns `status`."""

    def _urlopen(req, timeout=None):
        captured["req"] = req
        captured["timeout"] = timeout
        return _FakeResponse(status)

    return _urlopen


# ---------------------------------------------------------------------------
# inbox_url resolution
# ---------------------------------------------------------------------------


def test_resolves_inbox_url_from_peer_store(peer_store):
    t = HttpS2STransport()
    assert t._resolve_inbox_url("jarvis") == INBOX_URL


def test_resolve_returns_none_for_unknown_peer(peer_store):
    t = HttpS2STransport()
    assert t._resolve_inbox_url("nobody") is None


def test_is_available_true_when_peer_has_inbox(peer_store):
    assert HttpS2STransport().is_available() is True


# ---------------------------------------------------------------------------
# POST behaviour + status mapping
# ---------------------------------------------------------------------------


def test_posts_bytes_to_resolved_inbox_url(peer_store, monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(
        urllib.request, "urlopen", _capturing_urlopen(200, captured)
    )

    t = HttpS2STransport()
    result = t.send(ENVELOPE, "jarvis")

    assert result.success is True
    req = captured["req"]
    assert req.full_url == INBOX_URL
    assert req.get_method() == "POST"
    assert req.data == ENVELOPE
    # Header keys are capitalized by urllib (Content-type).
    assert req.headers.get("Content-type") == CONTENT_TYPE
    assert result.envelope_id == "env-123"


def test_200_maps_to_ok(peer_store, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _capturing_urlopen(200, {}))
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is True
    assert result.error is None


def test_2xx_201_maps_to_ok(peer_store, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _capturing_urlopen(201, {}))
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is True


def test_404_maps_to_permanent_failure(peer_store, monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(
            INBOX_URL, 404, "Not Found", hdrs=None, fp=io.BytesIO(b"")
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is False
    assert result.error.startswith("perm:")
    assert "404" in result.error


def test_4xx_403_maps_to_permanent_failure(peer_store, monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(
            INBOX_URL, 403, "Forbidden", hdrs=None, fp=io.BytesIO(b"")
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is False
    assert result.error.startswith("perm:")


def test_425_stale_maps_to_retryable_failure(peer_store, monkeypatch):
    """425 (Too Early) is the inbox's stale-envelope signal: a freshness-window
    expiry that is retryable, NOT a permanent 4xx like a schema 422/403."""
    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(
            INBOX_URL, 425, "Too Early", hdrs=None, fp=io.BytesIO(b"")
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is False
    assert result.error.startswith("retry:")
    assert "425" in result.error


def test_503_maps_to_retryable_failure(peer_store, monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(
            INBOX_URL, 503, "Service Unavailable", hdrs=None, fp=io.BytesIO(b"")
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is False
    assert result.error.startswith("retry:")
    assert "503" in result.error


def test_timeout_maps_to_retryable_failure(peer_store, monkeypatch):
    def _raise(req, timeout=None):
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is False
    assert result.error.startswith("retry:")


def test_connection_error_maps_to_retryable_failure(peer_store, monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is False
    assert result.error.startswith("retry:")


def test_unknown_peer_is_permanent_failure_without_posting(peer_store, monkeypatch):
    def _boom(req, timeout=None):
        raise AssertionError("urlopen should not be called for an unknown peer")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    result = HttpS2STransport().send(ENVELOPE, "nobody")
    assert result.success is False
    assert result.error.startswith("perm:")


# ---------------------------------------------------------------------------
# Structural gate: non-SignedEnvelope payloads never leave the box
# ---------------------------------------------------------------------------


def _no_network(monkeypatch):
    def _boom(req, timeout=None):
        raise AssertionError("urlopen must not be called for a non-signed payload")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)


def test_legacy_message_envelope_refused_locally_without_posting(peer_store, monkeypatch):
    """A legacy MessageEnvelope leak is a local perm failure, not a 422 round trip."""
    _no_network(monkeypatch)
    result = HttpS2STransport().send(LEGACY_ENVELOPE, "jarvis")
    assert result.success is False
    assert result.error.startswith("perm:")
    assert "legacy" in result.error


def test_bare_envelope_v1_refused_locally_without_posting(peer_store, monkeypatch):
    """An unsigned bare Envelope v1 is also refused before the wire."""
    _no_network(monkeypatch)
    bare = b'{"id": "e1", "from_fqid": "a@x.y", "to_fqid": "b@x.y", "body": "hi"}'
    result = HttpS2STransport().send(bare, "jarvis")
    assert result.success is False
    assert result.error.startswith("perm:")
    assert "envelope_v1" in result.error


def test_garbage_bytes_refused_locally_without_posting(peer_store, monkeypatch):
    """Non-JSON (and non-UTF-8) payloads are refused before the wire."""
    _no_network(monkeypatch)
    for garbage in (b"not json at all", b"\xff\xfe\x00\x01"):
        result = HttpS2STransport().send(garbage, "jarvis")
        assert result.success is False
        assert result.error.startswith("perm:")
        assert "corrupt" in result.error


def test_signed_envelope_passes_the_structural_gate(peer_store, monkeypatch):
    """The canonical SignedEnvelope shape still goes out on the wire."""
    captured: dict = {}
    monkeypatch.setattr(urllib.request, "urlopen", _capturing_urlopen(200, captured))
    result = HttpS2STransport().send(ENVELOPE, "jarvis")
    assert result.success is True
    assert captured["req"].data == ENVELOPE


# ---------------------------------------------------------------------------
# ABC contract
# ---------------------------------------------------------------------------


def test_receive_returns_empty_list():
    assert HttpS2STransport().receive() == []


def test_attributes_and_priority_above_tailscale():
    t = HttpS2STransport()
    assert t.name == "https-s2s"
    assert t.category == http_s2s.TransportCategory.REALTIME
    # Tailscale TCP rail is priority 2; S2S must sit above it (lower number).
    assert t.priority < 2


def test_health_check_reports_known_inboxes(peer_store):
    health = HttpS2STransport().health_check()
    assert health.transport_name == "https-s2s"
    assert health.details["known_inboxes"] == 1


def test_create_transport_factory():
    t = create_transport(priority=1)
    assert isinstance(t, HttpS2STransport)
    assert t.priority == 1


def test_registered_in_builtin_transports():
    from skcomms.core import BUILTIN_TRANSPORTS

    assert BUILTIN_TRANSPORTS["https-s2s"] == "skcomms.transports.http_s2s"
