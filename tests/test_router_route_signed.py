"""Tests for Router.route_signed / route_bytes — the S4 federation send path.

route_signed sends a SignedEnvelope's own bytes verbatim, addressed by its
inner to_fqid, honoring peer-advertised rail order; the outbox (not the router)
owns retry, so route_bytes does NOT enqueue on failure.
"""

from __future__ import annotations

import pytest

from skcomms import router as router_mod
from skcomms.envelope import Envelope, SignedEnvelope
from skcomms.router import Router
from skcomms.transport import (
    HealthStatus, SendResult, Transport, TransportCategory, TransportStatus,
)


class FakeTransport(Transport):
    def __init__(self, name, priority, log, *, succeed=True, available=True):
        self.name = name
        self.priority = priority
        self.category = TransportCategory.REALTIME
        self._log = log
        self._succeed = succeed
        self._available = available
        self.sent: list[tuple[str, bytes]] = []

    def configure(self, config): pass
    def is_available(self): return self._available
    def send(self, envelope_bytes, recipient):
        self._log.append(self.name)
        self.sent.append((recipient, envelope_bytes))
        return SendResult(success=self._succeed, transport_name=self.name,
                          envelope_id="", latency_ms=0.0,
                          error=None if self._succeed else "forced")
    def receive(self): return []
    def health_check(self):
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


@pytest.fixture(autouse=True)
def isolate_retry_queue(tmp_path, monkeypatch):
    # The router no longer owns a JSONL retry queue (durable retry moved to the
    # PersistentOutbox, the single queue of record), so there is nothing to
    # isolate. Kept as an inert autouse fixture to preserve test structure.
    yield


def _signed() -> SignedEnvelope:
    env = Envelope(from_fqid="jarvis@chef.skworld", to_fqid="lumina@chef.skworld",
                   body="hello over s2s")
    return SignedEnvelope(envelope=env, signature="sig", signer_fingerprint="FP")


def test_route_signed_sends_signed_bytes_to_to_fqid():
    log: list[str] = []
    t = FakeTransport("https-s2s", 1, log)
    r = Router(transports=[t])
    signed = _signed()
    report = r.route_signed(signed)
    assert report.delivered is True
    assert log == ["https-s2s"]
    recipient, wire = t.sent[0]
    assert recipient == "lumina@chef.skworld"          # routed by inner to_fqid
    assert wire == signed.to_bytes()                    # verbatim signed bytes


def test_route_signed_honors_preferred_rail_order():
    log: list[str] = []
    a = FakeTransport("https-s2s", 1, log)
    b = FakeTransport("nostr", 2, log)
    r = Router(transports=[a, b])
    # advertise nostr first, https-s2s second, but make nostr succeed
    r.route_signed(_signed(), preferred_transports=["nostr", "https-s2s"])
    assert log[0] == "nostr"                            # advertised order honored


def test_route_signed_failover_then_success():
    log: list[str] = []
    a = FakeTransport("https-s2s", 1, log, succeed=False)
    b = FakeTransport("tailscale", 2, log, succeed=True)
    r = Router(transports=[a, b])
    report = r.route_signed(_signed(), preferred_transports=["https-s2s", "tailscale"])
    assert report.delivered is True
    assert log == ["https-s2s", "tailscale"]            # failover to next


def test_route_bytes_no_candidates_not_delivered():
    log: list[str] = []
    t = FakeTransport("https-s2s", 1, log, available=False)
    r = Router(transports=[t])
    report = r.route_bytes(b"x", "lumina@chef.skworld")
    assert report.delivered is False
    assert log == []                                    # nothing attempted
