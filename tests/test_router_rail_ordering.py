"""Tests for federation rail ordering + store-and-forward fallback.

Covers [skfed][P1.S3] router behavior:
  (a) peer-advertised rail order is honored EXACTLY,
  (b) federation default chain is used when no order is advertised,
  (c) failover tries the next rail on failure,
  (d) the store-and-forward rail ("nostr") is attempted after all direct
      rails fail.

Uses fake Transport subclasses that record send order and have controllable
success/failure, so no real network/relay is touched.
"""

from __future__ import annotations

import pathlib

import pytest

from skcomms import router as router_mod
from skcomms.models import (
    MessageEnvelope,
    MessagePayload,
    MessageType,
    RoutingConfig,
    RoutingMode,
)
from skcomms.router import Router
from skcomms.transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeTransport(Transport):
    """A controllable transport that records the order in which it is sent to.

    Args:
        name: Transport name (matched against the rail chain / advertised order).
        priority: Global priority (lower = higher); used for default fallback sort.
        send_log: Shared list every transport appends its name to on send().
        succeed: Whether send() reports success.
        available: Whether is_available() returns True.
        category: Behavioral category for stealth/speed filtering.
    """

    def __init__(
        self,
        name: str,
        priority: int,
        send_log: list[str],
        *,
        succeed: bool = True,
        available: bool = True,
        category: TransportCategory = TransportCategory.REALTIME,
    ):
        self.name = name
        self.priority = priority
        self.category = category
        self._send_log = send_log
        self._succeed = succeed
        self._available = available

    def configure(self, config: dict) -> None:  # pragma: no cover - trivial
        pass

    def is_available(self) -> bool:
        return self._available

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        self._send_log.append(self.name)
        return SendResult(
            success=self._succeed,
            transport_name=self.name,
            envelope_id="",
            latency_ms=0.0,
            error=None if self._succeed else "forced failure",
        )

    def receive(self) -> list[bytes]:  # pragma: no cover - unused
        return []

    def health_check(self) -> HealthStatus:  # pragma: no cover - unused
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolate_retry_queue(tmp_path, monkeypatch):
    """Inert: the router JSONL retry queue was removed (durable retry moved to
    the PersistentOutbox, the single queue of record), so there is no
    background worker to isolate."""
    yield


def make_envelope(preferred: list[str] | None = None) -> MessageEnvelope:
    routing = RoutingConfig(mode=RoutingMode.FAILOVER)
    if preferred is not None:
        routing.preferred_transports = preferred
    return MessageEnvelope(
        sender="lumina",
        recipient="jarvis",
        payload=MessagePayload(content="hi", content_type=MessageType.TEXT),
        routing=routing,
    )


# ---------------------------------------------------------------------------
# (a) peer-advertised order honored exactly
# ---------------------------------------------------------------------------


def test_peer_advertised_order_is_honored_exactly():
    log: list[str] = []
    # Register in an order that does NOT match either priority or advertised order.
    transports = [
        FakeTransport("file", priority=1, send_log=log),       # lowest priority number
        FakeTransport("telegram", priority=2, send_log=log),
        FakeTransport("lora", priority=3, send_log=log),
        FakeTransport("nostr", priority=4, send_log=log),
    ]
    r = Router(transports=transports)
    # Peer advertises a deliberate order distinct from priority + default chain.
    env = make_envelope(preferred=["telegram", "lora", "file"])

    candidates = r._select_transports(RoutingMode.FAILOVER, env)
    names = [t.name for t in candidates]

    # Advertised rails lead, in EXACTLY the advertised order...
    assert names[:3] == ["telegram", "lora", "file"]
    # ...then the un-advertised remainder (nostr) follows as a fallback.
    assert "nostr" in names[3:]


def test_peer_advertised_order_survives_actual_routing():
    log: list[str] = []
    transports = [
        FakeTransport("file", priority=1, send_log=log),
        FakeTransport("telegram", priority=2, send_log=log),
        FakeTransport("lora", priority=3, send_log=log, succeed=True),
    ]
    r = Router(transports=transports)
    # First two advertised rails fail so we can prove the order is walked.
    transports[1]._succeed = False  # telegram fails
    env = make_envelope(preferred=["telegram", "lora", "file"])

    report = r.route(env)

    assert report.delivered is True
    assert report.successful_transport == "lora"
    # telegram tried first (and failed), then lora delivered. file never reached.
    assert log == ["telegram", "lora"]


# ---------------------------------------------------------------------------
# (b) federation default chain when unspecified
# ---------------------------------------------------------------------------


def test_default_federation_chain_when_no_preference():
    log: list[str] = []
    # Register in reverse-ish order; priorities intentionally NOT matching chain.
    transports = [
        FakeTransport("file", priority=1, send_log=log),
        FakeTransport("telegram", priority=2, send_log=log),
        FakeTransport("nostr", priority=3, send_log=log),
        FakeTransport("tailscale", priority=4, send_log=log),
        FakeTransport("https-s2s", priority=5, send_log=log),
    ]
    r = Router(transports=transports)
    env = make_envelope(preferred=None)  # no advertised order

    candidates = r._select_transports(RoutingMode.FAILOVER, env)
    names = [t.name for t in candidates]

    # Must follow FEDERATION_DEFAULT_CHAIN order, NOT registration/priority order.
    assert names == ["https-s2s", "tailscale", "nostr", "telegram", "file"]


def test_default_chain_appends_unknown_rails_by_priority():
    log: list[str] = []
    transports = [
        FakeTransport("file", priority=9, send_log=log),
        FakeTransport("https-s2s", priority=5, send_log=log),
        FakeTransport("mystery-b", priority=2, send_log=log),  # not in chain
        FakeTransport("mystery-a", priority=1, send_log=log),  # not in chain
    ]
    r = Router(transports=transports)
    env = make_envelope(preferred=None)

    names = [t.name for t in r._select_transports(RoutingMode.FAILOVER, env)]

    # Chain rails first (in chain order), then unknowns sorted by priority.
    assert names == ["https-s2s", "file", "mystery-a", "mystery-b"]


# ---------------------------------------------------------------------------
# (c) failover tries next on failure
# ---------------------------------------------------------------------------


def test_failover_tries_next_rail_on_failure():
    log: list[str] = []
    # NOTE: "https-s2s" is deliberately NOT used as a stand-in name here (it is
    # excluded from route()'s unsigned candidates — see
    # test_router_unsigned_excludes_https_s2s.py); "tailscale"/"nostr" stand in
    # for "some rail" to test pure failover-order mechanics instead.
    transports = [
        FakeTransport("tailscale", priority=1, send_log=log, succeed=False),
        FakeTransport("nostr", priority=2, send_log=log, succeed=False),
        FakeTransport("file", priority=3, send_log=log, succeed=True),
    ]
    r = Router(transports=transports)
    env = make_envelope(preferred=None)  # uses default chain order

    report = r.route(env)

    assert report.delivered is True
    assert report.successful_transport == "file"
    # Walked the chain in order: tailscale, nostr (both failed), then file.
    assert log == ["tailscale", "nostr", "file"]
    assert len(report.attempts) == 3


# ---------------------------------------------------------------------------
# (d) store-and-forward fallback ("nostr") after all direct rails fail
# ---------------------------------------------------------------------------


def test_store_forward_nostr_attempted_after_all_direct_fail():
    log: list[str] = []
    # Direct rails (advertised) all fail; ble is NOT advertised, so it is only
    # reached via the store-and-forward fallback seam.
    # NOTE: "https-s2s" is deliberately NOT used as a stand-in (excluded from
    # route()'s unsigned candidates — see test_router_unsigned_excludes_https_s2s.py).
    transports = [
        FakeTransport("tailscale", priority=1, send_log=log, succeed=False),
        FakeTransport("nostr", priority=2, send_log=log, succeed=False),
        FakeTransport("ble", priority=3, send_log=log, succeed=True),
    ]
    r = Router(transports=transports)
    env = make_envelope(preferred=["tailscale", "nostr"])

    report = r.route(env)

    assert report.delivered is True
    assert report.successful_transport == "ble"
    # Direct rails tried first, then the S&F fallback rail last.
    assert log == ["tailscale", "nostr", "ble"]


def test_store_forward_not_double_sent_when_already_a_candidate():
    log: list[str] = []
    # nostr IS in the default chain (and thus a direct candidate). It must not be
    # sent twice — once as a direct rail and again as the S&F fallback.
    transports = [
        FakeTransport("tailscale", priority=1, send_log=log, succeed=False),
        FakeTransport("nostr", priority=2, send_log=log, succeed=False),
    ]
    r = Router(transports=transports)
    env = make_envelope(preferred=None)

    report = r.route(env)

    assert report.delivered is False
    # nostr attempted exactly once (as a direct rail), not re-attempted as S&F.
    assert log == ["tailscale", "nostr"]


def test_store_forward_skipped_when_rail_unavailable():
    log: list[str] = []
    transports = [
        FakeTransport("tailscale", priority=1, send_log=log, succeed=False),
        FakeTransport("nostr", priority=2, send_log=log, succeed=True, available=False),
    ]
    r = Router(transports=transports)
    env = make_envelope(preferred=["tailscale"])

    report = r.route(env)

    assert report.delivered is False
    # nostr unavailable → never sent, even as S&F fallback.
    assert log == ["tailscale"]


def test_custom_store_forward_transport_name():
    log: list[str] = []
    transports = [
        FakeTransport("tailscale", priority=1, send_log=log, succeed=False),
        FakeTransport("ipfs", priority=9, send_log=log, succeed=True),
    ]
    r = Router(transports=transports, store_forward_transport="ipfs")
    # ipfs is not in the default chain, so only reached via the configurable seam.
    env = make_envelope(preferred=["tailscale"])

    report = r.route(env)

    assert report.delivered is True
    assert report.successful_transport == "ipfs"
    assert log == ["tailscale", "ipfs"]
