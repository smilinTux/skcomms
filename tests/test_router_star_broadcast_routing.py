"""Workstream B3: router '*' broadcast must exclude point-to-point-only rails.

RC3 (the ``*`` heartbeat bug): ``skchat`` broadcasts presence to the literal
recipient ``"*"`` every ~60s. Point-to-point rails (``https-s2s``,
``tailscale``) were offered as candidates and turned ``"*"`` into a peer-store
lookup that raised ``Peer name '*' is empty after sanitization`` — two WARNINGs
per heartbeat. The fix: when ``recipient == "*"``, ``_select_transports`` keeps
only broadcast/relay-capable rails and drops the point-to-point-only ones, so a
broadcast never even offers a rail that cannot serve it (no ValueError, no WARN).
"""

from __future__ import annotations

import logging

import pytest

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


class FakeTransport(Transport):
    def __init__(self, name, priority, send_log, *, succeed=True, available=True,
                 category=TransportCategory.REALTIME):
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


def _broadcast_envelope() -> MessageEnvelope:
    return MessageEnvelope(
        sender="lumina",
        recipient="*",
        payload=MessagePayload(content="heartbeat", content_type=MessageType.HEARTBEAT),
        routing=RoutingConfig(mode=RoutingMode.BROADCAST),
    )


def _dm_envelope() -> MessageEnvelope:
    return MessageEnvelope(
        sender="lumina",
        recipient="jarvis",
        payload=MessagePayload(content="hi"),
        routing=RoutingConfig(mode=RoutingMode.FAILOVER),
    )


def test_star_broadcast_excludes_point_to_point_rails():
    log: list[str] = []
    transports = [
        FakeTransport("https-s2s", priority=1, send_log=log),
        FakeTransport("tailscale", priority=2, send_log=log),
        FakeTransport("file", priority=3, send_log=log, category=TransportCategory.FILE_BASED),
        FakeTransport("nostr", priority=4, send_log=log),
    ]
    r = Router(transports=transports)
    env = _broadcast_envelope()

    names = [t.name for t in r._select_transports(RoutingMode.BROADCAST, env)]

    assert "https-s2s" not in names
    assert "tailscale" not in names
    assert "file" in names
    assert "nostr" in names


def test_star_broadcast_route_does_not_touch_point_to_point_or_warn(caplog):
    log: list[str] = []
    transports = [
        FakeTransport("https-s2s", priority=1, send_log=log),
        FakeTransport("tailscale", priority=2, send_log=log),
        FakeTransport("file", priority=3, send_log=log, category=TransportCategory.FILE_BASED),
    ]
    r = Router(transports=transports)
    env = _broadcast_envelope()

    with caplog.at_level(logging.WARNING, logger="skcomms.router"):
        report = r.route(env)

    # Point-to-point rails must never be attempted for a '*' broadcast...
    assert "https-s2s" not in log
    assert "tailscale" not in log
    # ...delivery still lands on the broadcast-capable rail, and nothing WARNs.
    assert "file" in log
    assert report.delivered is True
    assert [rec for rec in caplog.records if rec.levelno >= logging.WARNING] == []


def test_dm_still_offers_point_to_point_rails():
    """A normal (non-'*') DM is unaffected: point-to-point rails stay eligible."""
    log: list[str] = []
    transports = [
        FakeTransport("tailscale", priority=2, send_log=log),
        FakeTransport("file", priority=3, send_log=log, category=TransportCategory.FILE_BASED),
    ]
    r = Router(transports=transports)
    env = _dm_envelope()

    names = [t.name for t in r._select_transports(RoutingMode.FAILOVER, env)]
    assert "tailscale" in names
    assert "file" in names
