"""Regression test for the chronic https-s2s 422 log-noise shadow.

Root cause: ``Router.route()`` is the LEGACY / unsigned ``MessageEnvelope``
path (used by ``Comm.send()`` for heartbeats, typing indicators, and any
non-federated send). It selects candidate transports purely by availability
and priority/chain order, with no awareness that ``/api/v1/inbox`` (the
receiving end of the ``https-s2s`` transport) hard-requires a
:class:`~skcomms.envelope.SignedEnvelope` (see ``api.py::post_inbox`` —
``SignedEnvelope.from_bytes`` raises -> 422 on anything else).

Because ``route()`` serializes a plain ``MessageEnvelope`` (``envelope.to_bytes()``,
never a ``SignedEnvelope``) and still offers ``https-s2s`` as a candidate
whenever ANY peer in the store advertises an inbox_url, every legacy send
that reaches this transport is a **guaranteed, 100%-reproducible** 422 —
confirmed by ~75k identical "https-s2s inbox returned 422 (perm)" log lines
in the live daemon log with zero corresponding successes via this path (the
only https-s2s successes on record go through the SIGNED federation path,
``send_federated`` -> ``route_signed`` -> ``route_bytes``, which this fix
must not touch).

The fix: ``route()`` excludes known signed-envelope-only rails from its
candidate list. ``route_bytes`` / ``route_signed`` (which put real
``SignedEnvelope`` bytes on the wire) are unaffected.
"""

from __future__ import annotations

import pytest

from skcomms import router as router_mod
from skcomms.models import MessageEnvelope, MessagePayload, MessageType, RoutingConfig, RoutingMode
from skcomms.router import Router
from skcomms.transport import HealthStatus, SendResult, Transport, TransportCategory, TransportStatus


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


@pytest.fixture(autouse=True)
def isolate_retry_queue(tmp_path, monkeypatch):
    # Router JSONL retry queue was removed (PersistentOutbox is the single
    # queue of record); nothing to isolate. Inert fixture kept for structure.
    yield


def make_envelope(preferred: list[str] | None = None, recipient: str = "*") -> MessageEnvelope:
    routing = RoutingConfig(mode=RoutingMode.FAILOVER)
    if preferred is not None:
        routing.preferred_transports = preferred
    return MessageEnvelope(
        sender="lumina",
        recipient=recipient,
        payload=MessagePayload(content="heartbeat", content_type=MessageType.HEARTBEAT),
        routing=routing,
    )


def test_unsigned_route_never_offers_https_s2s_as_a_candidate():
    """route() (unsigned/legacy) must not select https-s2s, even when it is
    the only/highest-priority available transport."""
    log: list[str] = []
    transports = [
        FakeTransport("https-s2s", priority=1, send_log=log, succeed=True),
        FakeTransport("tailscale", priority=2, send_log=log, succeed=False),
        FakeTransport("file", priority=3, send_log=log, succeed=True),
    ]
    r = Router(transports=transports)
    # DM recipient isolates the signed-only exclusion from the separate '*'
    # broadcast rule (which also drops point-to-point rails like tailscale).
    env = make_envelope(recipient="jarvis")

    report = r.route(env)

    # https-s2s must never be attempted on the unsigned path...
    assert "https-s2s" not in log
    # ...delivery still succeeds via the next real candidate (file).
    assert report.delivered is True
    assert log == ["tailscale", "file"]


def test_unsigned_route_falls_through_when_https_s2s_is_the_only_transport():
    """If https-s2s is literally the only registered transport, the unsigned
    path must not silently 'succeed' through it — it should report
    undelivered (and fall to the retry queue), not paper over the mismatch."""
    log: list[str] = []
    transports = [FakeTransport("https-s2s", priority=1, send_log=log, succeed=True)]
    r = Router(transports=transports)
    env = make_envelope()

    report = r.route(env)

    assert log == []  # never even attempted
    assert report.delivered is False


def test_signed_path_still_uses_https_s2s(monkeypatch, tmp_path):
    """route_bytes()/route_signed() (the SIGNED federation path) must be
    completely unaffected — https-s2s stays a normal candidate there."""
    log: list[str] = []
    transports = [FakeTransport("https-s2s", priority=1, send_log=log, succeed=True)]
    r = Router(transports=transports)

    report = r.route_bytes(b"signed-envelope-bytes", "jarvis@chef.skworld")

    assert log == ["https-s2s"]
    assert report.delivered is True


def test_select_transports_default_still_includes_https_s2s():
    """Direct _select_transports() calls (as used by pre-existing callers /
    tests) are unaffected unless the new exclude flag is explicitly set."""
    log: list[str] = []
    transports = [FakeTransport("https-s2s", priority=1, send_log=log)]
    r = Router(transports=transports)
    # DM recipient: the '*' broadcast rule (B3) independently drops https-s2s,
    # so use a normal recipient to check the exclude_signed_only flag alone.
    env = make_envelope(recipient="jarvis")

    names = [t.name for t in r._select_transports(RoutingMode.FAILOVER, env)]
    assert names == ["https-s2s"]

    names_excluded = [
        t.name for t in r._select_transports(RoutingMode.FAILOVER, env, exclude_signed_only=True)
    ]
    assert names_excluded == []
