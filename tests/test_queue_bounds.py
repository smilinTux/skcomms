"""Queue bounds + outbound send throttling (coord 74d7b799).

Before this change no queue had a size bound (the PersistentOutbox pending
queue grew one file per entry with only supersede_key eviction), rate limiting
existed only on the INBOUND inbox gate, and the retry sweep drained every due
entry at once. So the moment the 422 fix let a big backlog flush, it could
flood a peer and re-dead-letter en masse, and a dead rail could grow the
on-disk queues without limit (the 140k-file freeze). Covered here:

  * PersistentOutbox enforces ``max_pending`` and raises OutboxFullError as
    the explicit backpressure signal (rewrites and supersede replacements are
    exempt because they never grow the queue),
  * the retry sweep drains in bounded, paced batches (``sweep_batch``),
  * FileTransport / SyncthingTransport cap outbox depth (per peer for
    syncthing) with oldest-eviction at send time,
  * the Router passes every send attempt through an outbound RateLimiter:
    throttled attempts never reach the transport, never arm the cooldown, and
    are counted separately from failures,
  * SKComms.send surfaces OutboxFullError to local callers and the HTTP API
    maps it to a 429.
"""

from __future__ import annotations

import importlib
import json
import os
import time

import pytest

from skcomms.config import SKCommsConfig
from skcomms.models import (
    MessageEnvelope,
    MessagePayload,
    RoutingConfig,
    RoutingMode,
)
from skcomms.outbox import OutboxFullError, PersistentOutbox
from skcomms.ratelimit import RateLimitConfig, RateLimiter
from skcomms.router import Router
from skcomms.transport import (
    DeliveryReport,
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

LEGACY_JSON = '{"sender": "me", "recipient": "jarvis", "payload": {"content": "x"}}'


def _envelope(recipient: str = "jarvis") -> MessageEnvelope:
    return MessageEnvelope(
        sender="me",
        recipient=recipient,
        payload=MessagePayload(content="hello"),
        routing=RoutingConfig(mode=RoutingMode.FAILOVER),
    )


class RecordingTransport(Transport):
    """A rail that records sends and always succeeds (confirmed)."""

    def __init__(self, name="tailscale", priority=1, succeed=True):
        self.name = name
        self.priority = priority
        self.category = TransportCategory.REALTIME
        self.sent: list[tuple[str, bytes]] = []
        self.succeed = succeed

    def configure(self, c):
        pass

    def is_available(self):
        return True

    def send(self, envelope_bytes, recipient):
        self.sent.append((recipient, envelope_bytes))
        return SendResult(
            success=self.succeed,
            transport_name=self.name,
            envelope_id="",
            latency_ms=0.0,
            error=None if self.succeed else "down",
        )

    def receive(self):
        return []

    def health_check(self):
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


# ---------------------------------------------------------------------------
# PersistentOutbox: max_pending bound + OutboxFullError backpressure
# ---------------------------------------------------------------------------


def test_outbox_enqueue_raises_when_full(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", max_pending=3)
    for i in range(3):
        outbox.enqueue(f"e{i}", "jarvis", LEGACY_JSON, error="down")
    assert outbox.pending_count == 3

    with pytest.raises(OutboxFullError):
        outbox.enqueue("e-overflow", "jarvis", LEGACY_JSON, error="down")

    # The bound held: nothing was written past the cap.
    assert outbox.pending_count == 3
    assert outbox.get("e-overflow") is None


def test_outbox_rewrite_of_existing_entry_allowed_at_cap(tmp_path):
    """Re-enqueueing an existing envelope_id rewrites in place, never grows."""
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", max_pending=2)
    outbox.enqueue("e0", "jarvis", LEGACY_JSON, error="first")
    outbox.enqueue("e1", "jarvis", LEGACY_JSON, error="first")

    entry = outbox.enqueue("e1", "jarvis", LEGACY_JSON, error="second attempt")

    assert entry.last_error == "second attempt"
    assert outbox.pending_count == 2


def test_outbox_supersede_replacement_allowed_at_cap(tmp_path):
    """A supersede-key replacement evicts its older twin, so it always fits."""
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", max_pending=2)
    outbox.enqueue("beacon-1", "jarvis", LEGACY_JSON, supersede_key="cot:me:jarvis")
    outbox.enqueue("durable-1", "jarvis", LEGACY_JSON)
    assert outbox.pending_count == 2

    outbox.enqueue("beacon-2", "jarvis", LEGACY_JSON, supersede_key="cot:me:jarvis")

    assert outbox.pending_count == 2
    assert outbox.get("beacon-1") is None
    assert outbox.get("beacon-2") is not None


def test_outbox_bound_disabled_with_nonpositive_max_pending(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", max_pending=0)
    for i in range(10):
        outbox.enqueue(f"e{i}", "jarvis", LEGACY_JSON)
    assert outbox.pending_count == 10


# ---------------------------------------------------------------------------
# PersistentOutbox: paced sweep batches
# ---------------------------------------------------------------------------


class FailingRouter:
    """Legacy router stub: route() always fails, counting calls."""

    def __init__(self):
        self.calls = 0

    def route(self, envelope):
        self.calls += 1
        return DeliveryReport(envelope_id=envelope.envelope_id, delivered=False)


def _due_outbox(tmp_path, router, count, sweep_batch):
    """An outbox with *count* immediately-due legacy entries."""
    outbox = PersistentOutbox(
        outbox_dir=tmp_path / "outbox",
        router=router,
        base_backoff=0,  # next_retry_at == now, so entries are due immediately
        sweep_batch=sweep_batch,
    )
    for i in range(count):
        outbox.enqueue(f"e{i:02d}", "jarvis", LEGACY_JSON, error="down")
    return outbox


def test_retry_sweep_drains_in_bounded_batches(tmp_path):
    router = FailingRouter()
    outbox = _due_outbox(tmp_path, router, count=10, sweep_batch=3)

    results = outbox.retry_all()

    # Only the batch budget was attempted; the rest was deferred, not dropped.
    assert results["retried"] == 3
    assert results["deferred"] == 7
    assert router.calls == 3
    assert outbox.pending_count == 10


def test_retry_sweep_batch_cap_zero_drains_everything(tmp_path):
    router = FailingRouter()
    outbox = _due_outbox(tmp_path, router, count=10, sweep_batch=3)

    results = outbox.retry_all(max_batch=0)

    assert results["retried"] == 10
    assert results["deferred"] == 0
    assert router.calls == 10


def test_retry_sweep_skips_do_not_consume_batch_budget(tmp_path):
    router = FailingRouter()
    outbox = _due_outbox(tmp_path, router, count=2, sweep_batch=2)
    # An await_ack hold sorts first (name "a...") but must not eat the budget.
    outbox.enqueue("a-hold", "jarvis", LEGACY_JSON, await_ack=True)

    results = outbox.retry_all()

    assert results["skipped"] == 1
    assert results["retried"] == 2
    assert results["deferred"] == 0


# ---------------------------------------------------------------------------
# FileTransport / SyncthingTransport: outbox depth caps (oldest-eviction)
# ---------------------------------------------------------------------------


def _age_files(directory, suffix=".skc.json"):
    """Spread file mtimes so oldest-first ordering is deterministic."""
    now = time.time()
    files = sorted(directory.glob(f"*{suffix}"))
    for i, f in enumerate(files):
        os.utime(f, (now - 1000 + i, now - 1000 + i))


def test_file_transport_outbox_depth_cap_evicts_oldest(tmp_path):
    from skcomms.transports.file import FileTransport

    t = FileTransport(
        outbox_path=tmp_path / "out",
        inbox_path=tmp_path / "in",
        max_outbox_depth=5,
    )
    for i in range(8):
        result = t.send(json.dumps({"envelope_id": f"e{i:02d}"}).encode(), "jarvis")
        assert result.success is True
        _age_files(tmp_path / "out")

    names = sorted(f.name for f in (tmp_path / "out").glob("*.skc.json"))
    assert len(names) == 5
    # The three OLDEST envelopes were evicted; the newest five remain.
    assert names == [f"e{i:02d}.skc.json" for i in range(3, 8)]


def test_file_transport_depth_cap_disabled(tmp_path):
    from skcomms.transports.file import FileTransport

    t = FileTransport(
        outbox_path=tmp_path / "out",
        inbox_path=tmp_path / "in",
        max_outbox_depth=0,
    )
    for i in range(8):
        t.send(json.dumps({"envelope_id": f"e{i:02d}"}).encode(), "jarvis")

    assert len(list((tmp_path / "out").glob("*.skc.json"))) == 8


def test_file_transport_depth_cap_via_configure(tmp_path):
    from skcomms.transports.file import FileTransport

    t = FileTransport(outbox_path=tmp_path / "out", inbox_path=tmp_path / "in")
    t.configure({"max_outbox_depth": 2})
    for i in range(4):
        t.send(json.dumps({"envelope_id": f"e{i:02d}"}).encode(), "jarvis")
        _age_files(tmp_path / "out")

    assert len(list((tmp_path / "out").glob("*.skc.json"))) == 2


def test_syncthing_per_peer_outbox_depth_cap(tmp_path):
    from skcomms.transports.syncthing import SyncthingTransport

    t = SyncthingTransport(comms_root=tmp_path, max_outbox_depth=3)
    for i in range(5):
        result = t.send(json.dumps({"envelope_id": f"e{i:02d}"}).encode(), "jarvis")
        assert result.success is True
        _age_files(tmp_path / "outbox" / "jarvis")
    t.send(json.dumps({"envelope_id": "a-solo"}).encode(), "ava")

    jarvis_names = sorted(
        f.name for f in (tmp_path / "outbox" / "jarvis").glob("*.skc.json")
    )
    assert len(jarvis_names) == 3
    assert jarvis_names == [f"e{i:02d}.skc.json" for i in range(2, 5)]
    # The cap is PER PEER: another peer's queue is untouched.
    assert len(list((tmp_path / "outbox" / "ava").glob("*.skc.json"))) == 1


# ---------------------------------------------------------------------------
# Router: outbound send throttling
# ---------------------------------------------------------------------------


def _throttling_router(transport, capacity=3.0, refill=0.0):
    limiter = RateLimiter(
        default_config=RateLimitConfig(
            transport_capacity=capacity,
            transport_refill=refill,
            peer_capacity=capacity,
            peer_refill=refill,
        )
    )
    return Router(transports=[transport], rate_limiter=limiter)


def test_router_burst_is_throttled_not_flooded():
    t = RecordingTransport()
    router = _throttling_router(t, capacity=3.0, refill=0.0)

    reports = [router.route(_envelope()) for _ in range(10)]

    # Exactly the burst budget hit the wire; the flood was cut off locally.
    assert len(t.sent) == 3
    assert [r.delivered for r in reports[:3]] == [True, True, True]
    for r in reports[3:]:
        assert r.delivered is False
        assert r.attempts, "throttled attempt must be reported, not silent"
        assert r.attempts[0].error.startswith("throttled:")


def test_throttled_sends_never_arm_the_cooldown():
    t = RecordingTransport()
    router = _throttling_router(t, capacity=1.0, refill=0.0)

    router.route(_envelope())  # consumes the only token
    for _ in range(5):
        router.route(_envelope())  # all throttled

    # Local pacing is not transport failure: no cooldown, no failure counts.
    assert router._transport_failures == {}
    stats = router.failure_stats()[t.name]
    assert stats["throttled"] == 5
    assert stats["failures"] == 0


def test_throttle_refill_paces_instead_of_dropping():
    t = RecordingTransport()
    router = _throttling_router(t, capacity=1.0, refill=50.0)

    first = router.route(_envelope())
    second = router.route(_envelope())  # immediate: throttled
    time.sleep(0.05)  # ~2.5 tokens refill
    third = router.route(_envelope())  # paced retry: allowed

    assert first.delivered is True
    assert second.delivered is False
    assert second.attempts[0].error.startswith("throttled:")
    assert third.delivered is True
    assert len(t.sent) == 2


def test_router_without_limiter_keeps_historical_behavior():
    t = RecordingTransport()
    router = Router(transports=[t])

    for _ in range(10):
        assert router.route(_envelope()).delivered is True
    assert len(t.sent) == 10


def test_route_bytes_is_throttled_too():
    """The federation/backlog-flush path passes through the same limiter."""
    t = RecordingTransport()
    router = _throttling_router(t, capacity=2.0, refill=0.0)

    reports = [
        router.route_bytes(b'{"envelope": {}}', "jarvis@op.realm", envelope_id=f"e{i}")
        for i in range(6)
    ]

    assert len(t.sent) == 2
    assert sum(1 for r in reports if r.delivered) == 2


# ---------------------------------------------------------------------------
# Config wiring
# ---------------------------------------------------------------------------


def test_config_defaults_bound_and_throttle():
    cfg = SKCommsConfig()
    assert cfg.outbox.max_pending == 5000
    assert cfg.outbox.sweep_batch == 50
    assert cfg.ratelimit.enabled is True
    assert cfg.ratelimit.transport_capacity > 0


def test_config_sections_parse_from_yaml(tmp_path):
    cfg_file = tmp_path / "config.yml"
    cfg_file.write_text(
        "skcomms:\n"
        "  outbox:\n"
        "    max_pending: 7\n"
        "    sweep_batch: 2\n"
        "  ratelimit:\n"
        "    enabled: false\n"
        "    transport_capacity: 5\n"
    )
    cfg = SKCommsConfig.from_yaml(cfg_file)
    assert cfg.outbox.max_pending == 7
    assert cfg.outbox.sweep_batch == 2
    assert cfg.ratelimit.enabled is False
    assert cfg.ratelimit.transport_capacity == 5


def test_build_outbound_limiter_respects_enabled_flag():
    from skcomms.core import build_outbound_limiter

    cfg = SKCommsConfig()
    assert isinstance(build_outbound_limiter(cfg), RateLimiter)

    cfg.ratelimit.enabled = False
    assert build_outbound_limiter(cfg) is None


def test_skcomms_wires_bounds_into_outbox_and_router():
    from skcomms.core import SKComms

    cfg = SKCommsConfig(ack=False)
    cfg.outbox.max_pending = 11
    cfg.outbox.sweep_batch = 4
    comm = SKComms(config=cfg)

    assert comm._outbox._max_pending == 11
    assert comm._outbox._sweep_batch == 4
    assert comm._router._rate_limiter is not None


# ---------------------------------------------------------------------------
# Core + API: explicit backpressure to local callers
# ---------------------------------------------------------------------------


@pytest.fixture
def full_outbox_comm(tmp_path, monkeypatch):
    """A keyless SKComms whose only rail fails and whose outbox holds 1 entry."""
    from skcomms.core import SKComms

    t = RecordingTransport(name="tailscale", succeed=False)
    comm = SKComms(config=SKCommsConfig(ack=False), router=Router(transports=[t]))
    monkeypatch.setattr(comm, "_signing_crypto", lambda: None)
    comm._outbox = PersistentOutbox(
        outbox_dir=tmp_path / "outbox", router=comm._router, max_pending=1
    )
    return comm


def test_core_send_surfaces_outbox_full_backpressure(full_outbox_comm, monkeypatch):
    from skcomms import integration as integration_mod

    alerts: list[str] = []
    monkeypatch.setattr(
        integration_mod,
        "alert",
        lambda event, payload, level="info": alerts.append(event) or True,
    )

    # First failed send occupies the single outbox slot.
    report = full_outbox_comm.send("jarvis", "first")
    assert report.delivered is False
    assert full_outbox_comm._outbox.pending_count == 1

    # Second failed send cannot be queued: explicit backpressure, loud alert.
    with pytest.raises(OutboxFullError):
        full_outbox_comm.send("jarvis", "second")
    assert "outbox_full" in alerts
    assert full_outbox_comm._outbox.pending_count == 1


def test_api_send_returns_429_when_outbox_full(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    import skcomms.api as api

    importlib.reload(api)

    class BackpressuredComm:
        identity = "test"

        def send(self, **kwargs):
            raise OutboxFullError("outbox pending queue is full (1 entries)")

    monkeypatch.setattr(api, "_skcomms", BackpressuredComm())

    # No context manager: the lifespan would rebuild the real SKComms and
    # clobber the stub (same pattern as test_api_health).
    client = TestClient(api.app)
    resp = client.post("/api/v1/send", json={"recipient": "jarvis", "message": "hi"})

    assert resp.status_code == 429
    assert "outbox full" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Observability: throttle counter surfaces in /metrics exposition
# ---------------------------------------------------------------------------


def test_metrics_exposition_includes_throttled_counter():
    from skcomms.observability import render_prometheus

    text = render_prometheus(
        outbox_depths={"file": 1},
        dead_letter_depth=0,
        failure_counters={"tailscale": {"failures": 0, "http_4xx": 0, "throttled": 7}},
    )
    assert 'skcomms_transport_throttled_total{transport="tailscale"} 7' in text
