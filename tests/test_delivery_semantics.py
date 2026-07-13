"""Honest delivery semantics (coord 66b51605).

A file/syncthing outbox write is a QUEUE hand-off, not confirmed receipt, so:

  * the transports report ``queued=True`` and ``DeliveryReport.queued_only``
    distinguishes a sneakernet queue from a confirmed delivery,
  * a queued-only send is held as a durable ``await_ack`` outbox entry until an
    ACK confirms receipt (then removed) or the ACK horizon lapses (then a
    ``delivery_failed`` alert fires and the entry is dead-lettered),
  * the outbox retry sweep leaves ``await_ack`` entries untouched.

The https-s2s body verification (a 2xx must carry ``{"ok": true}``) is covered
in ``test_http_s2s_transport.py``.
"""

from __future__ import annotations

import pytest

from skcomms import integration as integration_mod
from skcomms.core import SKComms
from skcomms.models import (
    MessageEnvelope,
    MessagePayload,
    MessageType,
    RoutingConfig,
    RoutingMode,
)
from skcomms.outbox import PersistentOutbox
from skcomms.router import Router
from skcomms.transport import (
    DeliveryReport,
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)


class QueueTransport(Transport):
    """A file-category rail that reports a queue hand-off (success + queued)."""

    def __init__(self, name="file", priority=2):
        self.name = name
        self.priority = priority
        self.category = TransportCategory.FILE_BASED
        self.sent: list[tuple[str, bytes]] = []
        self.inbound: list[bytes] = []

    def configure(self, c):
        pass

    def is_available(self):
        return True

    def send(self, envelope_bytes, recipient):
        self.sent.append((recipient, envelope_bytes))
        return SendResult(
            success=True,
            transport_name=self.name,
            envelope_id="",
            latency_ms=0.0,
            queued=True,
        )

    def receive(self):
        drained, self.inbound = self.inbound, []
        return drained

    def health_check(self):
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


# ---------------------------------------------------------------------------
# Transport-level + DeliveryReport semantics
# ---------------------------------------------------------------------------


def test_file_transport_reports_queued(tmp_path):
    from skcomms.transports.file import FileTransport

    t = FileTransport(outbox_path=tmp_path / "out", inbox_path=tmp_path / "in")
    result = t.send(b'{"envelope_id": "e1"}', "jarvis")
    assert result.success is True
    assert result.queued is True


def test_syncthing_transport_reports_queued(tmp_path):
    from skcomms.transports.syncthing import SyncthingTransport

    t = SyncthingTransport(outbox_path=tmp_path / "out", inbox_path=tmp_path / "in")
    result = t.send(b'{"envelope_id": "e1"}', "jarvis")
    assert result.success is True
    assert result.queued is True


def test_delivery_report_queued_only_vs_confirmed():
    queued = SendResult(success=True, transport_name="file", envelope_id="e1", queued=True)
    confirmed = SendResult(success=True, transport_name="https-s2s", envelope_id="e1")

    only_queued = DeliveryReport(envelope_id="e1", delivered=True, attempts=[queued])
    assert only_queued.queued_only is True
    assert only_queued.confirmed is False

    got_confirmed = DeliveryReport(
        envelope_id="e1", delivered=True, attempts=[queued, confirmed]
    )
    assert got_confirmed.queued_only is False
    assert got_confirmed.confirmed is True

    failed = DeliveryReport(envelope_id="e1", delivered=False, attempts=[])
    assert failed.queued_only is False


# ---------------------------------------------------------------------------
# Core: durable outbox hold for a queued-only send + ACK-tied cleanup
# ---------------------------------------------------------------------------


@pytest.fixture
def queued_comm(tmp_path, monkeypatch):
    """A keyless SKComms whose only rail is a queue (file) transport.

    Keyless forces the legacy MessageEnvelope path (fully wired to the
    AckTracker), and the queue rail makes every send queued-only. The outbox
    and ACK tracker are rooted in tmp so tests never touch real state.
    """
    from skcomms.ack import AckTracker

    t = QueueTransport()
    comm = SKComms(router=Router(transports=[t]))
    # Force the explicit legacy local-only path (no signing key).
    monkeypatch.setattr(comm, "_signing_crypto", lambda: None)
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=comm._router)
    comm._ack_tracker = AckTracker(acks_dir=tmp_path / "acks")
    return comm, t


def test_queued_only_send_holds_durable_outbox_entry(queued_comm):
    comm, _t = queued_comm

    report = comm.send("jarvis", "hello over the queue")

    assert report.delivered is True
    assert report.queued_only is True

    pending = comm._outbox.list_pending()
    assert len(pending) == 1
    assert pending[0].await_ack is True
    assert pending[0].recipient == "jarvis"
    # The ACK for this send is being tracked.
    assert comm._ack_tracker.pending_count == 1


def test_queued_only_broadcast_is_not_held(queued_comm):
    """A "*" broadcast is fire-and-forget: queued-only delivery must NOT hold a
    durable outbox entry (no peer can ever ACK it, so holding piles ~1/min
    presence pings up to the outbox cap and then re-floods on drain).
    """
    comm, _t = queued_comm

    report = comm.send("*", "presence ping")

    assert report.delivered is True
    assert report.queued_only is True
    # The broadcast left NO durable hold and is NOT awaiting an ACK.
    assert comm._outbox.list_pending() == []
    assert comm._ack_tracker.pending_count == 0


def test_ack_removes_the_held_outbox_entry(queued_comm):
    comm, t = queued_comm

    report = comm.send("jarvis", "confirm me")
    held = comm._outbox.list_pending()[0]
    assert comm._outbox.get(held.envelope_id) is not None

    # The recipient acknowledges: an ACK envelope referencing the original id,
    # sent by the recipient back to us. Delivered on the queue rail's inbound.
    ack = MessageEnvelope(
        sender="jarvis",
        recipient=comm._identity,
        payload=MessagePayload(content=held.envelope_id, content_type=MessageType.ACK),
        routing=RoutingConfig(mode=RoutingMode.FAILOVER, ack_requested=False),
    )
    t.inbound = [ack.to_bytes()]

    comm.receive()

    # ACK confirmed → the durable hold is gone.
    assert comm._outbox.get(held.envelope_id) is None
    assert comm._outbox.pending_count == 0


def test_no_ack_within_horizon_fires_delivery_failed(queued_comm, monkeypatch):
    comm, _t = queued_comm

    alerts: list[tuple[str, dict, str]] = []
    monkeypatch.setattr(
        integration_mod,
        "alert",
        lambda event, payload, level="info": alerts.append((event, payload, level)) or True,
    )
    # Zero ACK timeout so the tracked ACK is expired the instant it is created.
    comm._ack_tracker._default_timeout = 0

    report = comm.send("jarvis", "will never be acked")
    held = comm._outbox.list_pending()[0]
    assert report.queued_only is True

    timed_out = comm.sweep_ack_timeouts()

    assert len(timed_out) == 1
    events = [a[0] for a in alerts]
    assert "delivery_failed" in events
    df = next(a for a in alerts if a[0] == "delivery_failed")
    assert df[1]["recipient"] == "jarvis"
    assert df[2] == "warn"
    # The unconfirmed queued send is dead-lettered, not left pending.
    assert comm._outbox.get(held.envelope_id) is None
    assert comm._outbox.dead_count == 1


def test_confirmed_delivery_does_not_alert_on_sweep(queued_comm, monkeypatch):
    """A send whose held entry was already removed (ACK'd) never alerts."""
    comm, _t = queued_comm

    alerts: list[str] = []
    monkeypatch.setattr(
        integration_mod,
        "alert",
        lambda event, payload, level="info": alerts.append(event) or True,
    )
    comm._ack_tracker._default_timeout = 0

    comm.send("jarvis", "acked before the sweep")
    held = comm._outbox.list_pending()[0]
    # Simulate the ACK having arrived: hold removed.
    comm._outbox.remove(held.envelope_id)

    comm.sweep_ack_timeouts()

    assert "delivery_failed" not in alerts


# ---------------------------------------------------------------------------
# Outbox retry sweep leaves await_ack holds untouched
# ---------------------------------------------------------------------------


def test_retry_sweep_skips_await_ack_entries(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=None)
    outbox.enqueue(
        "held-1",
        "jarvis",
        '{"sender": "me", "recipient": "jarvis", "payload": {"content": "x"}}',
        error="queued on file; awaiting ACK",
        await_ack=True,
    )

    results = outbox.retry_all()

    # The hold is skipped (not retried, not delivered, not dead-lettered) and
    # remains in pending, awaiting its ACK.
    assert results["retried"] == 0
    assert results["skipped"] == 1
    assert outbox.get("held-1") is not None
