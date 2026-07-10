"""Outbox / dead-letter depth observability, alerting, and metrics (coord c547a1b2).

The failure mode that froze a fleet laptop was invisible: the sender outbox
grew to 140k files while health_check reported the depth and nothing
thresholded, alerted, or graphed it. These tests pin the fix:

  * DepthMonitor fires an sk-alert when outbox depth crosses its threshold,
  * DepthMonitor fires an sk-alert when the dead-letter count grows,
  * per-transport failure counters (incl. 4xx per rail) reach the router's
    failure_stats() and GET /api/v1/status,
  * SyncthingTransport.health_check reports pending_outbox, not just inbox,
  * render_prometheus emits a valid text exposition,
  * the daemon lifespan starts (and cancels) the depth-monitor loop.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from skcomms.config import HousekeepingConfig, ObservabilityConfig, SKCommsConfig
from skcomms.observability import (
    DepthMonitor,
    collect_outbox_depths,
    depth_monitor_loop,
    render_prometheus,
    total_outbox_depth,
)
from skcomms.transports.file import ENVELOPE_SUFFIX, FileTransport
from skcomms.transports.syncthing import SyncthingTransport


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeHealth:
    def __init__(self, details):
        self.details = details


class _FakeTransport:
    """Duck-typed transport reporting a fixed pending_outbox depth."""

    def __init__(self, name, pending_outbox=None):
        self.name = name
        self._details = {}
        if pending_outbox is not None:
            self._details["pending_outbox"] = pending_outbox

    def health_check(self):
        return _FakeHealth(dict(self._details))


class _RecordingAlert:
    """Captures alert() calls; mimics integration.alert's signature."""

    def __init__(self):
        self.calls = []

    def __call__(self, event, payload, level="info"):
        self.calls.append({"event": event, "payload": payload, "level": level})
        return True

    def events(self):
        return [c["event"] for c in self.calls]


# ---------------------------------------------------------------------------
# collect_outbox_depths / total_outbox_depth
# ---------------------------------------------------------------------------


class TestCollectOutboxDepths:
    def test_sums_reporting_transports_and_skips_others(self):
        transports = [
            _FakeTransport("file", 3),
            _FakeTransport("syncthing", 5),
            _FakeTransport("nostr", None),  # no pending_outbox -> skipped
        ]
        assert collect_outbox_depths(transports) == {"file": 3, "syncthing": 5}
        assert total_outbox_depth(transports) == 8

    def test_health_check_raising_is_skipped(self):
        class _Boom:
            name = "boom"

            def health_check(self):
                raise RuntimeError("nope")

        transports = [_Boom(), _FakeTransport("file", 2)]
        assert collect_outbox_depths(transports) == {"file": 2}


# ---------------------------------------------------------------------------
# DepthMonitor: outbox threshold (acceptance: crossing fires sk-alert)
# ---------------------------------------------------------------------------


class TestDepthMonitorOutbox:
    def test_crossing_threshold_fires_alert(self):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(outbox_depth_threshold=10, dead_letter_threshold=0)
        mon = DepthMonitor(cfg, alert=alert)

        result = mon.check([_FakeTransport("file", 12)], dead_count=0)

        assert "outbox_depth_high" in result["alerts_fired"]
        assert alert.events() == ["outbox_depth_high"]
        assert alert.calls[0]["level"] == "warn"
        assert alert.calls[0]["payload"]["outbox_depth"] == 12
        assert alert.calls[0]["payload"]["by_transport"] == {"file": 12}

    def test_below_threshold_is_quiet(self):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(outbox_depth_threshold=10, dead_letter_threshold=0)
        mon = DepthMonitor(cfg, alert=alert)

        mon.check([_FakeTransport("file", 3)], dead_count=0)
        assert alert.calls == []

    def test_edge_triggered_no_storm_until_recovery(self):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(outbox_depth_threshold=10, dead_letter_threshold=0)
        mon = DepthMonitor(cfg, alert=alert)

        mon.check([_FakeTransport("file", 20)], dead_count=0)  # fires
        mon.check([_FakeTransport("file", 25)], dead_count=0)  # still high, quiet
        assert alert.events() == ["outbox_depth_high"]

        mon.check([_FakeTransport("file", 1)], dead_count=0)  # recover -> re-arm
        mon.check([_FakeTransport("file", 30)], dead_count=0)  # cross again -> fires
        assert alert.events() == ["outbox_depth_high", "outbox_depth_high"]

    def test_zero_threshold_disables_check(self):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(outbox_depth_threshold=0, dead_letter_threshold=0)
        mon = DepthMonitor(cfg, alert=alert)
        mon.check([_FakeTransport("file", 9999)], dead_count=0)
        assert alert.calls == []

    def test_default_sink_routes_through_integration_alert(self, monkeypatch):
        """With no injected sink, the monitor fires the real integration.alert.

        Integration-level test with the integration mocked: proves the wire
        from a threshold crossing to the shared sk-alert bus, not just the
        injected-callback shortcut used elsewhere.
        """
        from skcomms import integration

        seen = []
        monkeypatch.setattr(
            integration,
            "alert",
            lambda event, payload, level="info": seen.append((event, level)) or True,
        )
        cfg = ObservabilityConfig(outbox_depth_threshold=1, dead_letter_threshold=0)
        mon = DepthMonitor(cfg)  # default sink

        mon.check([_FakeTransport("file", 4)], dead_count=0)
        assert seen == [("outbox_depth_high", "warn")]


# ---------------------------------------------------------------------------
# DepthMonitor: dead-letter growth (acceptance: growth fires sk-alert)
# ---------------------------------------------------------------------------


class TestDepthMonitorDeadLetter:
    def test_growth_fires_alert(self):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(outbox_depth_threshold=0, dead_letter_threshold=1)
        mon = DepthMonitor(cfg, alert=alert)

        result = mon.check([], dead_count=2)
        assert "dead_letter_growth" in result["alerts_fired"]
        assert alert.calls[0]["payload"]["dead_letter_depth"] == 2
        assert alert.calls[0]["payload"]["previous"] == 0

    def test_no_growth_is_quiet(self):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(outbox_depth_threshold=0, dead_letter_threshold=1)
        mon = DepthMonitor(cfg, alert=alert)

        mon.check([], dead_count=3)  # growth 0 -> 3 fires
        mon.check([], dead_count=3)  # static, quiet
        assert alert.events() == ["dead_letter_growth"]

        mon.check([], dead_count=5)  # grows again -> fires
        assert alert.events() == ["dead_letter_growth", "dead_letter_growth"]

    def test_below_threshold_quiet_even_on_growth(self):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(outbox_depth_threshold=0, dead_letter_threshold=5)
        mon = DepthMonitor(cfg, alert=alert)
        mon.check([], dead_count=2)  # grew but below threshold
        assert alert.calls == []


# ---------------------------------------------------------------------------
# Prometheus exposition
# ---------------------------------------------------------------------------


class TestRenderPrometheus:
    def test_emits_gauges_and_counters(self):
        text = render_prometheus(
            outbox_depths={"file": 3, "syncthing": 5},
            dead_letter_depth=2,
            failure_counters={
                "https-s2s": {"failures": 7, "http_4xx": 2},
                "file": {"failures": 1, "http_4xx": 0},
            },
            transport_health={
                "file": {"status": "available"},
                "nostr": {"status": "unavailable"},
            },
        )
        assert 'skcomms_outbox_pending{transport="file"} 3' in text
        assert 'skcomms_outbox_pending{transport="syncthing"} 5' in text
        assert "skcomms_outbox_depth_total 8" in text
        assert "skcomms_dead_letter_depth 2" in text
        assert 'skcomms_transport_failures_total{transport="https-s2s"} 7' in text
        assert 'skcomms_transport_http_4xx_total{transport="https-s2s"} 2' in text
        assert 'skcomms_transport_up{transport="file"} 1' in text
        assert 'skcomms_transport_up{transport="nostr"} 0' in text
        # Every HELP has a matching TYPE and the body ends in a newline.
        assert text.count("# HELP") == text.count("# TYPE")
        assert text.endswith("\n")

    def test_escapes_label_values(self):
        text = render_prometheus(
            outbox_depths={'we"ird': 1},
            dead_letter_depth=0,
            failure_counters={},
        )
        assert 'transport="we\\"ird"' in text


# ---------------------------------------------------------------------------
# SyncthingTransport.health_check reports pending_outbox
# ---------------------------------------------------------------------------


class TestSyncthingOutboxHealth:
    def test_health_check_counts_outbox_depth(self, tmp_path):
        transport = SyncthingTransport(comms_root=tmp_path / "comms")
        # Send two envelopes to a peer -> two files in outbox/<peer>/.
        transport.send(json.dumps({"envelope_id": "a"}).encode(), "peer1")
        transport.send(json.dumps({"envelope_id": "b"}).encode(), "peer1")

        health = transport.health_check()
        assert health.details["pending_outbox"] == 2
        assert "pending_inbox" in health.details


# ---------------------------------------------------------------------------
# Router failure counters (acceptance: 4xx per rail in status)
# ---------------------------------------------------------------------------


class TestRouterFailureCounters:
    def _envelope(self):
        from skcomms.models import MessageEnvelope, MessagePayload

        return MessageEnvelope(
            sender="me",
            recipient="peer",
            payload=MessagePayload(content="hi"),
        )

    def test_counts_failures_and_4xx_subset(self):
        from skcomms.router import Router
        from skcomms.transport import SendResult

        class _RejectingTransport:
            """Duck-typed rail that always 422s (no ABC to satisfy)."""

            name = "https-s2s"

            def send(self, envelope_bytes, recipient):
                return SendResult(
                    success=False,
                    transport_name=self.name,
                    envelope_id="x",
                    error="perm: HTTP 422 Unprocessable Entity",
                )

        router = Router(transports=[])
        rail = _RejectingTransport()
        router._try_send(rail, b"{}", "peer")
        router._try_send(rail, b"{}", "peer")

        stats = router.failure_stats()
        assert stats["https-s2s"]["failures"] == 2
        assert stats["https-s2s"]["http_4xx"] == 2
        assert "422" in stats["https-s2s"]["last_error"]

    def test_non_4xx_failure_not_counted_as_4xx(self):
        from skcomms.router import Router

        router = Router(transports=[])
        router._count_failure("nostr", "retry: relay timeout")
        stats = router.failure_stats()
        assert stats["nostr"]["failures"] == 1
        assert stats["nostr"]["http_4xx"] == 0

    def test_gate_refusal_counts_as_4xx(self):
        from skcomms.router import Router

        router = Router(transports=[])
        router._count_failure(
            "https-s2s",
            "perm: refusing non-SignedEnvelope payload on https-s2s "
            "(classified 'plain'); the inbox gate would 422 it",
        )
        stats = router.failure_stats()
        assert stats["https-s2s"]["http_4xx"] == 1

    def test_failure_counters_surface_in_core_status(self):
        """Acceptance: per-rail failure + 4xx counters appear in status()."""
        from skcomms.core import SKComms
        from skcomms.router import Router

        router = Router(transports=[])
        router._count_failure("https-s2s", "perm: HTTP 422 nope")
        router._count_failure("nostr", "retry: relay timeout")

        comm = SKComms(router=router, crypto=None)
        status = comm.status()

        assert "transport_failures" in status
        tf = status["transport_failures"]
        assert tf["https-s2s"]["failures"] == 1
        assert tf["https-s2s"]["http_4xx"] == 1
        assert tf["nostr"]["failures"] == 1
        assert tf["nostr"]["http_4xx"] == 0


# ---------------------------------------------------------------------------
# depth_monitor_loop + daemon lifespan wiring
# ---------------------------------------------------------------------------


class TestDepthMonitorLoop:
    async def test_loop_checks_periodically(self, monkeypatch):
        alert = _RecordingAlert()
        cfg = ObservabilityConfig(
            interval_s=0.01, outbox_depth_threshold=1, dead_letter_threshold=0
        )
        transport = _FakeTransport("file", 5)
        mon = DepthMonitor(cfg, alert=alert)

        task = asyncio.create_task(
            depth_monitor_loop(lambda: [transport], lambda: 0, cfg, monitor=mon)
        )
        try:
            for _ in range(200):
                await asyncio.sleep(0.01)
                if alert.calls:
                    break
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert alert.events() == ["outbox_depth_high"]


class TestObservabilityConfig:
    def test_sane_defaults(self):
        cfg = ObservabilityConfig()
        assert cfg.enabled is True
        assert cfg.interval_s == 300.0
        assert cfg.outbox_depth_threshold == 1000
        assert cfg.dead_letter_threshold == 1
        assert cfg.alert_level == "warn"

    def test_loaded_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "config.yml"
        cfg_file.write_text(
            "skcomms:\n"
            "  observability:\n"
            "    enabled: false\n"
            "    interval_s: 30\n"
            "    outbox_depth_threshold: 50\n"
            "    dead_letter_threshold: 3\n"
            "    alert_level: error\n"
        )
        obs = SKCommsConfig.from_yaml(cfg_file).observability
        assert obs.enabled is False
        assert obs.interval_s == 30.0
        assert obs.outbox_depth_threshold == 50
        assert obs.dead_letter_threshold == 3
        assert obs.alert_level == "error"

    def test_absent_block_uses_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.yml"
        cfg_file.write_text("skcomms:\n  version: '1.0.0'\n")
        assert SKCommsConfig.from_yaml(cfg_file).observability == ObservabilityConfig()


class TestMetricsEndpoint:
    async def test_metrics_endpoint_renders_prometheus(self, monkeypatch):
        import skcomms.api as api

        class _Router:
            transports = [_FakeTransport("file", 4)]

            def failure_stats(self):
                return {"https-s2s": {"failures": 2, "http_4xx": 1}}

            def health_report(self):
                return {"file": {"status": "available"}}

        class _Outbox:
            def dead_count(self):
                return 3

        class _Comm:
            router = _Router()
            _outbox = _Outbox()

        monkeypatch.setattr(api, "get_skcomms", lambda: _Comm())

        resp = await api.get_metrics()
        body = resp.body.decode()
        assert "text/plain" in resp.media_type
        assert 'skcomms_outbox_pending{transport="file"} 4' in body
        assert "skcomms_dead_letter_depth 3" in body
        assert 'skcomms_transport_http_4xx_total{transport="https-s2s"} 1' in body


class TestLifespanDepthMonitorWiring:
    class _StubOutbox:
        def dead_count(self):
            return 0

    class _StubSKComms:
        identity = "test-agent"

        def __init__(self, transports, obs_cfg):
            class _Router:
                pass

            self.router = _Router()
            self.router.transports = transports
            self._outbox = TestLifespanDepthMonitorWiring._StubOutbox()
            self._config = SKCommsConfig(
                housekeeping=HousekeepingConfig(enabled=False),
                observability=obs_cfg,
            )

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        import skcomms.api as api

        monkeypatch.setattr(api, "SignalingBroker", lambda *a, **k: object())
        monkeypatch.setattr(api, "CapAuthValidator", lambda *a, **k: object())
        monkeypatch.setattr(
            "skcomms.config.load_adapters_block", lambda *a, **k: {"adapters": {}}
        )
        yield

    async def test_lifespan_starts_and_cancels_depth_monitor(self, monkeypatch):
        import skcomms.api as api

        transport = _FakeTransport("file", 0)
        stub = self._StubSKComms([transport], ObservabilityConfig(interval_s=0.01))
        monkeypatch.setattr(api.SKComms, "from_config", classmethod(lambda cls: stub))

        async with api.lifespan(api.app):
            assert api._depth_monitor_task is not None
            await asyncio.sleep(0.05)

        assert api._depth_monitor_task is None

    async def test_lifespan_respects_observability_disabled(self, monkeypatch):
        import skcomms.api as api

        transport = _FakeTransport("file", 0)
        stub = self._StubSKComms(
            [transport], ObservabilityConfig(enabled=False, interval_s=0.01)
        )
        monkeypatch.setattr(api.SKComms, "from_config", classmethod(lambda cls: stub))

        async with api.lifespan(api.app):
            assert api._depth_monitor_task is None
            await asyncio.sleep(0.02)
