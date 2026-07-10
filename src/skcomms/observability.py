"""Outbox / dead-letter depth observability, alerting, and metrics exposition.

The failure mode that froze a fleet laptop was invisible: the sender outbox
grew to 140k files while ``FileTransport.health_check`` faithfully reported
``pending_outbox`` and nothing thresholded, alerted, or graphed it. This
module closes that gap without touching any send path or queue mechanics:

  * :func:`collect_outbox_depths` / :func:`total_outbox_depth` read the
    ``pending_outbox`` each transport already reports from ``health_check``,
  * :class:`DepthMonitor` thresholds those depths plus the dead-letter queue
    depth and fires an sk-alert (via :mod:`skcomms.integration`) when either
    crosses its threshold, edge-triggered so it never storms the bus,
  * :func:`depth_monitor_loop` runs the monitor periodically in the daemon
    (a sibling of :mod:`skcomms.housekeeping`'s loop),
  * :func:`render_prometheus` renders a dependency-free Prometheus text
    exposition of outbox depth, dead-letter depth, and per-rail failure
    counters for a ``GET /metrics`` endpoint.

Thresholds come from :class:`skcomms.config.ObservabilityConfig` (config.yml
``observability:`` block). This module is strictly read-only on transports and
queues: it counts, thresholds, exposes, and alerts, nothing more.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Iterable, Optional

from . import integration
from .config import ObservabilityConfig

logger = logging.getLogger("skcomms.observability")

#: Type of the alert callback: (event, payload, level) -> bool. Matches
#: :func:`skcomms.integration.alert` so it can be dependency-injected in tests.
AlertFn = Callable[..., bool]


def collect_outbox_depths(transports: Iterable[object]) -> dict[str, int]:
    """Return per-transport pending outbox depth from each ``health_check``.

    Duck-typed: every transport whose ``health_check().details`` carries a
    ``pending_outbox`` key contributes its count; rails without one (realtime
    push rails, etc.) are skipped. Uses the SAME source GET /api/v1/status
    already reports, so the numbers never disagree. A transport whose
    health_check raises is skipped (logged at debug) rather than aborting the
    sweep.

    Args:
        transports: Transport instances to inspect (e.g. ``router.transports``).

    Returns:
        ``{transport_name: pending_outbox_count}`` for reporting rails.
    """
    depths: dict[str, int] = {}
    for transport in transports:
        name = getattr(transport, "name", transport.__class__.__name__)
        health = getattr(transport, "health_check", None)
        if not callable(health):
            continue
        try:
            details = getattr(health(), "details", None) or {}
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("health_check failed for transport %s: %s", name, exc)
            continue
        if "pending_outbox" in details:
            try:
                depths[name] = int(details["pending_outbox"])
            except (TypeError, ValueError):
                continue
    return depths


def total_outbox_depth(transports: Iterable[object]) -> int:
    """Return the summed pending outbox depth across all reporting transports."""
    return sum(collect_outbox_depths(transports).values())


class DepthMonitor:
    """Thresholds outbox + dead-letter depth and fires sk-alert on crossing.

    Edge-triggered by design: the outbox alert fires once when the summed
    depth first reaches its threshold and re-arms only after it drops back
    below, so a persistently deep outbox does not re-alert every pass. The
    dead-letter alert fires when the count has both grown since the previous
    pass and sits at or above its threshold, so a single new permanently
    failed message surfaces without repeating for a static backlog.

    The monitor is purely observational: it never mutates transports, queues,
    or send state. It only reads depths and calls the alert function.

    Args:
        config: Threshold + level settings; defaults to
            :class:`~skcomms.config.ObservabilityConfig`.
        alert: Alert sink ``(event, payload, level) -> bool``; defaults to
            :func:`skcomms.integration.alert`. Injectable for tests.
    """

    def __init__(
        self,
        config: Optional[ObservabilityConfig] = None,
        alert: Optional[AlertFn] = None,
    ) -> None:
        self._cfg = config or ObservabilityConfig()
        self._alert = alert or integration.alert
        # Edge-trigger state.
        self._outbox_alerting = False
        self._last_dead = 0

    def check(self, transports: Iterable[object], dead_count: int) -> dict:
        """Run one depth check, firing alerts on threshold crossings.

        Args:
            transports: Transports to sum outbox depth over.
            dead_count: Current dead-letter queue depth (e.g.
                ``PersistentOutbox.dead_count()``).

        Returns:
            dict: ``{"outbox_depth": int, "dead_letter_depth": int,
            "outbox_by_transport": {...}, "alerts_fired": [event, ...]}``.
        """
        by_transport = collect_outbox_depths(transports)
        outbox_depth = sum(by_transport.values())
        fired: list[str] = []

        outbox_threshold = self._cfg.outbox_depth_threshold
        if outbox_threshold > 0 and outbox_depth >= outbox_threshold:
            if not self._outbox_alerting:
                self._alert(
                    "outbox_depth_high",
                    {
                        "outbox_depth": outbox_depth,
                        "threshold": outbox_threshold,
                        "by_transport": by_transport,
                    },
                    level=self._cfg.alert_level,
                )
                fired.append("outbox_depth_high")
                logger.warning(
                    "Outbox depth %d crossed threshold %d (by transport: %s)",
                    outbox_depth,
                    outbox_threshold,
                    by_transport,
                )
            self._outbox_alerting = True
        elif outbox_threshold > 0 and outbox_depth < outbox_threshold:
            # Re-arm once it recovers so a future crossing alerts again.
            self._outbox_alerting = False

        dead_threshold = self._cfg.dead_letter_threshold
        if (
            dead_threshold > 0
            and dead_count >= dead_threshold
            and dead_count > self._last_dead
        ):
            self._alert(
                "dead_letter_growth",
                {
                    "dead_letter_depth": dead_count,
                    "previous": self._last_dead,
                    "threshold": dead_threshold,
                },
                level=self._cfg.alert_level,
            )
            fired.append("dead_letter_growth")
            logger.warning(
                "Dead-letter depth grew %d -> %d (threshold %d)",
                self._last_dead,
                dead_count,
                dead_threshold,
            )
        self._last_dead = dead_count

        return {
            "outbox_depth": outbox_depth,
            "dead_letter_depth": dead_count,
            "outbox_by_transport": by_transport,
            "alerts_fired": fired,
        }


async def depth_monitor_loop(
    get_transports: Callable[[], Iterable[object]],
    get_dead_count: Callable[[], int],
    config: Optional[ObservabilityConfig] = None,
    monitor: Optional[DepthMonitor] = None,
) -> None:
    """Run :meth:`DepthMonitor.check` forever at the configured interval.

    Sibling of :func:`skcomms.housekeeping.housekeeping_loop`: intended to be
    started as an ``asyncio`` task by the daemon lifespan and cancelled on
    shutdown. Sleeps FIRST so a short-lived process never alerts on startup.
    Each check runs in a worker thread so filesystem globbing never blocks the
    event loop. Errors are logged and the loop keeps going; only cancellation
    stops it.

    Args:
        get_transports: Zero-arg callable returning the current transports
            (late-bound so the loop always sees live router state).
        get_dead_count: Zero-arg callable returning the current dead-letter
            queue depth.
        config: Threshold + interval settings; defaults to
            :class:`~skcomms.config.ObservabilityConfig`.
        monitor: Pre-built monitor (keeps edge-trigger state across passes);
            one is created from *config* when omitted.
    """
    cfg = config or ObservabilityConfig()
    mon = monitor or DepthMonitor(cfg)

    def _one_pass() -> dict:
        transports = list(get_transports() or [])
        try:
            dead = int(get_dead_count() or 0)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("dead-letter count unavailable: %s", exc)
            dead = 0
        return mon.check(transports, dead)

    while True:
        await asyncio.sleep(cfg.interval_s)
        try:
            await asyncio.to_thread(_one_pass)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Depth-monitor pass failed; will retry next interval")


# ---------------------------------------------------------------------------
# Prometheus text exposition (dependency-free)
# ---------------------------------------------------------------------------

#: Content type for the Prometheus text exposition format (version 0.0.4).
PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_STATUS_UP = {"available": 1, "degraded": 1, "unavailable": 0}


def _escape_label(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_prometheus(
    *,
    outbox_depths: dict[str, int],
    dead_letter_depth: int,
    failure_counters: dict[str, dict],
    transport_health: Optional[dict[str, dict]] = None,
) -> str:
    """Render a Prometheus text exposition of skcomms observability metrics.

    Plain-text exposition format (no client library, no new dependency). All
    inputs are already-collected snapshots so this function is pure and easy
    to unit-test.

    Args:
        outbox_depths: ``{transport: pending_outbox}`` (see
            :func:`collect_outbox_depths`).
        dead_letter_depth: Current dead-letter queue depth.
        failure_counters: ``{transport: {"failures": int, "http_4xx": int}}``
            (see :meth:`skcomms.router.Router.failure_stats`).
        transport_health: Optional ``{transport: {"status": str, ...}}`` from
            ``router.health_report()``, used to emit an ``up`` gauge per rail.

    Returns:
        The exposition text, ending with a trailing newline.
    """
    lines: list[str] = []

    lines.append("# HELP skcomms_outbox_pending Pending envelopes in a transport outbox.")
    lines.append("# TYPE skcomms_outbox_pending gauge")
    for name in sorted(outbox_depths):
        label = _escape_label(name)
        lines.append(f'skcomms_outbox_pending{{transport="{label}"}} {int(outbox_depths[name])}')

    lines.append("# HELP skcomms_outbox_depth_total Total pending envelopes across all rails.")
    lines.append("# TYPE skcomms_outbox_depth_total gauge")
    lines.append(f"skcomms_outbox_depth_total {sum(int(v) for v in outbox_depths.values())}")

    lines.append("# HELP skcomms_dead_letter_depth Messages in the dead-letter queue.")
    lines.append("# TYPE skcomms_dead_letter_depth gauge")
    lines.append(f"skcomms_dead_letter_depth {int(dead_letter_depth)}")

    lines.append(
        "# HELP skcomms_transport_failures_total Cumulative failed send attempts per rail."
    )
    lines.append("# TYPE skcomms_transport_failures_total counter")
    for name in sorted(failure_counters):
        label = _escape_label(name)
        failures = int(failure_counters[name].get("failures", 0))
        lines.append(f'skcomms_transport_failures_total{{transport="{label}"}} {failures}')

    lines.append(
        "# HELP skcomms_transport_http_4xx_total Cumulative 4xx send rejections per rail."
    )
    lines.append("# TYPE skcomms_transport_http_4xx_total counter")
    for name in sorted(failure_counters):
        label = _escape_label(name)
        http_4xx = int(failure_counters[name].get("http_4xx", 0))
        lines.append(f'skcomms_transport_http_4xx_total{{transport="{label}"}} {http_4xx}')

    if transport_health:
        lines.append("# HELP skcomms_transport_up Whether a rail is currently reachable (1/0).")
        lines.append("# TYPE skcomms_transport_up gauge")
        for name in sorted(transport_health):
            label = _escape_label(name)
            status = str(transport_health[name].get("status", "")).lower()
            up = _STATUS_UP.get(status, 0)
            lines.append(f'skcomms_transport_up{{transport="{label}"}} {up}')

    return "\n".join(lines) + "\n"
