"""
SKComm transport metrics — per-transport delivery stats and latency tracking.

Tracks success/failure counts, average latency, error history,
and uptime per transport. Persisted as JSON at ~/.skcomm/metrics.json
so stats survive restarts.

Usage:
    from skcomm.metrics import MetricsCollector
    mc = MetricsCollector()
    mc.record_send("syncthing", success=True, latency_ms=12.5)
    mc.record_send("nostr", success=False, error="relay timeout")
    print(mc.summary())
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .config import SKCOMM_HOME

logger = logging.getLogger("skcomm.metrics")

METRICS_FILE = "metrics.json"
MAX_ERRORS = 20


class TransportStats(BaseModel):
    """Delivery statistics for a single transport.

    Attributes:
        transport: Transport name.
        sends_ok: Successful delivery count.
        sends_fail: Failed delivery count.
        receives: Messages received count.
        total_latency_ms: Cumulative send latency in milliseconds.
        min_latency_ms: Fastest successful send.
        max_latency_ms: Slowest successful send.
        last_send: Timestamp of the last send attempt.
        last_receive: Timestamp of the last receive.
        last_error: Most recent error message.
        recent_errors: Last N error messages with timestamps.
        first_seen: When this transport was first used.
    """

    transport: str
    sends_ok: int = 0
    sends_fail: int = 0
    receives: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    last_send: Optional[datetime] = None
    last_receive: Optional[datetime] = None
    last_error: Optional[str] = None
    recent_errors: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_sends(self) -> int:
        """Total send attempts (success + failure)."""
        return self.sends_ok + self.sends_fail

    @property
    def success_rate(self) -> float:
        """Delivery success rate as a percentage (0-100)."""
        if self.total_sends == 0:
            return 0.0
        return (self.sends_ok / self.total_sends) * 100

    @property
    def avg_latency_ms(self) -> float:
        """Average send latency in milliseconds."""
        if self.sends_ok == 0:
            return 0.0
        return self.total_latency_ms / self.sends_ok


class MetricsCollector:
    """Collects and persists per-transport delivery metrics.

    Stats are kept in memory and flushed to a JSON file on
    each write operation. Loads existing stats from disk on init.

    Args:
        metrics_path: Path to the metrics JSON file.
    """

    def __init__(self, metrics_path: Optional[Path] = None):
        self._path = metrics_path or Path(SKCOMM_HOME).expanduser() / METRICS_FILE
        self._stats: dict[str, TransportStats] = {}
        self._load()

    @property
    def metrics_path(self) -> Path:
        """Path to the metrics JSON file."""
        return self._path

    def record_send(
        self,
        transport: str,
        success: bool,
        latency_ms: float = 0.0,
        error: Optional[str] = None,
    ) -> None:
        """Record a send attempt for a transport.

        Args:
            transport: Transport name.
            success: Whether the delivery succeeded.
            latency_ms: Send latency in milliseconds.
            error: Error message if the send failed.
        """
        stats = self._get_or_create(transport)
        now = datetime.now(timezone.utc)
        stats.last_send = now

        if success:
            stats.sends_ok += 1
            stats.total_latency_ms += latency_ms
            if stats.min_latency_ms is None or latency_ms < stats.min_latency_ms:
                stats.min_latency_ms = latency_ms
            if stats.max_latency_ms is None or latency_ms > stats.max_latency_ms:
                stats.max_latency_ms = latency_ms
        else:
            stats.sends_fail += 1
            stats.last_error = error
            if error:
                ts = now.strftime("%H:%M:%S")
                stats.recent_errors.append(f"[{ts}] {error}")
                if len(stats.recent_errors) > MAX_ERRORS:
                    stats.recent_errors = stats.recent_errors[-MAX_ERRORS:]

        self._save()

    def record_receive(self, transport: str, count: int = 1) -> None:
        """Record messages received from a transport.

        Args:
            transport: Transport name.
            count: Number of messages received.
        """
        stats = self._get_or_create(transport)
        stats.receives += count
        stats.last_receive = datetime.now(timezone.utc)
        self._save()

    def get(self, transport: str) -> Optional[TransportStats]:
        """Get stats for a specific transport.

        Args:
            transport: Transport name.

        Returns:
            TransportStats or None if no data exists.
        """
        return self._stats.get(transport)

    def all_stats(self) -> list[TransportStats]:
        """Get stats for all transports, sorted by name.

        Returns:
            List of TransportStats.
        """
        return sorted(self._stats.values(), key=lambda s: s.transport)

    def summary(self) -> dict:
        """Generate an overall metrics summary.

        Returns:
            Dict with total counts and per-transport breakdown.
        """
        total_ok = sum(s.sends_ok for s in self._stats.values())
        total_fail = sum(s.sends_fail for s in self._stats.values())
        total_recv = sum(s.receives for s in self._stats.values())

        return {
            "total_sends_ok": total_ok,
            "total_sends_fail": total_fail,
            "total_receives": total_recv,
            "overall_success_rate": (
                f"{(total_ok / (total_ok + total_fail)) * 100:.1f}%"
                if (total_ok + total_fail) > 0
                else "N/A"
            ),
            "transports": {
                s.transport: {
                    "sends_ok": s.sends_ok,
                    "sends_fail": s.sends_fail,
                    "receives": s.receives,
                    "success_rate": f"{s.success_rate:.1f}%",
                    "avg_latency_ms": round(s.avg_latency_ms, 1),
                    "last_error": s.last_error,
                }
                for s in self.all_stats()
            },
        }

    def reset(self, transport: Optional[str] = None) -> None:
        """Reset metrics for a transport or all transports.

        Args:
            transport: Transport name to reset, or None for all.
        """
        if transport:
            self._stats.pop(transport, None)
        else:
            self._stats.clear()
        self._save()

    def _get_or_create(self, transport: str) -> TransportStats:
        """Get existing stats or create a new entry."""
        if transport not in self._stats:
            self._stats[transport] = TransportStats(transport=transport)
        return self._stats[transport]

    def _save(self) -> None:
        """Persist metrics to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            name: stats.model_dump(mode="json", exclude_none=True)
            for name, stats in self._stats.items()
        }
        tmp = self._path.parent / f".{self._path.name}.tmp"
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.rename(self._path)

    def _load(self) -> None:
        """Load metrics from disk if the file exists."""
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text())
            for name, data in raw.items():
                self._stats[name] = TransportStats.model_validate(data)
        except Exception as exc:
            logger.warning("Failed to load metrics: %s", exc)
