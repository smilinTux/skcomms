"""Persistent outbox -- queue failed messages and auto-retry.

When SKComms fails to deliver a message (all transports down, network
issues, relay rejection), the outbox saves it to disk and retries
with exponential backoff. Messages that exhaust retries move to a
dead letter queue for manual review.

The outbox is filesystem-based: one JSON file per queued message.
No database needed. Works offline. Survives daemon restarts.

Layout:
    ~/.skcomms/outbox/
    ├── pending/          # messages awaiting retry
    │   └── {id}.json
    └── dead/             # permanently failed messages
        └── {id}.json
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("skcomms.outbox")

DEFAULT_OUTBOX_DIR = "~/.skcomms/outbox"
DEFAULT_MAX_RETRIES = 10
DEFAULT_BASE_BACKOFF = 5


class OutboxEntry(BaseModel):
    """A queued message awaiting delivery.

    Attributes:
        envelope_id: The SKComms envelope ID.
        recipient: Target agent/peer.
        envelope_json: Full serialized envelope (JSON string).
        created_at: When the message was first queued.
        last_attempt: When the last delivery attempt was made.
        attempt_count: Number of delivery attempts so far.
        max_retries: Maximum attempts before moving to dead letter.
        next_retry_at: Earliest time for the next retry attempt.
        last_error: Error message from the most recent failure.
    """

    envelope_id: str
    recipient: str
    envelope_json: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_attempt: Optional[datetime] = None
    attempt_count: int = 0
    max_retries: int = DEFAULT_MAX_RETRIES
    next_retry_at: Optional[datetime] = None
    last_error: str = ""


class PersistentOutbox:
    """Filesystem-backed message queue with retry and dead letter.

    Failed sends are saved as JSON files in the pending directory.
    A retry sweep re-attempts delivery with exponential backoff.
    Messages that exhaust retries move to the dead letter directory.

    Args:
        outbox_dir: Root directory for the outbox.
        max_retries: Default max retries per message.
        base_backoff: Base backoff in seconds (doubled each retry).
        router: Optional SKComms Router for retry delivery.
    """

    def __init__(
        self,
        outbox_dir: str | Path = DEFAULT_OUTBOX_DIR,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_backoff: int = DEFAULT_BASE_BACKOFF,
        router: Optional[object] = None,
    ) -> None:
        self._root = Path(outbox_dir).expanduser()
        self._pending = self._root / "pending"
        self._dead = self._root / "dead"
        self._max_retries = max_retries
        self._base_backoff = base_backoff
        self._router = router

        self._pending.mkdir(parents=True, exist_ok=True)
        self._dead.mkdir(parents=True, exist_ok=True)

    def enqueue(
        self,
        envelope_id: str,
        recipient: str,
        envelope_json: str,
        error: str = "",
    ) -> OutboxEntry:
        """Add a failed message to the outbox queue.

        Args:
            envelope_id: The envelope's unique ID.
            recipient: Target agent/peer.
            envelope_json: Full serialized envelope JSON.
            error: Error from the failed delivery attempt.

        Returns:
            OutboxEntry: The queued entry.
        """
        entry = OutboxEntry(
            envelope_id=envelope_id,
            recipient=recipient,
            envelope_json=envelope_json,
            max_retries=self._max_retries,
            attempt_count=1,
            last_attempt=datetime.now(timezone.utc),
            last_error=error,
            next_retry_at=self._compute_next_retry(1),
        )

        self._write_entry(self._pending, entry)
        logger.info("Queued %s for retry (error: %s)", envelope_id[:8], error[:60])
        return entry

    def retry_all(self) -> dict[str, Any]:
        """Sweep the pending queue and retry all eligible messages.

        Only retries messages whose next_retry_at has passed.
        Successful deliveries are removed from the queue.
        Exhausted retries move to dead letter.

        Returns:
            dict: Summary with 'retried', 'delivered', 'dead_lettered', 'skipped'.
        """
        results = {"retried": 0, "delivered": 0, "dead_lettered": 0, "skipped": 0}
        now = datetime.now(timezone.utc)

        for entry_path in sorted(self._pending.glob("*.json")):
            try:
                entry = self._load_entry(entry_path)
            except (json.JSONDecodeError, ValueError, OSError) as exc:
                logger.warning("Skipping corrupt outbox entry %s: %s", entry_path.name, exc)
                continue

            if entry.next_retry_at and entry.next_retry_at > now:
                results["skipped"] += 1
                continue

            results["retried"] += 1
            delivered = self._attempt_delivery(entry)

            if delivered:
                entry_path.unlink(missing_ok=True)
                results["delivered"] += 1
                logger.info("Retry delivered %s", entry.envelope_id[:8])
            elif entry.attempt_count >= entry.max_retries:
                self._move_to_dead(entry, entry_path)
                results["dead_lettered"] += 1
                logger.warning(
                    "Dead-lettered %s after %d attempts",
                    entry.envelope_id[:8],
                    entry.attempt_count,
                )
            else:
                entry.attempt_count += 1
                entry.last_attempt = now
                entry.next_retry_at = self._compute_next_retry(entry.attempt_count)
                self._write_entry(self._pending, entry)

        return results

    def list_pending(self) -> list[OutboxEntry]:
        """List all messages in the pending queue.

        Returns:
            list[OutboxEntry]: Queued messages sorted by creation time.
        """
        return self._list_dir(self._pending)

    def list_dead(self) -> list[OutboxEntry]:
        """List all messages in the dead letter queue.

        Returns:
            list[OutboxEntry]: Dead-lettered messages sorted by creation time.
        """
        return self._list_dir(self._dead)

    def purge_pending(self) -> int:
        """Remove all messages from the pending queue.

        Returns:
            int: Number of messages purged.
        """
        return self._purge_dir(self._pending)

    def purge_dead(self) -> int:
        """Remove all messages from the dead letter queue.

        Returns:
            int: Number of messages purged.
        """
        return self._purge_dir(self._dead)

    def requeue_dead(self, envelope_id: Optional[str] = None) -> int:
        """Move dead-lettered messages back to pending for retry.

        Args:
            envelope_id: Specific message to requeue, or None for all.

        Returns:
            int: Number of messages requeued.
        """
        requeued = 0
        for entry_path in self._dead.glob("*.json"):
            try:
                entry = self._load_entry(entry_path)
            except (json.JSONDecodeError, ValueError, OSError) as exc:
                logger.warning(
                    "Skipping corrupt dead-letter entry %s: %s",
                    entry_path.name,
                    exc,
                )
                continue

            if envelope_id and entry.envelope_id != envelope_id:
                continue

            entry.attempt_count = 0
            entry.next_retry_at = None
            entry.last_error = "requeued from dead letter"
            self._write_entry(self._pending, entry)
            entry_path.unlink(missing_ok=True)
            requeued += 1

        return requeued

    @property
    def pending_count(self) -> int:
        """Number of messages in the pending queue."""
        return len(list(self._pending.glob("*.json")))

    @property
    def dead_count(self) -> int:
        """Number of messages in the dead letter queue."""
        return len(list(self._dead.glob("*.json")))

    def start(self, interval: int = 30) -> None:
        """Start the background retry worker thread.

        The worker calls retry_all() every ``interval`` seconds until
        stop() is called. The thread is a daemon so it exits with the process.

        Args:
            interval: Seconds between retry sweeps (default 30).
        """
        if getattr(self, "_retry_thread", None) and self._retry_thread.is_alive():
            return
        self._stop_event = threading.Event()
        self._retry_interval = interval
        self._retry_thread = threading.Thread(
            target=self._retry_loop, daemon=True, name="skcomms-outbox-retry"
        )
        self._retry_thread.start()
        logger.info("Outbox retry worker started (interval=%ds)", interval)

    def stop(self) -> None:
        """Stop the background retry worker thread."""
        stop_event = getattr(self, "_stop_event", None)
        if stop_event:
            stop_event.set()
        thread = getattr(self, "_retry_thread", None)
        if thread and thread.is_alive():
            thread.join(timeout=5)
        logger.info("Outbox retry worker stopped")

    def _retry_loop(self) -> None:
        """Background thread: sweep pending queue every retry_interval seconds."""
        while not self._stop_event.is_set():
            try:
                results = self.retry_all()
                if results["retried"] > 0:
                    logger.info(
                        "Outbox sweep: retried=%d delivered=%d dead=%d skipped=%d",
                        results["retried"],
                        results["delivered"],
                        results["dead_lettered"],
                        results["skipped"],
                    )
            except Exception as exc:
                logger.warning("Outbox retry sweep error: %s", exc)
            self._stop_event.wait(timeout=self._retry_interval)

    def _attempt_delivery(self, entry: OutboxEntry) -> bool:
        """Try to deliver a queued message via the router.

        Args:
            entry: The outbox entry to deliver.

        Returns:
            bool: True if delivery succeeded.
        """
        if self._router is None:
            return False

        try:
            from .models import MessageEnvelope

            envelope = MessageEnvelope.from_bytes(entry.envelope_json.encode("utf-8"))
            report = self._router.route(envelope)
            return getattr(report, "delivered", False)
        except (json.JSONDecodeError, ValueError) as exc:
            entry.last_error = str(exc)
            logger.warning(
                "Outbox delivery failed for %s (bad envelope): %s",
                entry.envelope_id[:8],
                exc,
            )
            return False
        except OSError as exc:
            entry.last_error = str(exc)
            logger.warning(
                "Outbox delivery failed for %s (I/O error): %s",
                entry.envelope_id[:8],
                exc,
            )
            return False
        except Exception as exc:
            entry.last_error = str(exc)
            logger.warning(
                "Outbox delivery failed for %s: %s",
                entry.envelope_id[:8],
                exc,
            )
            return False

    def _compute_next_retry(self, attempt: int) -> datetime:
        """Compute the next retry time with exponential backoff.

        Args:
            attempt: Current attempt number (1-based).

        Returns:
            datetime: Earliest time for the next retry.
        """
        delay = self._base_backoff * (2 ** (attempt - 1))
        delay = min(delay, 3600)
        return datetime.now(timezone.utc) + timedelta(seconds=delay)

    def _move_to_dead(self, entry: OutboxEntry, source_path: Path) -> None:
        """Move an entry from pending to dead letter.

        Args:
            entry: The entry to move.
            source_path: Current file path in pending.
        """
        self._write_entry(self._dead, entry)
        source_path.unlink(missing_ok=True)

    @staticmethod
    def _write_entry(directory: Path, entry: OutboxEntry) -> Path:
        """Write an outbox entry to disk.

        Args:
            directory: Target directory.
            entry: The entry to write.

        Returns:
            Path: The written file path.
        """
        filepath = directory / f"{entry.envelope_id}.json"
        filepath.write_text(entry.model_dump_json(indent=2), encoding="utf-8")
        return filepath

    @staticmethod
    def _load_entry(filepath: Path) -> OutboxEntry:
        """Load an outbox entry from disk.

        Args:
            filepath: Path to the JSON file.

        Returns:
            OutboxEntry: The loaded entry.
        """
        return OutboxEntry.model_validate_json(filepath.read_text())

    def _list_dir(self, directory: Path) -> list[OutboxEntry]:
        """List all entries in a directory.

        Args:
            directory: Directory to scan.

        Returns:
            list[OutboxEntry]: Entries sorted by creation time.
        """
        entries = []
        for f in sorted(directory.glob("*.json")):
            try:
                entries.append(self._load_entry(f))
            except (json.JSONDecodeError, ValueError, OSError) as exc:
                logger.warning("Skipping unreadable entry %s: %s", f.name, exc)
                continue
        return entries

    @staticmethod
    def _purge_dir(directory: Path) -> int:
        """Remove all JSON files from a directory.

        Args:
            directory: Directory to purge.

        Returns:
            int: Number of files removed.
        """
        count = 0
        for f in directory.glob("*.json"):
            f.unlink(missing_ok=True)
            count += 1
        return count
