"""
SKComms message queue — persistent outbox with retry and expiry.

When all transports are down, envelopes are queued to disk as JSON
files. A drain loop retries delivery with exponential backoff and
removes expired messages that exceed their TTL.

Queue layout:
    ~/.skcomms/queue/
    ├── {envelope_id}.skc.json       # Envelope bytes
    └── {envelope_id}.skc.meta.json  # Retry state and metadata

The queue is atomic (write-tmp-then-rename) and crash-safe.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .config import SKCOMMS_HOME

logger = logging.getLogger("skcomms.queue")

QUEUE_DIR_NAME = "queue"
ENVELOPE_SUFFIX = ".skc.json"
META_SUFFIX = ".skc.meta.json"


class QueueMeta(BaseModel):
    """Retry and delivery metadata for a queued envelope.

    Attributes:
        envelope_id: Unique envelope identifier.
        recipient: Target agent name or identifier.
        queued_at: When the envelope was first queued.
        attempts: Number of delivery attempts so far.
        last_attempt: Timestamp of the most recent attempt.
        next_retry: Earliest time to retry delivery.
        ttl: Time-to-live in seconds from queued_at.
        backoff: List of backoff intervals in seconds.
        error: Last delivery error message.
    """

    envelope_id: str
    recipient: str
    queued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attempts: int = 0
    last_attempt: Optional[datetime] = None
    next_retry: Optional[datetime] = None
    ttl: int = 86400
    backoff: list[int] = Field(default_factory=lambda: [5, 15, 60, 300, 900])
    error: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        """Check if this envelope has exceeded its TTL."""
        age = (datetime.now(timezone.utc) - self.queued_at).total_seconds()
        return age > self.ttl

    @property
    def is_ready(self) -> bool:
        """Check if this envelope is ready for a retry attempt."""
        if self.is_expired:
            return False
        if self.next_retry is None:
            return True
        return datetime.now(timezone.utc) >= self.next_retry

    def record_attempt(self, error: Optional[str] = None) -> None:
        """Record a delivery attempt and compute the next retry time.

        Args:
            error: Error message if the attempt failed, None on success.
        """
        now = datetime.now(timezone.utc)
        self.attempts += 1
        self.last_attempt = now
        self.error = error

        if error and self.attempts <= len(self.backoff):
            delay = self.backoff[self.attempts - 1]
        elif error:
            delay = self.backoff[-1] if self.backoff else 900
        else:
            delay = 0

        from datetime import timedelta

        self.next_retry = now + timedelta(seconds=delay)


class QueuedEnvelope(BaseModel):
    """A queued envelope with its metadata.

    Attributes:
        meta: Retry and delivery metadata.
        envelope_bytes: Raw serialized envelope.
    """

    meta: QueueMeta
    envelope_bytes: bytes


class MessageQueue:
    """Persistent file-based message queue with retry and expiry.

    Stores undeliverable envelopes as JSON files on disk.
    Supports atomic writes, exponential backoff retries,
    TTL-based expiry, and crash-safe operation.

    Args:
        queue_dir: Directory for queue files. Defaults to ~/.skcomms/queue/.
    """

    def __init__(self, queue_dir: Optional[Path] = None):
        self._dir = queue_dir or Path(SKCOMMS_HOME).expanduser() / QUEUE_DIR_NAME
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def queue_dir(self) -> Path:
        """Path to the queue directory."""
        return self._dir

    def enqueue(
        self,
        envelope_bytes: bytes,
        recipient: str,
        envelope_id: Optional[str] = None,
        ttl: int = 86400,
        backoff: Optional[list[int]] = None,
    ) -> QueueMeta:
        """Add an envelope to the persistent queue.

        Args:
            envelope_bytes: Serialized MessageEnvelope bytes.
            recipient: Target agent name or identifier.
            envelope_id: Envelope ID (extracted from bytes if omitted).
            ttl: Time-to-live in seconds.
            backoff: Custom backoff schedule (seconds between retries).

        Returns:
            QueueMeta for the queued envelope.
        """
        if envelope_id is None:
            envelope_id = self._extract_id(envelope_bytes)

        meta = QueueMeta(
            envelope_id=envelope_id,
            recipient=recipient,
            ttl=ttl,
            backoff=backoff or [5, 15, 60, 300, 900],
        )

        env_path = self._dir / f"{envelope_id}{ENVELOPE_SUFFIX}"
        meta_path = self._dir / f"{envelope_id}{META_SUFFIX}"

        self._atomic_write(env_path, envelope_bytes)
        self._atomic_write(meta_path, meta.model_dump_json(indent=2).encode())

        logger.info("Queued envelope %s for %s (TTL=%ds)", envelope_id[:8], recipient, ttl)
        return meta

    def dequeue(self, envelope_id: str) -> bool:
        """Remove an envelope from the queue (after successful delivery).

        Args:
            envelope_id: ID of the envelope to remove.

        Returns:
            True if the envelope was found and removed.
        """
        env_path = self._dir / f"{envelope_id}{ENVELOPE_SUFFIX}"
        meta_path = self._dir / f"{envelope_id}{META_SUFFIX}"

        removed = False
        if env_path.exists():
            env_path.unlink()
            removed = True
        if meta_path.exists():
            meta_path.unlink()
            removed = True

        if removed:
            logger.info("Dequeued envelope %s", envelope_id[:8])
        return removed

    def peek(self, envelope_id: str) -> Optional[QueuedEnvelope]:
        """Read a queued envelope without removing it.

        Args:
            envelope_id: ID of the envelope.

        Returns:
            QueuedEnvelope or None if not found.
        """
        env_path = self._dir / f"{envelope_id}{ENVELOPE_SUFFIX}"
        meta_path = self._dir / f"{envelope_id}{META_SUFFIX}"

        if not env_path.exists() or not meta_path.exists():
            return None

        try:
            envelope_bytes = env_path.read_bytes()
            meta = QueueMeta.model_validate_json(meta_path.read_text())
            return QueuedEnvelope(meta=meta, envelope_bytes=envelope_bytes)
        except Exception as exc:
            logger.warning("Failed to read queued envelope %s: %s", envelope_id[:8], exc)
            return None

    def list_pending(self) -> list[QueueMeta]:
        """List all queued envelopes that are ready for retry.

        Returns:
            List of QueueMeta for envelopes ready to send, sorted by queue time.
        """
        pending: list[QueueMeta] = []
        for meta_path in sorted(self._dir.glob(f"*{META_SUFFIX}")):
            try:
                meta = QueueMeta.model_validate_json(meta_path.read_text())
                if meta.is_ready:
                    pending.append(meta)
            except Exception as exc:
                logger.warning("Skipping corrupt queue meta %s: %s", meta_path.name, exc)
        return pending

    def list_all(self) -> list[QueueMeta]:
        """List all queued envelopes regardless of retry state.

        Returns:
            List of all QueueMeta, sorted by queue time.
        """
        all_meta: list[QueueMeta] = []
        for meta_path in sorted(self._dir.glob(f"*{META_SUFFIX}")):
            try:
                all_meta.append(QueueMeta.model_validate_json(meta_path.read_text()))
            except Exception as exc:
                logger.warning("Skipping corrupt queue meta %s: %s", meta_path.name, exc)
        return all_meta

    def update_meta(self, meta: QueueMeta) -> None:
        """Persist updated metadata after a delivery attempt.

        Args:
            meta: Updated QueueMeta to save.
        """
        meta_path = self._dir / f"{meta.envelope_id}{META_SUFFIX}"
        self._atomic_write(meta_path, meta.model_dump_json(indent=2).encode())

    def purge_expired(self) -> int:
        """Remove all envelopes that have exceeded their TTL.

        Returns:
            Number of expired envelopes removed.
        """
        removed = 0
        for meta_path in list(self._dir.glob(f"*{META_SUFFIX}")):
            try:
                meta = QueueMeta.model_validate_json(meta_path.read_text())
                if meta.is_expired:
                    self.dequeue(meta.envelope_id)
                    logger.info("Purged expired envelope %s", meta.envelope_id[:8])
                    removed += 1
            except Exception as exc:
                logger.warning("Skipping corrupt queue meta %s: %s", meta_path.name, exc)
        return removed

    def drain(self, send_fn) -> tuple[int, int]:
        """Attempt to deliver all pending queued envelopes.

        Calls send_fn for each ready envelope. On success, dequeues it.
        On failure, records the attempt and updates backoff timing.

        Args:
            send_fn: Callable(envelope_bytes, recipient) -> bool.
                     Returns True on successful delivery.

        Returns:
            Tuple of (delivered_count, failed_count).
        """
        self.purge_expired()
        pending = self.list_pending()

        delivered, failed = 0, 0
        for meta in pending:
            queued = self.peek(meta.envelope_id)
            if queued is None:
                continue

            try:
                success = send_fn(queued.envelope_bytes, queued.meta.recipient)
            except Exception as exc:
                logger.warning("queue.py: %s", exc)
                success = False
                meta.record_attempt(error=str(exc))
                self.update_meta(meta)
                failed += 1
                continue

            if success:
                self.dequeue(meta.envelope_id)
                delivered += 1
                logger.info("Drained envelope %s", meta.envelope_id[:8])
            else:
                meta.record_attempt(error="Transport delivery failed")
                self.update_meta(meta)
                failed += 1

        return delivered, failed

    @property
    def size(self) -> int:
        """Number of envelopes currently in the queue."""
        return len(list(self._dir.glob(f"*{META_SUFFIX}")))

    def _atomic_write(self, path: Path, data: bytes) -> None:
        """Write data atomically via tmp-then-rename."""
        tmp = path.parent / f".{path.name}.tmp"
        tmp.write_bytes(data)
        tmp.rename(path)

    @staticmethod
    def _extract_id(envelope_bytes: bytes) -> str:
        """Best-effort envelope_id extraction from raw bytes."""
        try:
            return json.loads(envelope_bytes).get("envelope_id", f"q-{int(time.time())}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return f"q-{int(time.time())}"
