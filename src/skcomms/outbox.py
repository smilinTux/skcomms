"""Persistent outbox -- queue failed messages and auto-retry.

When SKComms fails to deliver a message (all transports down, network
issues, relay rejection), the outbox saves it to disk and retries
with exponential backoff. Messages that exhaust retries move to a
dead letter queue for manual review.

The outbox is filesystem-based: one JSON file per queued message.
No database needed. Works offline. Survives daemon restarts.

Single queue of record (coord eb659f61)
----------------------------------------
:class:`PersistentOutbox` is now the ONE retry store in skcomms. The two
historical overlapping stores were removed: ``skcomms.core.RetryQueue`` and
the router's own JSONL retry (``Router._enqueue_retry``), which both wrote
incompatible schemas to the same ``~/.skcapstone/retry_queue.jsonl`` file
under independent, unlocked one-second sweepers. Any pre-existing entries in
that file are drained into this outbox by
:func:`skcomms.outbox_migrate.migrate_retry_queue_jsonl` (both schemas), run
best-effort at daemon startup.

Every failed send enqueues here exactly once. The federation contract is:
an :attr:`OutboxEntry.envelope_json` holds a serialized **SignedEnvelope**
(Envelope v1, the canonical wire format). Legacy entries holding a serialized
:class:`~skcomms.models.MessageEnvelope` are tolerated (detected + skipped on
delivery, converted by :func:`skcomms.outbox_migrate.migrate_outbox`).

Layout:
    ~/.skcapstone/skcomms/outbox/
    ├── pending/          # messages awaiting retry
    │   └── {id}.json
    ├── dead/             # permanently failed messages
    │   └── {id}.json
    └── archive/          # migrated-away corrupt / dead-end entries
        └── {id}.json
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("skcomms.outbox")

DEFAULT_OUTBOX_DIR = "~/.skcapstone/skcomms/outbox"
DEFAULT_MAX_RETRIES = 10
DEFAULT_BASE_BACKOFF = 5


def default_outbox_dir() -> Path:
    """Resolve the default persistent-outbox root.

    Honors the ``SKCOMMS_OUTBOX_DIR`` environment override (used by tests and
    by operators who relocate the queue), falling back to
    :data:`DEFAULT_OUTBOX_DIR`.

    Returns:
        Path: The expanded outbox root directory.
    """
    return Path(os.environ.get("SKCOMMS_OUTBOX_DIR", DEFAULT_OUTBOX_DIR)).expanduser()


def classify_envelope_json(envelope_json: str) -> str:
    """Classify a serialized envelope string by its on-wire shape.

    Used to keep the federation outbox tolerant of the historical mix of
    serialized payloads. No deserialization into a model is performed --
    only a cheap structural inspection -- so a corrupt-for-one-model entry
    is still classifiable.

    Returns one of:
        - ``"signed"``  : an Envelope v1 :class:`SignedEnvelope`
          (has a nested ``envelope`` object with ``from_fqid``/``to_fqid``).
        - ``"envelope_v1"`` : a bare Envelope v1
          (has ``from_fqid``/``to_fqid`` at the top level).
        - ``"legacy"``  : a legacy :class:`~skcomms.models.MessageEnvelope`
          (has ``sender``/``recipient``/``payload``).
        - ``"corrupt"`` : not valid JSON, or an unrecognized shape.

    Args:
        envelope_json: The serialized envelope string.

    Returns:
        str: The classification token.
    """
    try:
        data = json.loads(envelope_json)
    except (json.JSONDecodeError, TypeError):
        return "corrupt"

    if not isinstance(data, dict):
        return "corrupt"

    inner = data.get("envelope")
    if isinstance(inner, dict) and "from_fqid" in inner and "to_fqid" in inner:
        return "signed"
    if "from_fqid" in data and "to_fqid" in data:
        return "envelope_v1"
    if "sender" in data and "recipient" in data and "payload" in data:
        return "legacy"
    return "corrupt"


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
        supersede_key: Optional ephemeral-supersede key. Entries sharing a
            key (e.g. re-beaconed CoT position reports for one entity+peer)
            evict older undelivered peers so the outbox keeps only the latest
            and never accumulates stale state. ``None`` = durable (never evicted).
        await_ack: When True this entry is NOT a failed send awaiting retry; it
            is a queued (file/syncthing sneakernet) send that succeeded onto a
            shared filesystem but is not yet confirmed received. The retry sweep
            leaves it untouched. It is removed when its ACK arrives
            (:meth:`remove`) or surfaced via ``delivery_failed`` on ACK timeout.
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
    supersede_key: Optional[str] = None
    await_ack: bool = False


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
        outbox_dir: str | Path | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_backoff: int = DEFAULT_BASE_BACKOFF,
        router: Optional[object] = None,
    ) -> None:
        self._root = (
            Path(outbox_dir).expanduser() if outbox_dir is not None else default_outbox_dir()
        )
        self._pending = self._root / "pending"
        self._dead = self._root / "dead"
        self._archive = self._root / "archive"
        self._max_retries = max_retries
        self._base_backoff = base_backoff
        self._router = router

        self._pending.mkdir(parents=True, exist_ok=True)
        self._dead.mkdir(parents=True, exist_ok=True)
        self._archive.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        """Root directory of this outbox."""
        return self._root

    @property
    def pending_dir(self) -> Path:
        """Directory holding pending entries."""
        return self._pending

    @property
    def dead_dir(self) -> Path:
        """Directory holding dead-lettered (retries exhausted) entries."""
        return self._dead

    @property
    def archive_dir(self) -> Path:
        """Directory holding migrated-away (corrupt / dead-end) entries."""
        return self._archive

    def enqueue(
        self,
        envelope_id: str,
        recipient: str,
        envelope_json: str,
        error: str = "",
        *,
        supersede_key: Optional[str] = None,
        await_ack: bool = False,
    ) -> OutboxEntry:
        """Add a message to the outbox queue.

        Args:
            envelope_id: The envelope's unique ID.
            recipient: Target agent/peer.
            envelope_json: Full serialized envelope JSON.
            error: Error from the failed delivery attempt.
            supersede_key: Optional ephemeral-supersede key (see OutboxEntry).
            await_ack: When True the entry is a queued (file/syncthing) send held
                until its ACK confirms receipt, not a failed send awaiting retry.
                The retry sweep leaves such entries untouched.

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
            supersede_key=supersede_key,
            await_ack=await_ack,
        )

        # Ephemeral entries (e.g. CoT position beacons) carry a supersede_key:
        # a newer entry for the same key evicts any older, still-undelivered
        # ones so the outbox keeps only the latest and never accumulates stale,
        # superseded state. Durable entries (supersede_key=None) are never
        # matched and remain reliably queued.
        if supersede_key:
            evicted = self._evict_superseded(supersede_key)
            if evicted:
                logger.debug(
                    "Superseded %d stale outbox entr%s for key %s",
                    evicted, "y" if evicted == 1 else "ies", supersede_key,
                )

        self._write_entry(self._pending, entry)
        logger.info("Queued %s for retry (error: %s)", envelope_id[:8], error[:60])
        return entry

    def enqueue_signed(
        self, signed: object, error: str = "", *, supersede_key: Optional[str] = None
    ) -> OutboxEntry:
        """Enqueue a :class:`~skcomms.envelope.SignedEnvelope` (federation path).

        This is the canonical federation enqueue helper: it serializes the
        SignedEnvelope to its wire bytes and stores it as the entry's
        ``envelope_json``, deriving ``envelope_id`` / ``recipient`` from the
        inner Envelope v1 (``id`` / ``to_fqid``).

        Args:
            signed: A :class:`~skcomms.envelope.SignedEnvelope` instance.
            error: Error from the failed delivery attempt.

        Returns:
            OutboxEntry: The queued entry.
        """
        env = signed.envelope  # type: ignore[attr-defined]
        return self.enqueue(
            envelope_id=env.id,
            recipient=env.to_fqid,
            envelope_json=signed.to_bytes().decode("utf-8"),  # type: ignore[attr-defined]
            error=error,
            supersede_key=supersede_key,
        )

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

            # Queued (file/syncthing) sends held for an ACK are NOT failed sends:
            # they already reached a shared-filesystem queue. Re-sending would
            # write duplicate envelopes and a queued re-send would even look
            # "delivered" and unlink the hold. Leave them for the ACK path
            # (:meth:`remove` on confirmation, ``delivery_failed`` on timeout).
            if entry.await_ack:
                results["skipped"] += 1
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

    def get(self, envelope_id: str) -> Optional[OutboxEntry]:
        """Look up a pending entry by envelope_id.

        Args:
            envelope_id: The envelope ID (the pending file is ``{id}.json``).

        Returns:
            OutboxEntry if a pending entry exists, else None.
        """
        path = self._pending / f"{envelope_id}.json"
        if not path.exists():
            return None
        try:
            return self._load_entry(path)
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            logger.warning("Unreadable pending entry %s: %s", path.name, exc)
            return None

    def get_dead(self, envelope_id: str) -> Optional[OutboxEntry]:
        """Look up a dead-lettered entry by envelope_id.

        Args:
            envelope_id: The envelope ID (the dead file is ``{id}.json``).

        Returns:
            OutboxEntry if a dead-letter entry exists and is readable, else None.
        """
        path = self._dead / f"{envelope_id}.json"
        if not path.exists():
            return None
        try:
            return self._load_entry(path)
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            logger.warning("Unreadable dead-letter entry %s: %s", path.name, exc)
            return None

    def remove(self, envelope_id: str) -> bool:
        """Delete a pending entry (e.g. when its delivery ACK confirms receipt).

        This is the ACK-tied cleanup for queued (file/syncthing) sends held via
        :meth:`enqueue` with ``await_ack=True``: once the recipient's ACK lands,
        the durable entry is removed.

        Args:
            envelope_id: The envelope ID whose pending entry to delete.

        Returns:
            True if a pending entry was found and removed.
        """
        path = self._pending / f"{envelope_id}.json"
        if path.exists():
            path.unlink(missing_ok=True)
            logger.info("Removed outbox entry %s (ACK confirmed / resolved)", envelope_id[:8])
            return True
        return False

    def mark_dead(self, envelope_id: str, error: str = "") -> bool:
        """Move a pending entry to the dead-letter queue.

        Used when a held (``await_ack``) queued send exhausts its ACK horizon:
        the message reached only a queue and was never confirmed received, so it
        is dead-lettered for inspection (and a ``delivery_failed`` alert fires
        separately).

        Args:
            envelope_id: The envelope ID whose pending entry to dead-letter.
            error: Optional error/reason recorded on the entry.

        Returns:
            True if a pending entry was found and moved.
        """
        path = self._pending / f"{envelope_id}.json"
        if not path.exists():
            return False
        try:
            entry = self._load_entry(path)
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            logger.warning("Unreadable pending entry %s: %s", path.name, exc)
            return False
        if error:
            entry.last_error = error
        self._move_to_dead(entry, path)
        return True

    def purge_pending(self) -> int:
        """Remove all messages from the pending queue.

        Returns:
            int: Number of messages purged.
        """
        return self._purge_dir(self._pending)

    def purge_dead(self, envelope_id: Optional[str] = None) -> int:
        """Remove messages from the dead letter queue.

        Args:
            envelope_id: Specific message to purge, or None for all
                (backward compatible with the historical purge-all form).

        Returns:
            int: Number of messages purged.
        """
        if envelope_id is None:
            return self._purge_dir(self._dead)
        path = self._dead / f"{envelope_id}.json"
        if path.exists():
            path.unlink(missing_ok=True)
            return 1
        return 0

    def prune_dead(self, ttl_hours: float = 0.0, max_count: int = 0) -> int:
        """Enforce retention on the dead-letter directory.

        Dead letters are kept for manual review, but a persistent peer outage
        dead-letters every retry-exhausted send, so without retention ``dead/``
        grows forever exactly like the 140k-file sender outbox did. Two
        independent bounds, each disabled when <= 0:

          * ``ttl_hours``: entries whose file mtime is older are deleted.
          * ``max_count``: only the newest N entries are kept; the oldest
            overflow is deleted.

        Args:
            ttl_hours: Age bound in hours (<= 0 disables the TTL sweep).
            max_count: Count bound (<= 0 disables the count sweep).

        Returns:
            int: Number of dead-letter entries deleted.
        """
        removed = self._prune_retention(self._dead, ttl_hours, max_count)
        if removed:
            logger.info(
                "Dead-letter retention pruned %d entr%s (ttl=%sh max=%s)",
                removed, "y" if removed == 1 else "ies", ttl_hours, max_count,
            )
        return removed

    def prune_archive(self, ttl_hours: float = 0.0, max_count: int = 0) -> int:
        """Enforce retention on the archive (migrated-away entries) directory.

        Same bounds as :meth:`prune_dead`: a TTL on file mtime and a max
        count keeping only the newest N; each disabled when <= 0. The archive
        holds corrupt / dead-end entries parked by the outbox migrator and is
        never read on the delivery path, so pruning it is always safe.

        Args:
            ttl_hours: Age bound in hours (<= 0 disables the TTL sweep).
            max_count: Count bound (<= 0 disables the count sweep).

        Returns:
            int: Number of archive entries deleted.
        """
        removed = self._prune_retention(self._archive, ttl_hours, max_count)
        if removed:
            logger.info(
                "Outbox-archive retention pruned %d entr%s (ttl=%sh max=%s)",
                removed, "y" if removed == 1 else "ies", ttl_hours, max_count,
            )
        return removed

    @staticmethod
    def _prune_retention(directory: Path, ttl_hours: float, max_count: int) -> int:
        """Delete entries in *directory* violating the TTL or count bound.

        Args:
            directory: Directory whose ``*.json`` entries to bound.
            ttl_hours: Age bound in hours (<= 0 disables).
            max_count: Keep-newest count bound (<= 0 disables).

        Returns:
            int: Number of files deleted.
        """
        files: list[tuple[float, Path]] = []
        for f in directory.glob("*.json"):
            try:
                files.append((f.stat().st_mtime, f))
            except OSError:
                continue

        removed = 0

        if ttl_hours > 0:
            cutoff = time.time() - ttl_hours * 3600.0
            kept: list[tuple[float, Path]] = []
            for mtime, f in files:
                if mtime < cutoff:
                    try:
                        f.unlink(missing_ok=True)
                        removed += 1
                    except OSError as exc:
                        logger.warning("Failed to prune %s: %s", f, exc)
                        kept.append((mtime, f))
                else:
                    kept.append((mtime, f))
            files = kept

        if max_count > 0 and len(files) > max_count:
            files.sort()  # oldest first
            for mtime, f in files[: len(files) - max_count]:
                try:
                    f.unlink(missing_ok=True)
                    removed += 1
                except OSError as exc:
                    logger.warning("Failed to prune %s: %s", f, exc)

        return removed

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

    @property
    def archive_count(self) -> int:
        """Number of messages in the archive (migrated-away) directory."""
        return len(list(self._archive.glob("*.json")))

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

    def _deliver_federation(self, entry: OutboxEntry, kind: str) -> bool:
        """Deliver a federation (Envelope v1 / SignedEnvelope) entry.

        Deserializes the entry into a :class:`~skcomms.envelope.SignedEnvelope`
        (wrapping a bare Envelope v1 in an unsigned :class:`SignedEnvelope` so
        the wire shape is uniform) and routes the signed bytes.

        The router is engaged via duck typing so this works with both the
        current router (legacy ``route(MessageEnvelope)``) and the forward
        federation router (S3/S4: ``route_signed`` / ``route_bytes``):

          - ``router.route_signed(signed_envelope)``  -- preferred (S4).
          - ``router.route_bytes(signed_bytes, recipient)`` -- bytes rail.

        If the router exposes neither, the entry stays queued (returns False)
        rather than crashing -- the canonical bytes are preserved on disk for a
        federation-capable router to pick up later.

        Args:
            entry: The outbox entry to deliver.
            kind: ``"signed"`` or ``"envelope_v1"`` (from
                :func:`classify_envelope_json`).

        Returns:
            bool: True if delivery succeeded.
        """
        from .envelope import Envelope, SignedEnvelope

        raw = entry.envelope_json.encode("utf-8")
        if kind == "signed":
            signed = SignedEnvelope.from_bytes(raw)
        else:  # bare Envelope v1 -> wrap unsigned for a uniform wire shape
            signed = SignedEnvelope(envelope=Envelope.from_bytes(raw))

        signed_bytes = signed.to_bytes()

        route_signed = getattr(self._router, "route_signed", None)
        if callable(route_signed):
            report = route_signed(signed)
            return getattr(report, "delivered", False)

        route_bytes = getattr(self._router, "route_bytes", None)
        if callable(route_bytes):
            report = route_bytes(signed_bytes, entry.recipient)
            return getattr(report, "delivered", False)

        # No federation-aware router path available yet (pre-S3/S4). Keep the
        # canonical SignedEnvelope on disk; do not crash the sweep.
        entry.last_error = (
            "router has no federation route path (route_signed/route_bytes); "
            "entry preserved for a federation-capable router"
        )
        logger.info(
            "Outbox %s held: SignedEnvelope ready but router lacks a "
            "federation route path",
            entry.envelope_id[:8],
        )
        return False

    def _attempt_delivery(self, entry: OutboxEntry) -> bool:
        """Try to deliver a queued message via the router.

        The federation contract (SKFed S7) is that ``envelope_json`` holds a
        serialized :class:`~skcomms.envelope.SignedEnvelope` (Envelope v1).
        Delivery deserializes via ``SignedEnvelope.from_bytes`` and routes the
        signed bytes. The method stays tolerant of the existing backlog:

          - ``signed``      : deserialize + route (preferred path).
          - ``envelope_v1`` : a bare unsigned Envelope v1 -- routed too, so the
            migrator can re-queue unsigned-pending entries that signing-at-send
            will eventually cover.
          - ``legacy``      : an old MessageEnvelope -- routed via the legacy
            path for backward compatibility (until migrated).
          - ``corrupt``     : skipped (returns False) without raising, so a
            corrupt backlog never crashes the retry sweep.

        Args:
            entry: The outbox entry to deliver.

        Returns:
            bool: True if delivery succeeded.
        """
        if self._router is None:
            return False

        kind = classify_envelope_json(entry.envelope_json)

        if kind == "corrupt":
            entry.last_error = "corrupt envelope_json (unparseable / unknown shape)"
            logger.warning(
                "Outbox delivery skipped for %s: corrupt entry (run migrate_outbox)",
                entry.envelope_id[:8],
            )
            return False

        try:
            if kind in ("signed", "envelope_v1"):
                return self._deliver_federation(entry, kind)
            # kind == "legacy"
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

    def _evict_superseded(self, supersede_key: str) -> int:
        """Evict pending entries sharing *supersede_key* (ephemeral supersede).

        Bounds ephemeral traffic (e.g. re-beaconed CoT position reports): when
        a newer entry for the same key is enqueued, older undelivered ones for
        that key are removed from the pending queue so superseded state never
        accumulates. Durable entries (``supersede_key`` unset) are never
        matched.

        Args:
            supersede_key: The key whose older pending entries to evict.

        Returns:
            int: Number of entries evicted.
        """
        evicted = 0
        for entry_path in self._pending.glob("*.json"):
            try:
                entry = self._load_entry(entry_path)
            except (json.JSONDecodeError, ValueError, OSError):
                continue
            if entry.supersede_key and entry.supersede_key == supersede_key:
                entry_path.unlink(missing_ok=True)
                evicted += 1
        return evicted

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
