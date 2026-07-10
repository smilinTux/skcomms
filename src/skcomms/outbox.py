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
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("skcomms.outbox")

DEFAULT_OUTBOX_DIR = "~/.skcapstone/skcomms/outbox"
DEFAULT_MAX_RETRIES = 10
DEFAULT_BASE_BACKOFF = 5

# Bounds (coord 74d7b799): the pending queue is one-file-per-entry on disk and
# historically had NO size bound (only supersede_key eviction), so a dead rail
# could grow it without limit (the 140k-file class of failure). The default cap
# is generous for a healthy deploy but bounds the pathological case; <= 0
# disables the bound (explicit opt-out, not the default).
DEFAULT_MAX_PENDING = 5000

# Paced draining (coord 74d7b799): a backlog flush that retries EVERY due entry
# in a single sweep can DoS a receiving node's inbox rate limiter and re-dead-
# letter en masse the moment a rail comes back. Each sweep now attempts at most
# this many deliveries; the remainder stays queued for the next sweep interval,
# so a large backlog drains in bounded, paced batches. <= 0 disables pacing.
#
# INVARIANT: keep this <= the outbound rate limiter's peer_capacity
# (config.OutboundRateLimitConfig.peer_capacity, default 20). A same-peer
# backlog sweep larger than the peer bucket guarantees the tail of every sweep
# is throttled locally, so the paced sweep and the peer bucket would fight
# instead of cooperate. 20 attempts per sweep with the default 30s sweep
# interval and 2 tokens/s peer refill means the bucket is back at full burst
# capacity before each sweep starts.
DEFAULT_SWEEP_BATCH = 20


class OutboxFullError(RuntimeError):
    """Raised when the pending queue is at its bound and cannot accept more.

    The explicit backpressure signal to local callers (coord 74d7b799): the
    HTTP API maps it to a 429, library callers see the exception instead of
    silently growing an unbounded on-disk queue.
    """


class _DeliveryOutcome(NamedTuple):
    """Result of one outbox delivery attempt through the router.

    Attributes:
        delivered: True when a rail accepted the message.
        throttled: True when the attempt failed ONLY because every attempted
            rail was denied by the LOCAL outbound rate limiter (every failed
            attempt error starts with ``throttled:``, so nothing reached the
            wire). Per ``Router._throttle_check``'s contract that is pacing,
            not a delivery failure: such an attempt must not consume the
            entry's durable retry budget or advance it toward dead-letter.
    """

    delivered: bool
    throttled: bool = False


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
        max_pending: Bound on the pending queue's entry count. When a new
            enqueue would exceed it, :class:`OutboxFullError` is raised
            (explicit backpressure). Values <= 0 disable the bound.
        sweep_batch: Max delivery attempts per retry sweep, so a backlog
            drains in bounded, paced batches. Values <= 0 disable pacing.
    """

    def __init__(
        self,
        outbox_dir: str | Path = DEFAULT_OUTBOX_DIR,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_backoff: int = DEFAULT_BASE_BACKOFF,
        router: Optional[object] = None,
        max_pending: int = DEFAULT_MAX_PENDING,
        sweep_batch: int = DEFAULT_SWEEP_BATCH,
    ) -> None:
        self._root = Path(outbox_dir).expanduser()
        self._pending = self._root / "pending"
        self._dead = self._root / "dead"
        self._archive = self._root / "archive"
        self._max_retries = max_retries
        self._base_backoff = base_backoff
        self._router = router
        self._max_pending = max_pending
        self._sweep_batch = sweep_batch

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

        Raises:
            OutboxFullError: The pending queue is at ``max_pending`` and this
                enqueue would grow it (rewrites of an existing envelope_id and
                supersede-key replacements do not grow the queue, so they are
                always accepted).
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

        # Bound check (after supersede eviction, which may have freed a slot).
        # Rewriting an existing entry never grows the queue, so it is exempt.
        #
        # NOTE: this is a deliberate SOFT bound. pending_count is a directory
        # glob, so (a) concurrent enqueues (e.g. from the FastAPI threadpool)
        # can race the check-then-write and overshoot the cap by a few
        # entries (a TOCTOU window), and (b) the count is an O(n) scan per
        # enqueue at queue depth n. Both are accepted trade-offs: the bound
        # exists to stop unbounded 140k-file growth, not to enforce an exact
        # ceiling, and no correctness depends on the precise count. If the
        # O(n) scan ever shows up in profiles, cache the count and reconcile
        # it against the glob periodically.
        if (
            self._max_pending > 0
            and not (self._pending / f"{entry.envelope_id}.json").exists()
            and self.pending_count >= self._max_pending
        ):
            logger.warning(
                "Outbox pending queue full (%d >= %d): refusing enqueue of %s",
                self.pending_count,
                self._max_pending,
                envelope_id[:8],
            )
            raise OutboxFullError(
                f"outbox pending queue is full ({self._max_pending} entries): "
                f"refusing to enqueue {envelope_id}"
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

    def retry_all(self, max_batch: Optional[int] = None) -> dict[str, Any]:
        """Sweep the pending queue and retry eligible messages, paced.

        Only retries messages whose next_retry_at has passed.
        Successful deliveries are removed from the queue.
        Exhausted retries move to dead letter.

        Draining is paced (coord 74d7b799): at most ``max_batch`` (default the
        instance's ``sweep_batch``) delivery attempts are made per sweep, and
        any further due entries are deferred to the next sweep. This keeps a
        large backlog flush from flooding a recovering rail or a receiving
        node's inbox rate limiter.

        Throttle-only failures (every attempted rail denied by the LOCAL
        outbound rate limiter, nothing reached the wire) are pacing, not
        delivery failures: they do NOT consume the entry's durable retry
        budget (no ``attempt_count`` increment, no progress toward
        dead-letter) and are reported under 'throttled'. The entry is simply
        retried on a later, paced sweep, per ``Router._throttle_check``'s
        contract.

        Args:
            max_batch: Per-sweep delivery-attempt cap. ``None`` uses the
                instance's ``sweep_batch``; values <= 0 disable pacing.

        Returns:
            dict: Summary with 'retried', 'delivered', 'dead_lettered',
            'skipped', 'throttled' (attempts denied entirely by the local
            outbound rate limiter, retried later with no retry-budget cost),
            and 'deferred' (due entries left for the next sweep because the
            batch cap was reached).
        """
        batch_cap = self._sweep_batch if max_batch is None else max_batch
        results = {
            "retried": 0,
            "delivered": 0,
            "dead_lettered": 0,
            "skipped": 0,
            "throttled": 0,
            "deferred": 0,
        }
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

            # Paced batch: budget exhausted, leave the rest for the next sweep.
            # Throttle-only attempts consume the SWEEP budget too (once the
            # outbound buckets are dry, further attempts this sweep would
            # throttle as well, so trying them is wasted work), but never the
            # per-entry retry budget below.
            if batch_cap > 0 and (results["retried"] + results["throttled"]) >= batch_cap:
                results["deferred"] += 1
                continue

            outcome = self._attempt_delivery(entry)

            if not outcome.delivered and outcome.throttled:
                # Every attempted rail was denied by the LOCAL outbound rate
                # limiter; nothing reached the wire. That is pacing, not a
                # delivery failure: leave the entry untouched (no
                # attempt_count increment, no dead-letter progress) so a
                # throttled backlog can never dead-letter messages that were
                # never actually attempted on the wire. It stays due and is
                # retried on a later, paced sweep.
                results["throttled"] += 1
                continue

            results["retried"] += 1

            if outcome.delivered:
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
                if (
                    results["retried"] > 0
                    or results.get("throttled", 0) > 0
                    or results.get("deferred", 0) > 0
                ):
                    logger.info(
                        "Outbox sweep: retried=%d delivered=%d dead=%d "
                        "skipped=%d throttled=%d deferred=%d",
                        results["retried"],
                        results["delivered"],
                        results["dead_lettered"],
                        results["skipped"],
                        results.get("throttled", 0),
                        results.get("deferred", 0),
                    )
            except Exception as exc:
                logger.warning("Outbox retry sweep error: %s", exc)
            self._stop_event.wait(timeout=self._retry_interval)

    def _report_outcome(self, entry: OutboxEntry, report: object) -> _DeliveryOutcome:
        """Fold a router :class:`DeliveryReport` into a :class:`_DeliveryOutcome`.

        Also records WHY a failed attempt failed: ``entry.last_error`` is set
        from the report's last failed attempt, so a dead-lettered entry shows
        operators the actual reason instead of a stale or empty error (report
        failures previously only surfaced when an exception was raised).

        The throttled flag is True only when the report failed AND every
        failed attempt error starts with ``throttled:`` (the router's local
        outbound rate limiter denied the send before it reached the
        transport). A report with no attempts at all (e.g. no candidate
        rails) is a real failure, not a throttle.

        Args:
            entry: The outbox entry being delivered (last_error updated).
            report: A router DeliveryReport (duck-typed for test stubs).

        Returns:
            _DeliveryOutcome: The delivery outcome.
        """
        delivered = bool(getattr(report, "delivered", False))
        attempts = list(getattr(report, "attempts", None) or [])
        failed_errors = [
            (getattr(attempt, "error", None) or "")
            for attempt in attempts
            if not getattr(attempt, "success", False)
        ]
        if not delivered and failed_errors:
            entry.last_error = failed_errors[-1]
        throttled = (
            not delivered
            and bool(failed_errors)
            and all(err.startswith("throttled:") for err in failed_errors)
        )
        return _DeliveryOutcome(delivered=delivered, throttled=throttled)

    def _deliver_federation(self, entry: OutboxEntry, kind: str) -> _DeliveryOutcome:
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
            _DeliveryOutcome: The delivery outcome (delivered / throttled).
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
            return self._report_outcome(entry, report)

        route_bytes = getattr(self._router, "route_bytes", None)
        if callable(route_bytes):
            report = route_bytes(signed_bytes, entry.recipient)
            return self._report_outcome(entry, report)

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
        return _DeliveryOutcome(delivered=False)

    def _attempt_delivery(self, entry: OutboxEntry) -> _DeliveryOutcome:
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
            _DeliveryOutcome: The delivery outcome. ``throttled=True`` means
            every attempted rail was denied by the local outbound rate
            limiter and nothing reached the wire (pacing, not failure).
        """
        if self._router is None:
            return _DeliveryOutcome(delivered=False)

        kind = classify_envelope_json(entry.envelope_json)

        if kind == "corrupt":
            entry.last_error = "corrupt envelope_json (unparseable / unknown shape)"
            logger.warning(
                "Outbox delivery skipped for %s: corrupt entry (run migrate_outbox)",
                entry.envelope_id[:8],
            )
            return _DeliveryOutcome(delivered=False)

        try:
            if kind in ("signed", "envelope_v1"):
                return self._deliver_federation(entry, kind)
            # kind == "legacy"
            from .models import MessageEnvelope

            envelope = MessageEnvelope.from_bytes(entry.envelope_json.encode("utf-8"))
            report = self._router.route(envelope)
            return self._report_outcome(entry, report)
        except (json.JSONDecodeError, ValueError) as exc:
            entry.last_error = str(exc)
            logger.warning(
                "Outbox delivery failed for %s (bad envelope): %s",
                entry.envelope_id[:8],
                exc,
            )
            return _DeliveryOutcome(delivered=False)
        except OSError as exc:
            entry.last_error = str(exc)
            logger.warning(
                "Outbox delivery failed for %s (I/O error): %s",
                entry.envelope_id[:8],
                exc,
            )
            return _DeliveryOutcome(delivered=False)
        except Exception as exc:
            entry.last_error = str(exc)
            logger.warning(
                "Outbox delivery failed for %s: %s",
                entry.envelope_id[:8],
                exc,
            )
            return _DeliveryOutcome(delivered=False)

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
