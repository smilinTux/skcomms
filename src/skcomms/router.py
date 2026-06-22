"""
SKComms router — the brain that picks how to deliver.

Decides which transport(s) to use based on routing mode,
transport priority, health status, and peer configuration.
Handles failover, broadcast, and retry logic.
"""

from __future__ import annotations

import base64
import json
import logging
import pathlib
import threading
import time
from collections import OrderedDict
from typing import Optional

from .envelope import SignedEnvelope
from .models import MessageEnvelope, MessagePayload, RoutingConfig, RoutingMode
from .transport import (
    DeliveryReport,
    SendResult,
    Transport,
    TransportCategory,
    TransportError,
)

logger = logging.getLogger("skcomms.router")

# Failure tracking defaults
FAILURE_THRESHOLD = 3  # consecutive failures before cooldown
COOLDOWN_SECONDS = 60.0  # seconds to skip a transport after repeated failures

# Federation default rail chain (by transport name). Used to order candidate
# transports when a peer advertises no explicit rail order. Rails not named
# here fall to the back, ordered by their global priority.
FEDERATION_DEFAULT_CHAIN = [
    "https-s2s",
    "tailscale",
    "nostr",
    "ble",
    "lora",
    "telegram",
    "file",
]

# Designated store-and-forward fallback rail. Tried last, after every direct
# rail has failed, before an envelope is handed to the retry queue.
DEFAULT_STORE_FORWARD_TRANSPORT = "nostr"

# Deduplication cache limit
SEEN_IDS_MAX = 10_000

# Retry queue
RETRY_QUEUE_PATH = pathlib.Path.home() / ".skcapstone" / "retry_queue.jsonl"
RETRY_BASE_DELAY = 1.0  # seconds before first retry (doubles each attempt)
RETRY_MAX_DELAY = 60.0  # cap on per-attempt wait
RETRY_MAX_ATTEMPTS = 10  # drop envelope after this many retry attempts


class Router:
    """Transport router with multi-mode delivery and automatic failover.

    Supports four routing modes:
    - failover: try transports in priority order, stop on first success
    - broadcast: send via ALL available transports simultaneously
    - stealth: use only high-stealth transports (file, dns_txt, ipfs)
    - speed: use only low-latency transports (netcat, tailscale, iroh)

    Tracks consecutive send failures per transport. After
    ``FAILURE_THRESHOLD`` failures a transport enters a cooldown period
    (``COOLDOWN_SECONDS``) during which it is temporarily skipped.

    Args:
        transports: List of configured Transport instances.
        default_mode: Fallback routing mode when envelope doesn't specify.
    """

    STEALTH_CATEGORIES = {TransportCategory.STEALTH, TransportCategory.FILE_BASED}
    SPEED_CATEGORIES = {TransportCategory.REALTIME}

    def __init__(
        self,
        transports: Optional[list[Transport]] = None,
        default_mode: RoutingMode = RoutingMode.FAILOVER,
        store_forward_transport: str = DEFAULT_STORE_FORWARD_TRANSPORT,
    ):
        self._transports: list[Transport] = transports or []
        self._default_mode = default_mode
        # Name of the designated store-and-forward fallback rail. When all
        # direct rails fail this rail is tried last (if available + not in
        # cooldown) before the envelope is queued for retry.
        self._store_forward_transport = store_forward_transport
        self._seen_ids: OrderedDict[str, float] = OrderedDict()
        self._seen_ttl = 7 * 24 * 3600  # 7 days

        # Failure tracking: {transport_name: (consecutive_fail_count, last_fail_time)}
        self._transport_failures: dict[str, tuple[int, float]] = {}

        # Retry queue
        self._queue_lock = threading.Lock()
        self._retry_thread = threading.Thread(
            target=self._retry_worker, daemon=True, name="skcomms-retry"
        )
        self._retry_thread.start()

    @property
    def transports(self) -> list[Transport]:
        """All registered transports, sorted by priority."""
        return sorted(self._transports, key=lambda t: t.priority)

    def register_transport(self, transport: Transport) -> None:
        """Add a transport to the routing table.

        Args:
            transport: A configured Transport instance.
        """
        existing = next((t for t in self._transports if t.name == transport.name), None)
        if existing:
            self._transports.remove(existing)
        self._transports.append(transport)
        logger.info(
            "Registered transport '%s' (priority=%d, category=%s)",
            transport.name,
            transport.priority,
            transport.category.value,
        )

    def unregister_transport(self, name: str) -> bool:
        """Remove a transport from the routing table.

        Args:
            name: Transport name to remove.

        Returns:
            True if the transport was found and removed.
        """
        before = len(self._transports)
        self._transports = [t for t in self._transports if t.name != name]
        removed = len(self._transports) < before
        if removed:
            logger.info("Unregistered transport '%s'", name)
        return removed

    def route(self, envelope: MessageEnvelope) -> DeliveryReport:
        """Route an envelope through the appropriate transport(s).

        Selects transports based on the envelope's routing mode,
        filters by availability, and handles delivery with retry.

        Args:
            envelope: The message envelope to deliver.

        Returns:
            DeliveryReport with all attempt results.
        """
        mode = envelope.routing.mode or self._default_mode
        report = DeliveryReport(envelope_id=envelope.envelope_id, delivered=False)

        candidates = self._select_transports(mode, envelope)
        if not candidates:
            logger.warning(
                "No available transports for envelope %s (mode=%s)",
                envelope.envelope_id[:8],
                mode.value,
            )
            return report

        envelope_bytes = envelope.to_bytes()

        if mode == RoutingMode.BROADCAST:
            report = self._route_broadcast(envelope_bytes, envelope, candidates, report)
        else:
            report = self._route_failover(envelope_bytes, envelope, candidates, report)

        # Store-and-forward fallback: when every direct rail failed, try the
        # designated S&F rail (default "nostr") as a last resort before the
        # envelope is queued for retry. Skipped if it was already a candidate
        # (and thus already attempted) above.
        if not report.delivered:
            report = self._try_store_forward(envelope_bytes, envelope, candidates, report)

        if report.delivered:
            logger.info(
                "Delivered %s via %s",
                envelope.envelope_id[:8],
                report.successful_transport,
            )
        else:
            logger.warning(
                "Failed to deliver %s after %d attempts — queuing for retry",
                envelope.envelope_id[:8],
                len(report.attempts),
            )
            self._enqueue_retry(envelope, envelope_bytes)

        return report

    def route_bytes(
        self,
        envelope_bytes: bytes,
        recipient: str,
        *,
        envelope_id: str = "",
        sender: str = "skfed-router",
        preferred_transports: Optional[list[str]] = None,
        mode: Optional[RoutingMode] = None,
    ) -> DeliveryReport:
        """Best-effort deliver pre-serialized wire bytes to ``recipient``.

        The federation send path: the caller supplies the EXACT wire bytes
        (a :class:`~skcomms.envelope.SignedEnvelope`) and owns durability/retry
        (the federation outbox is authoritative — see ``outbox.py``). This does
        rail selection (peer-advertised order or the federation default chain)
        → failover → store-and-forward fallback, and returns the report. Unlike
        :meth:`route`, it does NOT enqueue to the router's own retry queue.

        Args:
            envelope_bytes: The exact bytes to put on the wire (e.g.
                ``SignedEnvelope.to_bytes()``).
            recipient: Recipient address used for rail resolution (fqid/name).
            envelope_id: Stable id for dedup/reporting (the inner Envelope id).
            sender: Sender address (informational; not on the wire).
            preferred_transports: Peer-advertised ordered rail list.
            mode: Routing mode override (default the router's default).

        Returns:
            DeliveryReport for this attempt.
        """
        mode = mode or self._default_mode
        carrier = MessageEnvelope(
            envelope_id=envelope_id or "",
            sender=sender,
            recipient=recipient,
            payload=MessagePayload(content=""),
            routing=RoutingConfig(mode=mode, preferred_transports=preferred_transports or []),
        )
        report = DeliveryReport(envelope_id=carrier.envelope_id, delivered=False)
        candidates = self._select_transports(mode, carrier)
        if not candidates:
            logger.warning("No available rails for %s (mode=%s)", recipient, mode.value)
            return report
        report = self._route_failover(envelope_bytes, carrier, candidates, report)
        if not report.delivered:
            report = self._try_store_forward(envelope_bytes, carrier, candidates, report)
        return report

    def route_signed(
        self,
        signed: SignedEnvelope,
        *,
        preferred_transports: Optional[list[str]] = None,
        mode: Optional[RoutingMode] = None,
    ) -> DeliveryReport:
        """Route a canonical :class:`SignedEnvelope` to its ``to_fqid``.

        The signed envelope's own bytes go on the wire verbatim (so the remote
        node's ``POST /inbox`` parses the same ``SignedEnvelope`` and verifies
        it). Rail order comes from ``preferred_transports`` (peer-advertised) or
        the federation default chain.
        """
        env = signed.envelope
        return self.route_bytes(
            signed.to_bytes(),
            env.to_fqid,
            envelope_id=env.id,
            sender=env.from_fqid,
            preferred_transports=preferred_transports,
            mode=mode,
        )

    def receive_all(self) -> list[bytes]:
        """Poll all transports for incoming envelopes.

        Returns:
            List of raw envelope bytes from all transports,
            deduplicated by envelope_id.
        """
        self._prune_seen_ids()
        all_data: list[bytes] = []

        for transport in self.transports:
            if not transport.is_available():
                continue
            try:
                incoming = transport.receive()
                for data in incoming:
                    env_id = self._extract_envelope_id(data)
                    if env_id and env_id in self._seen_ids:
                        logger.debug(
                            "Duplicate envelope %s via %s — skipping",
                            env_id[:8],
                            transport.name,
                        )
                        continue
                    if env_id:
                        self._seen_ids[env_id] = time.time()
                        self._seen_ids.move_to_end(env_id)
                    all_data.append(data)
            except Exception as exc:
                logger.warning(
                    "Error receiving from transport '%s': %s", transport.name, exc
                )
                self._record_failure(transport.name)

        return all_data

    def health_report(self) -> dict[str, dict]:
        """Get health status of all registered transports.

        Returns:
            Dict mapping transport name to health info.
        """
        report = {}
        for transport in self.transports:
            try:
                health = transport.health_check()
                report[transport.name] = health.model_dump(mode="json")
            except Exception as exc:
                logger.warning("Health check failed for transport '%s': %s", transport.name, exc)
                report[transport.name] = {
                    "transport_name": transport.name,
                    "status": "unavailable",
                    "error": str(exc),
                }
        return report

    def _is_in_cooldown(self, transport_name: str) -> bool:
        """Check whether a transport is in failure cooldown.

        Args:
            transport_name: Name of the transport to check.

        Returns:
            True if the transport has exceeded the failure threshold and
            the cooldown period has not yet elapsed.
        """
        entry = self._transport_failures.get(transport_name)
        if entry is None:
            return False
        fail_count, last_fail = entry
        if fail_count < FAILURE_THRESHOLD:
            return False
        return (time.monotonic() - last_fail) < COOLDOWN_SECONDS

    def _select_transports(self, mode: RoutingMode, envelope: MessageEnvelope) -> list[Transport]:
        """Filter and order transports for the given routing mode.

        Ordering precedence (federation rail selection):
        1. **Peer-advertised ordered rail list** — when the envelope carries
           ``routing.preferred_transports``, that order is honored *strictly*.
           The named rails lead, in exactly the order given; any remaining
           available rails follow, ordered by the federation default chain.
        2. **Federation default chain** — when the peer advertises no order,
           rails are ordered by :data:`FEDERATION_DEFAULT_CHAIN` (by name),
           with un-named rails appended by global priority.

        Transports in failure cooldown (and, for stealth/speed modes, rails of
        the wrong category) are excluded from candidates.

        Args:
            mode: The routing mode to apply.
            envelope: The envelope being routed (carries the peer-advertised
                ordered rail list in ``routing.preferred_transports``).

        Returns:
            Ordered list of eligible, available transports.
        """
        available = [
            t for t in self._transports if t.is_available() and not self._is_in_cooldown(t.name)
        ]

        if mode == RoutingMode.STEALTH:
            available = [t for t in available if t.category in self.STEALTH_CATEGORIES]
        elif mode == RoutingMode.SPEED:
            available = [t for t in available if t.category in self.SPEED_CATEGORIES]

        preferred = envelope.routing.preferred_transports
        if preferred:
            # Reason: respect the peer-advertised rail ORDER exactly — the peer
            # knows which rails it is reachable on and in what preference. We do
            # not re-sort the advertised rails by our own global priority.
            by_name = {t.name: t for t in available}
            ordered: list[Transport] = []
            seen: set[str] = set()
            for name in preferred:
                t = by_name.get(name)
                if t is not None and t.name not in seen:
                    ordered.append(t)
                    seen.add(t.name)
            # Remaining available rails (not advertised) follow as fallbacks,
            # ordered by the federation default chain.
            rest = [t for t in available if t.name not in seen]
            return ordered + self._order_by_default_chain(rest)

        # No peer-advertised order → federation default chain.
        return self._order_by_default_chain(available)

    @staticmethod
    def _order_by_default_chain(transports: list[Transport]) -> list[Transport]:
        """Order transports by the federation default chain, then priority.

        Rails named in :data:`FEDERATION_DEFAULT_CHAIN` lead, in chain order;
        rails not in the chain follow, ordered by ascending global priority.

        Args:
            transports: The transports to order.

        Returns:
            A new, ordered list.
        """
        chain_index = {name: i for i, name in enumerate(FEDERATION_DEFAULT_CHAIN)}
        in_chain = [t for t in transports if t.name in chain_index]
        out_of_chain = [t for t in transports if t.name not in chain_index]
        in_chain.sort(key=lambda t: chain_index[t.name])
        out_of_chain.sort(key=lambda t: t.priority)
        return in_chain + out_of_chain

    def _route_failover(
        self,
        envelope_bytes: bytes,
        envelope: MessageEnvelope,
        candidates: list[Transport],
        report: DeliveryReport,
    ) -> DeliveryReport:
        """Try transports in priority order, stop on first success."""
        for transport in candidates:
            result = self._try_send(transport, envelope_bytes, envelope.recipient)
            report.attempts.append(result)
            if result.success:
                report.delivered = True
                break
        return report

    def _route_broadcast(
        self,
        envelope_bytes: bytes,
        envelope: MessageEnvelope,
        candidates: list[Transport],
        report: DeliveryReport,
    ) -> DeliveryReport:
        """Send via ALL available transports simultaneously."""
        for transport in candidates:
            result = self._try_send(transport, envelope_bytes, envelope.recipient)
            report.attempts.append(result)
            if result.success:
                report.delivered = True
        return report

    def _try_store_forward(
        self,
        envelope_bytes: bytes,
        envelope: MessageEnvelope,
        candidates: list[Transport],
        report: DeliveryReport,
    ) -> DeliveryReport:
        """Last-resort store-and-forward fallback after all direct rails fail.

        Attempts delivery via the designated store-and-forward rail
        (``self._store_forward_transport``, default "nostr"). The Nostr relay
        rail holds the signed envelope for an offline/NAT'd recipient to pull
        later — turning a hard failure into a deferred delivery.

        The rail is tried only if it is registered, available, not in cooldown,
        and was not already among the ``candidates`` attempted above (so we
        never double-send on the same rail).

        Args:
            envelope_bytes: Serialized envelope to deliver.
            envelope: The envelope being routed (for recipient).
            candidates: The direct rails already attempted this route.
            report: The delivery report to append the attempt to.

        Returns:
            The (possibly updated) delivery report.
        """
        sf_name = self._store_forward_transport
        if not sf_name:
            return report

        # Don't re-attempt a rail that was already tried as a direct candidate.
        already_tried = {t.name for t in candidates}
        if sf_name in already_tried:
            return report

        sf = next((t for t in self._transports if t.name == sf_name), None)
        if sf is None or not sf.is_available() or self._is_in_cooldown(sf.name):
            return report

        logger.info(
            "All direct rails failed for %s — attempting store-and-forward via '%s'",
            envelope.envelope_id[:8],
            sf_name,
        )
        result = self._try_send(sf, envelope_bytes, envelope.recipient)
        report.attempts.append(result)
        if result.success:
            report.delivered = True
        return report

    def _record_failure(self, transport_name: str) -> None:
        """Increment the consecutive failure counter for a transport.

        After ``FAILURE_THRESHOLD`` consecutive failures a warning is
        logged and the transport enters cooldown.  Each subsequent failure
        beyond the threshold is logged at ERROR to ensure repeated
        breakdowns remain visible.

        Args:
            transport_name: Name of the transport that failed.
        """
        prev = self._transport_failures.get(transport_name, (0, 0.0))
        new_count = prev[0] + 1
        now = time.monotonic()
        self._transport_failures[transport_name] = (new_count, now)
        if new_count == FAILURE_THRESHOLD:
            logger.warning(
                "Transport '%s' hit %d consecutive failures — entering %.0fs cooldown",
                transport_name,
                FAILURE_THRESHOLD,
                COOLDOWN_SECONDS,
            )
        elif new_count > FAILURE_THRESHOLD:
            logger.error(
                "Transport '%s' has now failed %d consecutive times "
                "(threshold=%d) — still in cooldown",
                transport_name,
                new_count,
                FAILURE_THRESHOLD,
            )

    def _record_success(self, transport_name: str) -> None:
        """Reset the failure counter for a transport after a successful send.

        Args:
            transport_name: Name of the transport that succeeded.
        """
        self._transport_failures.pop(transport_name, None)

    def _try_send(self, transport: Transport, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Attempt to send through a single transport with error handling."""
        start = time.monotonic()
        try:
            result = transport.send(envelope_bytes, recipient)
            if result.success:
                self._record_success(transport.name)
            else:
                logger.warning(
                    "Transport '%s' send failed: %s",
                    transport.name,
                    result.error or "no error detail",
                )
                self._record_failure(transport.name)
            return result
        except TransportError as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.warning("Transport '%s' TransportError: %s", transport.name, exc)
            self._record_failure(transport.name)
            return SendResult(
                success=False,
                transport_name=transport.name,
                envelope_id="",
                latency_ms=elapsed,
                error=str(exc),
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.warning("Transport '%s' failed: %s", transport.name, exc)
            self._record_failure(transport.name)
            return SendResult(
                success=False,
                transport_name=transport.name,
                envelope_id="",
                latency_ms=elapsed,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Retry queue
    # ------------------------------------------------------------------

    def _enqueue_retry(self, envelope: MessageEnvelope, envelope_bytes: bytes) -> None:
        """Persist a failed envelope to the JSONL retry queue."""
        entry = {
            "envelope_id": envelope.envelope_id,
            "recipient": envelope.recipient,
            "routing_mode": (envelope.routing.mode or self._default_mode).value,
            "envelope_b64": base64.b64encode(envelope_bytes).decode(),
            "attempt": 0,
            # First retry after RETRY_BASE_DELAY (2^0 = 1s)
            "next_retry_at": time.time() + RETRY_BASE_DELAY,
            "queued_at": time.time(),
        }
        try:
            RETRY_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with self._queue_lock:
                with RETRY_QUEUE_PATH.open("a") as fh:
                    fh.write(json.dumps(entry) + "\n")
            logger.info(
                "Queued envelope %s for retry (max %d attempts)",
                envelope.envelope_id[:8],
                RETRY_MAX_ATTEMPTS,
            )
        except OSError as exc:
            logger.error("Failed to write retry queue: %s", exc)

    def _retry_worker(self) -> None:
        """Daemon thread: process the retry queue every second."""
        while True:
            try:
                self._process_retry_queue()
            except Exception:
                logger.exception("Retry worker error")
            time.sleep(1.0)

    def _process_retry_queue(self) -> None:
        """One sweep: attempt ready entries, rewrite queue with survivors."""
        if not RETRY_QUEUE_PATH.exists():
            return

        with self._queue_lock:
            try:
                raw = RETRY_QUEUE_PATH.read_text()
            except OSError:
                return

            entries: list[dict] = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Corrupt retry queue entry — dropping")

            now = time.time()
            surviving: list[dict] = []

            for entry in entries:
                # Tolerate legacy entries that stored next_retry_at as an ISO
                # string instead of an epoch float.
                nra = entry.get("next_retry_at", 0)
                if isinstance(nra, str):
                    try:
                        from datetime import datetime
                        nra = datetime.fromisoformat(nra.replace("Z", "+00:00")).timestamp()
                    except Exception:
                        nra = 0
                if nra > now:
                    surviving.append(entry)
                    continue

                attempt = entry.get("attempt", 0)
                if attempt >= RETRY_MAX_ATTEMPTS:
                    logger.warning(
                        "Dropping envelope %s after %d retry attempts",
                        entry.get("envelope_id", "?")[:8],
                        RETRY_MAX_ATTEMPTS,
                    )
                    continue

                try:
                    envelope_bytes = base64.b64decode(entry["envelope_b64"])
                except Exception:
                    logger.warning("Retry queue entry has invalid envelope_b64 — dropping")
                    continue

                recipient = entry.get("recipient", "")
                try:
                    mode = RoutingMode(entry.get("routing_mode", RoutingMode.FAILOVER.value))
                except ValueError:
                    mode = RoutingMode.FAILOVER

                if self._retry_send(envelope_bytes, recipient, mode):
                    logger.info(
                        "Retry delivered envelope %s (attempt %d)",
                        entry.get("envelope_id", "?")[:8],
                        attempt + 1,
                    )
                    # Delivered — don't re-add to survivors
                else:
                    next_attempt = attempt + 1
                    delay = min(RETRY_BASE_DELAY * (2**next_attempt), RETRY_MAX_DELAY)
                    entry["attempt"] = next_attempt
                    entry["next_retry_at"] = time.time() + delay
                    surviving.append(entry)
                    logger.debug(
                        "Retry failed for %s — next in %.0fs (attempt %d/%d)",
                        entry.get("envelope_id", "?")[:8],
                        delay,
                        next_attempt,
                        RETRY_MAX_ATTEMPTS,
                    )

            try:
                if surviving:
                    RETRY_QUEUE_PATH.write_text("\n".join(json.dumps(e) for e in surviving) + "\n")
                else:
                    RETRY_QUEUE_PATH.write_text("")
            except OSError as exc:
                logger.error("Failed to rewrite retry queue: %s", exc)

    def _retry_send(self, envelope_bytes: bytes, recipient: str, mode: RoutingMode) -> bool:
        """Try to deliver envelope bytes via available transports (failover order)."""
        available = [
            t for t in self._transports if t.is_available() and not self._is_in_cooldown(t.name)
        ]
        if mode == RoutingMode.STEALTH:
            available = [t for t in available if t.category in self.STEALTH_CATEGORIES]
        elif mode == RoutingMode.SPEED:
            available = [t for t in available if t.category in self.SPEED_CATEGORIES]
        available = sorted(available, key=lambda t: t.priority)

        for transport in available:
            result = self._try_send(transport, envelope_bytes, recipient)
            if result.success:
                return True
        return False

    def _extract_envelope_id(self, data: bytes) -> Optional[str]:
        """Best-effort extraction of envelope_id from raw bytes for dedup."""
        import json

        try:
            parsed = json.loads(data)
            return parsed.get("envelope_id")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _prune_seen_ids(self) -> None:
        """Remove expired and excess entries from the deduplication cache.

        Evicts TTL-expired entries first, then removes oldest entries
        if the cache exceeds ``SEEN_IDS_MAX`` to prevent unbounded growth.
        """
        now = time.time()
        # Remove TTL-expired entries
        expired = [eid for eid, ts in self._seen_ids.items() if now - ts > self._seen_ttl]
        for eid in expired:
            del self._seen_ids[eid]
        # Evict oldest entries if cache exceeds max size (LRU eviction)
        while len(self._seen_ids) > SEEN_IDS_MAX:
            self._seen_ids.popitem(last=False)
