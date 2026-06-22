"""
SKComms — the sovereign communication engine.

High-level interface that wraps the router, transports, and
envelope creation into a clean send/receive API.
"""

from __future__ import annotations

import heapq
import importlib
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .config import SKCommsConfig, load_config
from .discovery import PeerStore
from .models import (
    MessageEnvelope,
    MessageMetadata,
    MessagePayload,
    MessageType,
    RoutingConfig,
    RoutingMode,
    Urgency,
)
from .outbox import PersistentOutbox
from .router import Router
from .transport import DeliveryReport, Transport
from . import integration as _integration

logger = logging.getLogger("skcomms.core")


class MessagePriorityQueue:
    """Min-heap priority queue for MessageEnvelope objects.

    Envelopes with lower priority numbers (higher urgency) are dequeued
    first. Within the same priority level, insertion order is preserved
    (FIFO).

    Priority mapping: CRITICAL=0, HIGH=1, NORMAL=2, LOW=3.
    """

    def __init__(self) -> None:
        self._heap: list[tuple[int, int, MessageEnvelope]] = []
        self._counter: int = 0  # tie-breaker to enforce FIFO within same priority

    def push(self, envelope: MessageEnvelope) -> None:
        """Push an envelope onto the priority queue.

        Args:
            envelope: The envelope to enqueue.
        """
        heapq.heappush(self._heap, (envelope.priority, self._counter, envelope))
        self._counter += 1

    def pop(self) -> MessageEnvelope:
        """Pop the highest-priority envelope (lowest priority integer).

        Returns:
            MessageEnvelope with the highest urgency.

        Raises:
            IndexError: If the queue is empty.
        """
        _, _, envelope = heapq.heappop(self._heap)
        return envelope

    def drain(self) -> list[MessageEnvelope]:
        """Return all envelopes in priority order and clear the queue.

        Returns:
            List of MessageEnvelope objects ordered CRITICAL→HIGH→NORMAL→LOW.
        """
        result: list[MessageEnvelope] = []
        while self._heap:
            result.append(self.pop())
        return result

    def __len__(self) -> int:
        return len(self._heap)


_RETRY_QUEUE_PATH = Path("~/.skcapstone/retry_queue.jsonl")
_RETRY_MAX_ATTEMPTS = 10
_RETRY_BASE_BACKOFF = 1  # seconds
_RETRY_MAX_BACKOFF = 60  # seconds


class RetryQueue:
    """Lightweight JSONL-backed retry queue with fast exponential backoff.

    On transport failure, the failed envelope is appended to
    ``~/.skcapstone/retry_queue.jsonl`` as a single JSON line.  A
    background daemon thread polls every second and re-attempts delivery
    using the backoff schedule 1s → 2s → 4s → … → 60s (max).  After
    ``_RETRY_MAX_ATTEMPTS`` (10) total attempts the entry is silently
    dropped with a warning log.

    The JSONL file location (``~/.skcapstone/``) makes the queue visible
    to ``skcapstone`` tooling for dashboard / coordination use.

    This queue complements (not replaces) the heavier
    :class:`~skcomms.outbox.PersistentOutbox` — it is optimised for fast
    transient failures that resolve within a minute.

    Args:
        router: The SKComms Router used for retry delivery.
        queue_path: Override the default JSONL path (useful in tests).
    """

    def __init__(
        self,
        router: Optional[object] = None,
        queue_path: Optional[Path] = None,
    ) -> None:
        self._path = (queue_path or _RETRY_QUEUE_PATH).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._router = router
        self._lock = threading.Lock()
        self._stop_event: Optional[threading.Event] = None
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue(
        self,
        envelope_id: str,
        recipient: str,
        envelope_json: str,
        error: str = "",
    ) -> None:
        """Append a failed envelope to the retry queue.

        Thread-safe.  The entry is appended as a single JSON line to
        ``~/.skcapstone/retry_queue.jsonl``.

        Args:
            envelope_id: The envelope's unique ID.
            recipient: Target agent/peer name.
            envelope_json: Full serialised envelope JSON string.
            error: Error message from the failed delivery attempt.
        """
        now = datetime.now(timezone.utc)
        entry = {
            "envelope_id": envelope_id,
            "recipient": recipient,
            "envelope_json": envelope_json,
            "attempt": 1,
            "max_attempts": _RETRY_MAX_ATTEMPTS,
            "next_retry_at": (now + timedelta(seconds=_RETRY_BASE_BACKOFF)).isoformat(),
            "last_error": error,
            "queued_at": now.isoformat(),
        }
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        logger.debug(
            "RetryQueue: queued %s for retry (error: %s)",
            envelope_id[:8],
            error[:80],
        )

    def start(self) -> None:
        """Start the background retry worker daemon thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._retry_loop,
            daemon=True,
            name="skcomms-retry-queue",
        )
        self._thread.start()
        logger.debug("RetryQueue worker started")

    def stop(self) -> None:
        """Stop the background retry worker thread (best-effort)."""
        if self._stop_event:
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _retry_loop(self) -> None:
        """Daemon loop: sweep the queue every second."""
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            try:
                self._sweep()
            except Exception as exc:
                logger.warning("RetryQueue sweep error: %s", exc)
            self._stop_event.wait(timeout=1)

    def _sweep(self) -> None:
        """Process all entries whose ``next_retry_at`` has elapsed.

        Strategy to avoid a lock-during-I/O race:

        1. **Drain phase** — acquire lock, read the file, clear it to
           empty (so concurrent ``enqueue()`` calls go to a fresh file),
           release lock.
        2. **Process phase** — iterate entries without any lock; attempt
           delivery for due entries; compute new state for entries that
           need another retry.
        3. **Flush phase** — acquire lock, read any lines written during
           the process phase, prepend our kept lines, write the merged
           result, release lock.
        """
        if not self._path.exists():
            return

        # Phase 1: drain
        with self._lock:
            try:
                raw = self._path.read_text(encoding="utf-8")
                self._path.write_text("", encoding="utf-8")
            except OSError:
                return

        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if not lines:
            return

        now = datetime.now(timezone.utc)
        keep: list[str] = []

        for line in lines:
            try:
                entry: dict = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("RetryQueue: skipping corrupt entry")
                continue

            next_retry = datetime.fromisoformat(entry["next_retry_at"])
            if next_retry > now:
                keep.append(json.dumps(entry))
                continue

            # Due for retry
            delivered = self._attempt_delivery(entry)
            if delivered:
                logger.info(
                    "RetryQueue: delivered %s on attempt %d",
                    entry["envelope_id"][:8],
                    entry["attempt"],
                )
                continue  # drop from queue

            attempt = entry["attempt"] + 1
            if attempt > entry["max_attempts"]:
                logger.warning(
                    "RetryQueue: giving up on %s after %d attempts — last error: %s",
                    entry["envelope_id"][:8],
                    entry["attempt"],
                    entry.get("last_error", "unknown"),
                )
                continue  # drop from queue (exhausted)

            backoff = min(
                _RETRY_BASE_BACKOFF * (2 ** (attempt - 1)),
                _RETRY_MAX_BACKOFF,
            )
            entry["attempt"] = attempt
            entry["next_retry_at"] = (now + timedelta(seconds=backoff)).isoformat()
            keep.append(json.dumps(entry))

        # Phase 3: flush — prepend kept entries to any newly appended ones
        if not keep:
            return
        with self._lock:
            try:
                new_lines = self._path.read_text(encoding="utf-8")
                self._path.write_text(
                    "\n".join(keep) + "\n" + new_lines,
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.warning("RetryQueue: failed to flush queue: %s", exc)

    def _attempt_delivery(self, entry: dict) -> bool:
        """Try to deliver a queued entry via the router.

        Args:
            entry: The mutable queue entry dict (``last_error`` is
                updated in-place on failure).

        Returns:
            True if delivery succeeded.
        """
        if self._router is None:
            return False
        try:
            from .models import MessageEnvelope

            envelope = MessageEnvelope.from_bytes(entry["envelope_json"].encode("utf-8"))
            report = self._router.route(envelope)
            delivered = getattr(report, "delivered", False)
            if not delivered and report.attempts:
                entry["last_error"] = report.attempts[-1].error or "delivery failed"
            return delivered
        except Exception as exc:
            entry["last_error"] = str(exc)
            logger.debug(
                "RetryQueue: attempt failed for %s: %s",
                entry["envelope_id"][:8],
                exc,
            )
            return False


# Mapping of transport name to module path within skcomms.transports
BUILTIN_TRANSPORTS: dict[str, str] = {
    "file": "skcomms.transports.file",
    "syncthing": "skcomms.transports.syncthing",
    "nostr": "skcomms.transports.nostr",
    "websocket": "skcomms.transports.websocket",
    "tailscale": "skcomms.transports.tailscale",
    "https-s2s": "skcomms.transports.http_s2s",
    "webrtc": "skcomms.transports.webrtc",
}


class SKComms:
    """The sovereign communication engine.

    Wraps envelope creation, transport routing, and message
    reception into a simple API. Optionally encrypts and signs
    all outbound envelopes via CapAuth PGP keys.

    Usage:
        comm = SKComms.from_config("~/.skcapstone/skcomms/config.yml")
        comm.send("lumina", "Hello from Opus")
        messages = comm.receive()

    Args:
        config: SKCommsConfig instance with all settings.
        router: Optional pre-configured Router.
        crypto: Optional EnvelopeCrypto for PGP encrypt/sign.
        keystore: Optional KeyStore for peer public keys.
    """

    def __init__(
        self,
        config: Optional[SKCommsConfig] = None,
        router: Optional[Router] = None,
        crypto: Optional["EnvelopeCrypto"] = None,
        keystore: Optional["KeyStore"] = None,
    ):
        self._config = config or SKCommsConfig()
        self._router = router or Router(default_mode=self._config.default_mode)
        self._identity = self._config.identity.name
        self._crypto = crypto
        self._keystore = keystore
        self._ack_tracker = None
        if self._config.ack:
            from .ack import AckTracker

            self._ack_tracker = AckTracker()
        self._outbox = PersistentOutbox(router=self._router)
        self._retry_queue = RetryQueue(router=self._router)

    @classmethod
    def from_config(cls, config_path: Optional[str] = None) -> SKComms:
        """Create an SKComms instance from a YAML config file.

        Loads the config, discovers and registers configured transports.
        Auto-initializes CapAuth encryption if keys are available and
        config enables encrypt/sign.

        Args:
            config_path: Path to config file. Defaults to ~/.skcapstone/skcomms/config.yml.

        Returns:
            Configured SKComms instance ready to send and receive.
        """
        config = load_config(config_path)
        router = Router(default_mode=config.default_mode)

        for name, tconf in config.transports.items():
            if not tconf.enabled:
                continue
            transport = _load_transport(name, tconf.priority, tconf.settings)
            if transport:
                # Tell transports the local identity so they can pick up
                # messages addressed to us (e.g. outbox/{my_name}/ dirs
                # arriving via bidirectional Syncthing sync).
                if hasattr(transport, "_set_identity"):
                    transport._set_identity(config.identity.name)
                router.register_transport(transport)

        crypto = None
        keystore = None
        if config.encrypt or config.sign:
            crypto, keystore = _init_crypto()

        instance = cls(config=config, router=router, crypto=crypto, keystore=keystore)
        instance._outbox.start()
        instance._retry_queue.start()
        crypto_status = "enabled" if crypto else "disabled"
        logger.info(
            "SKComms initialized as '%s' with %d transports, crypto %s",
            config.identity.name,
            len(router.transports),
            crypto_status,
        )
        return instance

    @property
    def identity(self) -> str:
        """This agent's name/identifier."""
        return self._identity

    @property
    def router(self) -> Router:
        """The underlying Router instance."""
        return self._router

    def register_transport(self, transport: Transport) -> None:
        """Register an additional transport at runtime.

        Args:
            transport: A configured Transport instance.
        """
        self._router.register_transport(transport)

    def send(
        self,
        recipient: str,
        message: str,
        *,
        message_type: MessageType = MessageType.TEXT,
        mode: Optional[RoutingMode] = None,
        thread_id: Optional[str] = None,
        in_reply_to: Optional[str] = None,
        urgency: Urgency = Urgency.NORMAL,
    ) -> DeliveryReport:
        """Send a message to a recipient.

        Creates an envelope, routes it through available transports.

        Args:
            recipient: Agent name or PGP fingerprint of the recipient.
            message: The message content (plaintext).
            message_type: Type of content being sent.
            mode: Override the default routing mode.
            thread_id: Optional conversation thread ID.
            in_reply_to: Optional envelope_id this is a reply to.
            urgency: Message urgency level.

        Returns:
            DeliveryReport with attempt results.
        """
        preferred_transports = self._resolve_peer_transports(recipient)

        envelope = MessageEnvelope(
            sender=self._identity,
            recipient=recipient,
            payload=MessagePayload(
                content=message,
                content_type=message_type,
            ),
            routing=RoutingConfig(
                mode=mode or self._config.default_mode,
                retry_max=self._config.retry_max,
                retry_backoff=self._config.retry_backoff,
                ttl=self._config.ttl,
                ack_requested=self._config.ack,
                preferred_transports=preferred_transports,
            ),
            metadata=MessageMetadata(
                thread_id=thread_id,
                in_reply_to=in_reply_to,
                urgency=urgency,
            ),
        )

        envelope = self._apply_compression(envelope)
        envelope = self._apply_outbound_crypto(envelope)

        logger.info(
            "Sending %s to %s [%s] via %s (compressed=%s, encrypted=%s, signed=%s)",
            message_type.value,
            recipient,
            envelope.envelope_id[:8],
            (mode or self._config.default_mode).value,
            envelope.payload.compressed,
            envelope.payload.encrypted,
            bool(envelope.payload.signature),
        )

        report = self._router.route(envelope)

        if not report.delivered:
            last_error = report.attempts[-1].error if report.attempts else "all transports failed"
            error_msg = last_error or "all transports failed"
            self._outbox.enqueue(
                envelope.envelope_id,
                recipient,
                envelope.model_dump_json(),
                error_msg,
            )
            self._retry_queue.enqueue(
                envelope.envelope_id,
                recipient,
                envelope.model_dump_json(),
                error_msg,
            )
            logger.warning(
                "Delivery failed for %s → %s — queued for retry",
                envelope.envelope_id[:8],
                recipient,
            )
            _integration.alert(
                "delivery_failed",
                {
                    "envelope_id": envelope.envelope_id[:8],
                    "recipient": recipient,
                    "error": error_msg,
                },
                level="warn",
            )

        if report.delivered and self._ack_tracker:
            self._ack_tracker.track(envelope)

        return report

    def _resolve_peer_transports(self, recipient: str) -> list[str]:
        """Look up the preferred transports for a recipient from the peer store.

        Checks ~/.skcapstone/skcomms/peers/<name>.yml for a list of configured transports.
        Returns transport names the router should prefer for this recipient.

        Args:
            recipient: Agent name or fingerprint to resolve.

        Returns:
            list[str]: Preferred transport names (may be empty).
        """
        try:
            store = PeerStore()
            peer = store.get(recipient)
            if peer and peer.transports:
                return [t.transport for t in peer.transports]
        except Exception as exc:
            logger.debug("Peer store lookup failed for '%s': %s", recipient, exc)
        return []

    def send_envelope(self, envelope: MessageEnvelope) -> DeliveryReport:
        """Send a pre-built envelope directly.

        Useful for forwarding, ACKs, or envelopes built externally.

        Args:
            envelope: A fully constructed MessageEnvelope.

        Returns:
            DeliveryReport with attempt results.
        """
        return self._router.route(envelope)

    def receive(self) -> list[MessageEnvelope]:
        """Check all transports for incoming messages.

        Polls every available transport, deduplicates, and deserializes.

        Returns:
            List of received MessageEnvelope objects.
        """
        raw_messages = self._router.receive_all()
        pq = MessagePriorityQueue()

        for data in raw_messages:
            try:
                envelope = MessageEnvelope.from_bytes(data)
                if envelope.is_expired:
                    logger.debug("Discarding expired envelope %s", envelope.envelope_id[:8])
                    continue
                envelope = self._apply_inbound_crypto(envelope)
                envelope = self._apply_decompression(envelope)

                if envelope.is_ack and self._ack_tracker:
                    self._ack_tracker.process_ack(envelope)

                self._send_auto_ack(envelope)
                pq.push(envelope)
            except Exception as exc:
                logger.warning("Failed to deserialize incoming envelope — skipping: %s", exc)

        envelopes = pq.drain()
        logger.info("Received %d message(s)", len(envelopes))
        return envelopes

    def _apply_outbound_crypto(self, envelope: MessageEnvelope) -> MessageEnvelope:
        """Encrypt and/or sign an outbound envelope if crypto is available.

        Args:
            envelope: The envelope to protect.

        Returns:
            MessageEnvelope: Possibly encrypted/signed copy.
        """
        if not self._crypto:
            return envelope

        if self._config.sign and not envelope.payload.signature:
            envelope = self._crypto.sign_payload(envelope)

        if self._config.encrypt and not envelope.payload.encrypted:
            if self._keystore and self._keystore.has_key(envelope.recipient):
                pub_armor = self._keystore.get_public_key(envelope.recipient)
                if pub_armor:
                    envelope = self._crypto.encrypt_payload(envelope, pub_armor)

        return envelope

    def _apply_inbound_crypto(self, envelope: MessageEnvelope) -> MessageEnvelope:
        """Decrypt an inbound envelope if it's encrypted.

        Args:
            envelope: The received envelope.

        Returns:
            MessageEnvelope: Decrypted copy if encrypted, otherwise unchanged.
        """
        if not self._crypto:
            return envelope

        if envelope.payload.encrypted:
            envelope = self._crypto.decrypt_payload(envelope)

        return envelope

    def _send_auto_ack(self, envelope: MessageEnvelope) -> None:
        """Automatically send an ACK for messages that request one.

        Args:
            envelope: The received envelope to potentially acknowledge.
        """
        from .ack import should_ack

        if not should_ack(envelope):
            return

        ack = envelope.make_ack(self._identity)
        try:
            self._router.route(ack)
            logger.debug("Sent auto-ACK for %s to %s", envelope.envelope_id[:8], envelope.sender)
        except Exception as exc:
            logger.warning("Failed to send auto-ACK for %s: %s", envelope.envelope_id[:8], exc)

    @staticmethod
    def _apply_compression(envelope: MessageEnvelope) -> MessageEnvelope:
        """Compress an outbound envelope's payload if worthwhile.

        Args:
            envelope: The envelope to compress.

        Returns:
            MessageEnvelope with compressed content, or unchanged if too small.
        """
        from .compression import compress_payload

        return compress_payload(envelope)

    @staticmethod
    def _apply_decompression(envelope: MessageEnvelope) -> MessageEnvelope:
        """Decompress an inbound envelope's payload if compressed.

        Args:
            envelope: The received envelope.

        Returns:
            MessageEnvelope with decompressed content, or unchanged.
        """
        from .compression import decompress_payload

        return decompress_payload(envelope)

    def status(self) -> dict:
        """Get the current status of SKComms.

        Returns:
            Dict with identity, transport health, crypto state, and config summary.
        """
        crypto_info = {
            "available": self._crypto is not None,
            "encrypt_enabled": self._config.encrypt,
            "sign_enabled": self._config.sign,
            "fingerprint": self._crypto.fingerprint if self._crypto else None,
            "known_peers": self._keystore.known_peers if self._keystore else [],
        }

        return {
            "version": self._config.version,
            "identity": self._config.identity.model_dump(),
            "default_mode": self._config.default_mode.value,
            "transports": self._router.health_report(),
            "transport_count": len(self._router.transports),
            "encrypt": self._config.encrypt,
            "sign": self._config.sign,
            "crypto": crypto_info,
        }


# Deprecated alias — external code may still `from skcomms.core import SKComm`.
SKComm = SKComms


def _init_crypto():
    """Initialize CapAuth-based encryption from the local profile.

    Returns:
        tuple: (EnvelopeCrypto or None, KeyStore or None).
    """
    try:
        from .crypto import EnvelopeCrypto, KeyStore

        crypto = EnvelopeCrypto.from_capauth()
        keystore = KeyStore()
        return crypto, keystore
    except ImportError:
        logger.debug("skcomms.crypto not available")
        return None, None
    except Exception as exc:
        logger.debug("Crypto init failed: %s", exc)
        return None, None


def _load_transport(name: str, priority: int, settings: dict) -> Optional[Transport]:
    """Attempt to load and configure a transport by name.

    Args:
        name: Transport name (e.g., "syncthing", "file").
        priority: Transport priority for routing.
        settings: Transport-specific configuration dict.

    Returns:
        Configured Transport instance, or None on failure.
    """
    module_path = BUILTIN_TRANSPORTS.get(name)
    if not module_path:
        logger.warning("Unknown transport '%s' — skipping", name)
        return None

    try:
        module = importlib.import_module(module_path)
        transport_cls = getattr(module, "create_transport", None)
        if transport_cls is None:
            logger.warning("Transport module '%s' has no create_transport() — skipping", name)
            return None
        transport = transport_cls(priority=priority, **settings)
        return transport
    except ImportError:
        logger.debug("Transport '%s' not yet implemented — skipping", name)
        return None
    except Exception:
        logger.exception("Failed to load transport '%s'", name)
        return None
