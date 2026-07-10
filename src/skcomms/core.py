"""
SKComms — the sovereign communication engine.

High-level interface that wraps the router, transports, and
envelope creation into a clean send/receive API.
"""

from __future__ import annotations

import heapq
import importlib
import logging
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
from .crypto import CryptoError
from .transport import DeliveryReport, SendResult, Transport
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


# ---------------------------------------------------------------------------
# Signed wire format (sign-at-send)
# ---------------------------------------------------------------------------
#
# Every rail carries canonical :class:`~skcomms.envelope.SignedEnvelope` bytes
# (Envelope v1 + detached capauth signature): the ONE wire format every
# receive gate parses (``POST /api/v1/inbox`` hard-requires it and 422s
# anything else). The legacy :class:`MessageEnvelope` keeps its role as the
# LOCAL delivery/persistence model; its payload metadata rides across the
# wire in the Envelope v1 header map below and is reconstructed faithfully on
# the receiving side by :func:`envelope_v1_to_message`.
WIRE_HEADER_MESSAGE_TYPE = "x-skcomms-message-type"
WIRE_HEADER_URGENCY = "x-skcomms-urgency"
WIRE_HEADER_ENCRYPTED = "x-skcomms-encrypted"
WIRE_HEADER_COMPRESSED = "x-skcomms-compressed"
WIRE_HEADER_PAYLOAD_SIGNATURE = "x-skcomms-payload-signature"
WIRE_HEADER_ACK_REQUESTED = "x-skcomms-ack-requested"

#: Envelope v1 content types that map back to the legacy TEXT message type.
_TEXTUAL_CONTENT_TYPES = frozenset({"text/plain", "text/markdown"})


def resolve_signing_capauth_dir(agent: str) -> Optional[Path]:
    """The capauth dir holding *agent*'s signing key, or None for the default.

    Returns the per-agent layout (``~/.skcapstone/agents/<agent>/capauth``)
    only when it actually HOLDS a private key. An existing but empty
    per-agent dir must not shadow a valid operator key at ``~/.capauth``:
    the identity gate (:func:`skcomms.trustbackup.identity_check`) counts
    either key as present, so crypto resolution has to match it or that
    configuration would pass the gate green with dead crypto. ``None``
    means "use the ``~/.capauth`` default" in
    :meth:`skcomms.crypto.EnvelopeCrypto.from_capauth`.
    """
    cap_dir = Path.home() / ".skcapstone" / "agents" / str(agent) / "capauth"
    if (cap_dir / "identity" / "private.asc").is_file():
        return cap_dir
    return None


def envelope_v1_to_message(env) -> MessageEnvelope:
    """Convert a (verified) Envelope v1 into the local transport MessageEnvelope.

    The inverse of the sign-at-send wrap in :meth:`SKComms.send`: local
    delivery (file inboxes, ``comm.receive()``) speaks MessageEnvelope, so
    the Envelope v1 wire format is mapped onto it. The Envelope v1 ``id`` is
    preserved as ``envelope_id`` for dedup; payload metadata (typed content,
    encrypted/compressed flags, payload signature, urgency, ack request) is
    restored from the ``x-skcomms-*`` header map when present, so inbound
    decrypt/decompress/ack keep working end to end. Envelopes from senders
    that never set those headers (plain federation sends) fall back to a
    plaintext payload with the historical inbox-conversion defaults.

    Args:
        env: A verified :class:`~skcomms.envelope.Envelope` (v1).

    Returns:
        MessageEnvelope: The reconstructed local envelope.
    """
    headers: dict = dict(getattr(env, "headers", None) or {})

    content_type = headers.get(WIRE_HEADER_MESSAGE_TYPE) or (
        MessageType.TEXT.value
        if env.content_type in _TEXTUAL_CONTENT_TYPES
        else env.content_type
    )

    try:
        urgency = Urgency(headers.get(WIRE_HEADER_URGENCY, ""))
    except ValueError:
        urgency = Urgency.NORMAL

    # Absent header (a plain federation send) keeps the historical inbox
    # default (RoutingConfig.ack_requested = True); a sign-at-send wrap is
    # explicit either way ("1"/"0").
    ack_header = headers.get(WIRE_HEADER_ACK_REQUESTED)
    ack_requested = True if ack_header is None else ack_header == "1"

    return MessageEnvelope(
        envelope_id=env.id,
        sender=env.from_fqid,
        recipient=env.to_fqid,
        payload=MessagePayload(
            content=env.body,
            content_type=content_type,
            encrypted=headers.get(WIRE_HEADER_ENCRYPTED) == "1",
            compressed=headers.get(WIRE_HEADER_COMPRESSED) == "1",
            signature=headers.get(WIRE_HEADER_PAYLOAD_SIGNATURE) or None,
        ),
        routing=RoutingConfig(ack_requested=ack_requested),
        metadata=MessageMetadata(
            thread_id=env.thread_id,
            in_reply_to=env.reply_to,
            urgency=urgency,
        ),
    )


# Mapping of transport name to module path within skcomms.transports
BUILTIN_TRANSPORTS: dict[str, str] = {
    "file": "skcomms.transports.file",
    "syncthing": "skcomms.transports.syncthing",
    "nostr": "skcomms.transports.nostr",
    # SKFed P4 store-and-forward rail (resolves fqid→pubkey; router fallback).
    "nostr-sf": "skcomms.store_forward",
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
        # Drain any pre-existing legacy JSONL retry queue (both the old
        # core.RetryQueue and router schemas) into the PersistentOutbox, which
        # is now the single queue of record. Best-effort, non-fatal.
        try:
            from .outbox_migrate import migrate_retry_queue_jsonl

            drained = migrate_retry_queue_jsonl(outbox=instance._outbox)
            if drained["migrated"]:
                logger.info(
                    "Drained %d legacy retry_queue.jsonl entr%s into the outbox",
                    drained["migrated"],
                    "y" if drained["migrated"] == 1 else "ies",
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("legacy retry queue migration failed: %s", exc)
        instance._outbox.start()
        # SKFed P4: ensure the store-and-forward rail is registered + selected,
        # and (config-gated) start the relay pull loop. Best-effort, non-fatal.
        instance._init_store_forward()
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

    def _init_store_forward(self) -> None:
        """Wire SKFed P4 store-and-forward: register the rail + start the puller.

        Best-effort and non-fatal:
          1. Register the ``nostr-sf`` :class:`StoreForwardTransport` rail (unless
             already present) so ``Router._try_store_forward`` can use it as the
             last-resort fallback when all direct rails fail.
          2. Point the router's ``_store_forward_transport`` at ``nostr-sf``.
          3. Start the relay pull loop (config-gated on
             ``SKCOMMS_STORE_FORWARD_PULL`` + a resolvable Nostr secret).

        Any failure (missing crypto deps, no key, no relays) is swallowed so S&F
        can never take the engine down.
        """
        try:
            from .store_forward import (
                STORE_FORWARD_RAIL,
                StoreForwardTransport,
                start_pull_loop,
            )

            have = any(t.name == STORE_FORWARD_RAIL for t in self._router.transports)
            if not have:
                self._router.register_transport(StoreForwardTransport())
            # Ensure the router selects the S&F rail (not the plain "nostr" DM rail).
            self._router._store_forward_transport = STORE_FORWARD_RAIL

            # Share the HTTP inbox's nonce cache for cross-rail idempotency.
            nonce_cache = None
            try:
                from .api import _get_nonce_cache

                nonce_cache = _get_nonce_cache()
            except Exception:  # noqa: BLE001
                nonce_cache = None
            self._sf_pull_thread = start_pull_loop(nonce_cache=nonce_cache)
        except Exception as exc:  # noqa: BLE001
            logger.warning("store-forward init failed (non-fatal): %s", exc)

    def send_federated(
        self,
        to_fqid: str,
        message: str,
        *,
        content_type: str = "text/plain",
        thread_id: Optional[str] = None,
        in_reply_to: Optional[str] = None,
        mode: Optional[RoutingMode] = None,
        consent_token: Optional[str] = None,
        supersede_key: Optional[str] = None,
    ) -> DeliveryReport:
        """Send a canonical signed Envelope v1 to a remote agent (federation).

        The strategic node-to-node path: build Envelope v1 (``from_fqid`` =
        this agent, ``to_fqid`` = recipient), **sign** it with this agent's
        capauth key, best-effort route it over the selected rail (router owns
        rail ordering + store-forward), and on failure enqueue a durable copy
        to the federation outbox (authoritative retry). Nonce dedup makes
        retry/redelivery idempotent.

        Args:
            to_fqid: Recipient FQID (``<agent>@<operator>.<realm>``).
            message: Body content.
            content_type: Rail-agnostic "kind" (default ``text/plain``).
            thread_id / in_reply_to: Optional threading.
            mode: Routing mode override.
            supersede_key: Optional ephemeral-supersede key for the outbox.
                Ephemeral sends (e.g. CoT position beacons) pass a key so a
                newer undelivered copy evicts the older one instead of
                accumulating; ``None`` (default) queues durably as before.

        Returns:
            DeliveryReport for the immediate attempt.
        """
        from .envelope import Envelope
        from .identity import resolve_self_identity

        ident = resolve_self_identity()
        from_fqid = ident.get("fqid") or self._identity
        crypto = self._signing_crypto()
        if crypto is None:
            raise RuntimeError("no capauth key available to sign federation envelope")

        signed = crypto.envelope_signer().sign(
            Envelope(
                from_fqid=from_fqid,
                to_fqid=to_fqid,
                content_type=content_type,
                body=message,
                thread_id=thread_id,
                reply_to=in_reply_to,
                consent_token=consent_token,
            )
        )
        # SKFed P3: if the recipient is an unknown fqid, try to auto-discover it
        # from the Nostr directory before routing (best-effort, non-fatal).
        if "@" in to_fqid and not self._resolve_peer_transports(to_fqid):
            try:
                from .nostr_discovery import ensure_peer

                ensure_peer(to_fqid)
            except Exception as exc:  # noqa: BLE001
                logger.debug("nostr discovery for %s failed: %s", to_fqid, exc)
        preferred = self._resolve_peer_transports(to_fqid)
        report = self._router.route_signed(signed, preferred_transports=preferred, mode=mode)
        if not report.delivered:
            try:
                self._outbox.enqueue_signed(
                    signed, error="initial send failed", supersede_key=supersede_key
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("federation outbox enqueue failed: %s", exc)
        return report

    def _signing_crypto(self) -> Optional["EnvelopeCrypto"]:
        """Resolve the crypto engine holding this agent's capauth signing key.

        Prefers the injected engine; otherwise resolves the running agent's
        capauth dir (SKAGENT-aware) rather than the hardcoded ``~/.capauth``
        default, since keys live under ``~/.skcapstone/agents/<agent>/capauth``
        in the multi-agent layout.

        Returns:
            EnvelopeCrypto or None when no signing key is available.
        """
        if self._crypto is not None:
            return self._crypto
        try:
            from .crypto import EnvelopeCrypto
            from .identity import resolve_self_identity

            ident = resolve_self_identity()
            agent = ident.get("agent") or self._identity
            # Per-agent dir only when it holds a key; empty dir falls back
            # to ~/.capauth so the operator key stays usable (matches the
            # identity gate's either-key-counts semantics).
            return EnvelopeCrypto.from_capauth(resolve_signing_capauth_dir(str(agent)))
        except Exception as exc:  # noqa: BLE001
            logger.debug("capauth signing key resolution failed: %s", exc)
            return None

    def _sign_message_envelope(self, envelope: MessageEnvelope, crypto) -> "SignedEnvelope":
        """Wrap a prepared MessageEnvelope in a signed canonical Envelope v1.

        The sign-at-send seam: the legacy envelope's payload and metadata are
        lifted onto Envelope v1 (body = payload content; the local-model
        metadata rides in the ``x-skcomms-*`` header map, see
        :func:`envelope_v1_to_message`) and the result is signed with this
        agent's capauth key, producing the exact wire bytes every receive
        gate parses. The Envelope v1 ``id`` is the legacy ``envelope_id`` so
        dedup and delivery reports stay coherent across both models.

        Args:
            envelope: The fully prepared (compressed/encrypted) local envelope.
            crypto: The EnvelopeCrypto engine holding the signing key.

        Returns:
            SignedEnvelope ready to put on the wire.
        """
        from .envelope import Envelope
        from .identity import resolve_self_identity

        ident = resolve_self_identity()
        from_fqid = ident.get("fqid") or self._identity

        raw_type = envelope.payload.content_type
        type_value = raw_type.value if isinstance(raw_type, MessageType) else str(raw_type)
        headers = {
            WIRE_HEADER_MESSAGE_TYPE: type_value,
            WIRE_HEADER_URGENCY: envelope.metadata.urgency.value,
            WIRE_HEADER_ACK_REQUESTED: "1" if envelope.routing.ack_requested else "0",
        }
        if envelope.payload.encrypted:
            headers[WIRE_HEADER_ENCRYPTED] = "1"
        if envelope.payload.compressed:
            headers[WIRE_HEADER_COMPRESSED] = "1"
        if envelope.payload.signature:
            headers[WIRE_HEADER_PAYLOAD_SIGNATURE] = envelope.payload.signature

        return crypto.envelope_signer().sign(
            Envelope(
                id=envelope.envelope_id,
                from_fqid=from_fqid,
                to_fqid=envelope.recipient,
                content_type=(
                    "text/plain" if type_value == MessageType.TEXT.value else type_value
                ),
                body=envelope.payload.content,
                thread_id=envelope.metadata.thread_id,
                reply_to=envelope.metadata.in_reply_to,
                headers=headers,
            )
        )

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
        """Send a message to a recipient (sign-at-send).

        Creates the local envelope (compression and payload crypto exactly as
        before), then signs it into the canonical Envelope v1 wire format with
        this agent's capauth key, so EVERY rail carries
        :class:`~skcomms.envelope.SignedEnvelope` bytes: the one format the
        federation receive gates parse (``POST /api/v1/inbox`` 422s anything
        else). Payload metadata rides in the ``x-skcomms-*`` Envelope v1
        headers and is reconstructed on the receiving side by
        :func:`envelope_v1_to_message`.

        When no signing key is available the send falls back to the explicit
        legacy unsigned path (:meth:`_route_legacy_unsigned`), whose router leg
        (:meth:`Router.route`) never offers signed-envelope-only rails such as
        https-s2s, so an unsigned envelope can never reach a gate that would
        reject it.

        Args:
            recipient: Agent name, fqid, or PGP fingerprint of the recipient.
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
        try:
            envelope = self._apply_outbound_crypto(envelope)
        except CryptoError as exc:
            # Confidentiality was requested and could not be provided. Do NOT
            # route, do NOT enqueue (that would persist plaintext to disk):
            # fail closed with a clear not-delivered report.
            logger.error(
                "Refusing to send %s → %s: %s", envelope.envelope_id[:8], recipient, exc
            )
            _integration.alert(
                "encryption_failed",
                {"envelope_id": envelope.envelope_id[:8], "recipient": recipient, "error": str(exc)},
                level="error",
            )
            return DeliveryReport(
                envelope_id=envelope.envelope_id,
                delivered=False,
                attempts=[
                    SendResult(
                        success=False,
                        transport_name="<crypto>",
                        envelope_id=envelope.envelope_id,
                        error=f"encryption failed, not sent: {exc}",
                    )
                ],
            )

        crypto = self._signing_crypto()
        if crypto is None:
            # Explicit legacy local-only fallback: without a signing key the
            # unsigned MessageEnvelope stays on rails that accept it
            # (Router.route() excludes signed-envelope-only rails).
            logger.warning(
                "No capauth signing key available: sending %s to %s unsigned "
                "over legacy local-only rails",
                envelope.envelope_id[:8],
                recipient,
            )
            return self._route_legacy_unsigned(envelope)

        try:
            signed = self._sign_message_envelope(envelope, crypto)
        except Exception as exc:  # noqa: BLE001
            # Signing broke unexpectedly (corrupt key, signer error). Fall back
            # to the legacy local-only path rather than dropping the message.
            logger.warning(
                "Sign-at-send failed for %s (%s): falling back to legacy "
                "local-only rails",
                envelope.envelope_id[:8],
                exc,
            )
            return self._route_legacy_unsigned(envelope)

        logger.info(
            "Sending %s to %s [%s] via %s as SignedEnvelope "
            "(compressed=%s, encrypted=%s)",
            message_type.value,
            recipient,
            envelope.envelope_id[:8],
            (mode or self._config.default_mode).value,
            envelope.payload.compressed,
            envelope.payload.encrypted,
        )

        report = self._router.route_signed(
            signed,
            preferred_transports=preferred_transports,
            mode=mode or self._config.default_mode,
        )

        if not report.delivered:
            last_error = report.attempts[-1].error if report.attempts else "all transports failed"
            error_msg = last_error or "all transports failed"
            try:
                # The federation outbox understands the signed wire shape and
                # owns durable retry for it (classify_envelope_json -> "signed").
                self._outbox.enqueue_signed(signed, error=error_msg)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "outbox enqueue failed for %s: %s", envelope.envelope_id[:8], exc
                )
            logger.warning(
                "Delivery failed for %s -> %s: queued for retry",
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
        elif report.queued_only:
            # Delivered ONLY to a file/syncthing queue: not confirmed receipt.
            # Hold a durable outbox entry until an ACK confirms.
            self._hold_queued_delivery(envelope, report, signed=signed)

        if report.delivered and self._ack_tracker:
            self._ack_tracker.track(envelope)

        return report

    def _route_legacy_unsigned(self, envelope: MessageEnvelope) -> DeliveryReport:
        """Route a legacy unsigned MessageEnvelope (explicit local-only path).

        :meth:`Router.route` excludes signed-envelope-only rails (https-s2s),
        so the unsigned wire shape can never reach a gate that hard-requires a
        SignedEnvelope. On failure the envelope is queued exactly once on the
        PersistentOutbox (the single queue of record), which understands the
        legacy JSON.

        Args:
            envelope: The fully prepared local envelope.

        Returns:
            DeliveryReport with attempt results.
        """
        report = self._router.route(envelope)

        if not report.delivered:
            last_error = report.attempts[-1].error if report.attempts else "all transports failed"
            error_msg = last_error or "all transports failed"
            self._outbox.enqueue(
                envelope.envelope_id,
                envelope.recipient,
                envelope.model_dump_json(),
                error_msg,
            )
            logger.warning(
                "Delivery failed for %s -> %s: queued for retry",
                envelope.envelope_id[:8],
                envelope.recipient,
            )
            _integration.alert(
                "delivery_failed",
                {
                    "envelope_id": envelope.envelope_id[:8],
                    "recipient": envelope.recipient,
                    "error": error_msg,
                },
                level="warn",
            )
        elif report.queued_only:
            # Delivered ONLY to a file/syncthing queue: not confirmed receipt.
            # Hold a durable outbox entry until an ACK confirms.
            self._hold_queued_delivery(envelope, report)

        if report.delivered and self._ack_tracker:
            self._ack_tracker.track(envelope)

        return report

    def _hold_queued_delivery(
        self,
        envelope: MessageEnvelope,
        report: DeliveryReport,
        *,
        signed: Optional["SignedEnvelope"] = None,
    ) -> None:
        """Hold a durable outbox entry for a queued-only (sneakernet) delivery.

        A file/syncthing write hands the bytes to a shared filesystem: that is a
        QUEUE, not confirmed receipt. When the sender requested an ACK, keep a
        durable outbox entry (``await_ack=True``, so the retry sweep leaves it
        alone) so the message stays tracked. The entry is removed when the ACK
        arrives (:meth:`receive`) and surfaced via a ``delivery_failed`` alert if
        none lands within the retry horizon (:meth:`sweep_ack_timeouts`).

        No-op unless the report is queued-only AND an ACK was requested (without
        an ACK there is nothing to confirm, so nothing to hold for).

        Args:
            envelope: The MessageEnvelope that was sent.
            report: The delivery report for the send.
            signed: The SignedEnvelope actually put on the wire, if any, so the
                held bytes match what was delivered (federation shape).
        """
        if not report.queued_only or not envelope.routing.ack_requested:
            return

        transport = report.successful_transport or "queue"
        try:
            if signed is not None:
                envelope_json = signed.to_bytes().decode("utf-8")
            else:
                envelope_json = envelope.model_dump_json()
            self._outbox.enqueue(
                envelope.envelope_id,
                envelope.recipient,
                envelope_json,
                error=f"queued on {transport}; awaiting ACK",
                await_ack=True,
            )
            logger.info(
                "Held %s in outbox: queued on %s, awaiting ACK",
                envelope.envelope_id[:8],
                transport,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "outbox hold enqueue failed for %s: %s", envelope.envelope_id[:8], exc
            )

    def sweep_ack_timeouts(self) -> list:
        """Fire ``delivery_failed`` for queued sends whose ACK horizon lapsed.

        Marks expired pending ACKs as timed-out (via the ACK tracker) and, for
        each one that still has a durable outbox entry held awaiting its ACK
        (i.e. a message that reached ONLY a file/syncthing queue and was never
        confirmed received), emits a ``delivery_failed`` sk-alert and moves the
        held entry to the dead-letter queue. Confirmed sends have already had
        their held entry removed, so they never alert here.

        Returns:
            The list of PendingAck entries that just timed out.
        """
        if not self._ack_tracker:
            return []

        timed_out = self._ack_tracker.check_timeouts()
        for pending in timed_out:
            entry = self._outbox.get(pending.envelope_id)
            if entry is None:
                # No held entry: not a queued-only send we are tracking here
                # (e.g. a confirmed rail whose entry was already removed).
                continue
            error_msg = (
                "queued on file rail but no ACK within the retry horizon"
            )
            logger.warning(
                "Delivery unconfirmed for %s -> %s: %s",
                pending.envelope_id[:8],
                pending.recipient,
                error_msg,
            )
            _integration.alert(
                "delivery_failed",
                {
                    "envelope_id": pending.envelope_id[:8],
                    "recipient": pending.recipient,
                    "error": error_msg,
                },
                level="warn",
            )
            self._outbox.mark_dead(pending.envelope_id, error=error_msg)
        return timed_out

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
            # fqid recipients are stored under the bare agent name (or carry the
            # fqid in their `fqid` field) — fall back to an fqid-aware scan so
            # auto-discovered peers (SKFed P3) are honored on the send path.
            if peer is None and "@" in recipient:
                bare = recipient.split("@", 1)[0]
                peer = store.get(bare)
                if peer is None or peer.fqid not in (None, recipient):
                    for candidate in store.list_all():
                        if candidate.fqid == recipient:
                            peer = candidate
                            break
            if peer and peer.transports:
                # honor the peer's advertised rail order if present
                if peer.rails:
                    return list(peer.rails)
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

    @staticmethod
    def _parse_inbound(data: bytes) -> MessageEnvelope:
        """Deserialize inbound wire bytes into a local MessageEnvelope.

        Sign-at-send means rails now carry canonical SignedEnvelope bytes,
        but legacy MessageEnvelope files (older peers, local drops, ACKs)
        are still in circulation, so both shapes are accepted: legacy parses
        directly; a SignedEnvelope is mapped back through
        :func:`envelope_v1_to_message`. Signature VERIFICATION stays where
        it always was: at the authenticated gates (``POST /api/v1/inbox``,
        store-and-forward pull), not on the local file rails, which carry
        the same trust as the legacy unsigned drops they replace.

        Args:
            data: Raw wire bytes from a transport.

        Returns:
            MessageEnvelope for local delivery.

        Raises:
            Exception: When the bytes parse as neither wire shape.
        """
        try:
            return MessageEnvelope.from_bytes(data)
        except Exception:
            from .envelope import SignedEnvelope

            signed = SignedEnvelope.from_bytes(data)
            return envelope_v1_to_message(signed.envelope)

    def receive(self) -> list[MessageEnvelope]:
        """Check all transports for incoming messages.

        Polls every available transport, deduplicates, and deserializes.
        Accepts both wire shapes (canonical SignedEnvelope and legacy
        MessageEnvelope, see :meth:`_parse_inbound`).

        Returns:
            List of received MessageEnvelope objects.
        """
        raw_messages = self._router.receive_all()
        pq = MessagePriorityQueue()

        for data in raw_messages:
            try:
                envelope = self._parse_inbound(data)
                if envelope.is_expired:
                    logger.debug("Discarding expired envelope %s", envelope.envelope_id[:8])
                    continue
                envelope = self._apply_inbound_crypto(envelope)
                envelope = self._apply_decompression(envelope)

                if envelope.is_ack and self._ack_tracker:
                    confirmed = self._ack_tracker.process_ack(envelope)
                    if confirmed is not None:
                        # ACK confirms receipt: drop the durable outbox entry
                        # held for this queued (file/syncthing) send.
                        self._outbox.remove(confirmed.envelope_id)

                self._send_auto_ack(envelope)
                pq.push(envelope)
            except Exception as exc:
                logger.warning("Failed to deserialize incoming envelope — skipping: %s", exc)

        # Surface any queued (file-rail) sends whose ACK horizon has lapsed.
        try:
            self.sweep_ack_timeouts()
        except Exception as exc:  # noqa: BLE001 - never let the sweep break receive
            logger.warning("ACK-timeout sweep failed: %s", exc)

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
                    # PQC cut-over: negotiate hybrid X25519+ML-KEM-768 BY DEFAULT
                    # when the recipient advertises a hybrid prekey (via the
                    # crypto engine's hybrid_provider); otherwise this is exactly
                    # the classical PGP wrap (negotiated downgrade, unchanged).
                    if hasattr(self._crypto, "encrypt_payload_provider"):
                        envelope, _suite = self._crypto.encrypt_payload_provider(
                            envelope, pub_armor
                        )
                    else:
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
            # Cumulative per-rail failure counters (every failed send + the 4xx
            # subset, e.g. the inbox gate 422ing a payload). Distinct from the
            # transient cooldown state in health_report; empty until a send
            # fails. See :meth:`skcomms.router.Router.failure_stats`.
            "transport_failures": self._router.failure_stats(),
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
