"""
SKComms pub/sub transport bridge — cross-node event forwarding.

Connects the in-process PubSubBroker to SKComms transports so that
published messages can propagate to remote agents across the mesh.

Architecture:
    Local publish  → PubSubBroker → TransportBridge.on_local_message()
                                  → SKComms.send() (if topic is exported)
    Remote receive → TransportBridge.inject_envelope() → broker.publish()

The bridge is intentionally lightweight:
    - Only forwards messages whose topics match configured export patterns.
    - Inbound envelopes carrying a ``pubsub_topic`` metadata field are
      automatically injected into the local broker.
    - No persistence; fire-and-forget delivery mirrors the broker's own
      synchronous dispatch model.

Usage::

    from skcomms.pubsub import PubSubBroker
    from skcomms.pubsub_transport import TransportBridge
    from skcomms.core import SKComms

    broker = PubSubBroker()
    comm   = SKComms.from_config()

    bridge = TransportBridge(
        broker=broker,
        comm=comm,
        export_patterns=["agent.#", "coord.#"],
        remote_agents=["lumina", "jarvis"],
    )
    bridge.start()

    # Now any publish to "agent.heartbeat" will be forwarded via SKComms
    broker.publish("agent.heartbeat", {"state": "active"}, sender="opus")
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Optional

from .pubsub import PubSubBroker, PubSubMessage, _pattern_to_regex

logger = logging.getLogger("skcomms.pubsub_transport")

# SKComms message type tag used to identify pub/sub envelopes
PUBSUB_CONTENT_TYPE_TAG = "pubsub"


class TransportBridge:
    """Bridges a local PubSubBroker to SKComms transports for remote delivery.

    Listens to a set of export topic patterns on the local broker and
    forwards matching messages to a list of remote agents via SKComms.
    Also provides :meth:`inject_envelope` to push inbound envelopes
    (received from transports) back into the local broker.

    Args:
        broker: The local :class:`~skcomms.pubsub.PubSubBroker` to connect.
        comm: An initialised :class:`~skcomms.core.SKComms` instance used
            for outbound delivery. If ``None``, the bridge operates in
            local-only mode (inject still works; forward is a no-op).
        export_patterns: Topic patterns whose messages should be forwarded
            to remote agents. Supports ``*`` and ``#`` wildcards.
            Default: ``[]`` (nothing exported).
        remote_agents: List of agent names to forward messages to.
            Each published message matching an export pattern is sent to
            all agents in this list.
        inject_sender_prefix: When a remote message is injected into the
            broker, the ``sender`` field is prefixed with this string so
            consumers can distinguish remote from local events.
            Default: ``"remote:"``

    Example::

        bridge = TransportBridge(
            broker=broker,
            comm=comm,
            export_patterns=["sync.#", "coord.task.#"],
            remote_agents=["lumina"],
        )
        bridge.start()
    """

    def __init__(
        self,
        broker: PubSubBroker,
        comm: Any = None,
        export_patterns: Optional[list[str]] = None,
        remote_agents: Optional[list[str]] = None,
        inject_sender_prefix: str = "remote:",
    ) -> None:
        self._broker = broker
        self._comm = comm
        self._export_patterns = export_patterns or []
        self._remote_agents = remote_agents or []
        self._inject_sender_prefix = inject_sender_prefix
        self._lock = threading.Lock()
        self._running = False
        # Pre-compile export pattern regexes for fast matching
        self._export_regexes = [_pattern_to_regex(p) for p in self._export_patterns]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register the bridge as a subscriber on all export patterns.

        After calling this, any message published to a matching topic
        on the local broker will be automatically forwarded to all
        configured remote agents.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        with self._lock:
            if self._running:
                return
            for pattern in self._export_patterns:
                self._broker.subscribe(pattern, self._on_local_message)
            self._running = True
            logger.info(
                "TransportBridge started — export_patterns=%r, remote_agents=%r",
                self._export_patterns,
                self._remote_agents,
            )

    def stop(self) -> None:
        """Unregister from all export patterns on the local broker.

        After calling this, no further forwarding occurs.
        """
        with self._lock:
            if not self._running:
                return
            for pattern in self._export_patterns:
                self._broker.unsubscribe(pattern, self._on_local_message)
            self._running = False
            logger.info("TransportBridge stopped")

    # ------------------------------------------------------------------
    # Outbound: local → remote
    # ------------------------------------------------------------------

    def _on_local_message(self, msg: PubSubMessage) -> None:
        """Callback invoked by the broker when a matching message is published.

        Serialises the :class:`~skcomms.pubsub.PubSubMessage` and sends
        it to all configured remote agents via SKComms.

        Args:
            msg: The published message from the local broker.
        """
        if not self._comm:
            logger.debug("TransportBridge: no comm configured — skipping forward")
            return

        if not self._remote_agents:
            return

        # Serialise the pub/sub message as JSON content
        content = msg.model_dump_json()

        for agent in self._remote_agents:
            try:
                from .models import MessageType

                self._comm.send(
                    recipient=agent,
                    message=content,
                    message_type=MessageType.COMMAND,
                )
                logger.debug("TransportBridge: forwarded %r to %r", msg.topic, agent)
            except Exception as exc:
                logger.warning("TransportBridge: forward to %r failed: %s", agent, exc)

    # ------------------------------------------------------------------
    # Inbound: remote → local broker
    # ------------------------------------------------------------------

    def inject_envelope(self, envelope: Any) -> bool:
        """Parse an inbound SKComms envelope and inject it into the local broker.

        Expects the envelope payload content to be a JSON-serialised
        :class:`~skcomms.pubsub.PubSubMessage`. If the content cannot be
        parsed, the envelope is silently skipped.

        Args:
            envelope: A :class:`~skcomms.models.MessageEnvelope` received
                from any SKComms transport.

        Returns:
            True if the message was successfully injected; False otherwise.
        """
        try:
            content = envelope.payload.content
            data = json.loads(content)

            # Require a "topic" field to treat as pub/sub
            if "topic" not in data:
                return False

            msg = PubSubMessage.model_validate(data)
            # Prefix sender so consumers know this came from a remote node
            msg = msg.model_copy(update={"sender": f"{self._inject_sender_prefix}{msg.sender}"})

            self._broker.publish(
                topic=msg.topic,
                message=msg.payload,
                sender=msg.sender,
            )
            logger.debug(
                "TransportBridge: injected remote message on %r from %r",
                msg.topic,
                envelope.sender,
            )
            return True

        except Exception as exc:
            logger.debug(
                "TransportBridge: inject_envelope skipped (%s: %s)",
                type(exc).__name__,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # Configuration inspection
    # ------------------------------------------------------------------

    def matches_export(self, topic: str) -> bool:
        """Check if *topic* would be forwarded by this bridge.

        Args:
            topic: Exact topic string (no wildcards).

        Returns:
            True if any export pattern matches *topic*.
        """
        return any(r.match(topic) for r in self._export_regexes)

    def add_remote_agent(self, agent: str) -> None:
        """Add an agent to the forwarding list at runtime.

        Args:
            agent: Agent name to add.
        """
        with self._lock:
            if agent not in self._remote_agents:
                self._remote_agents.append(agent)

    def remove_remote_agent(self, agent: str) -> bool:
        """Remove an agent from the forwarding list.

        Args:
            agent: Agent name to remove.

        Returns:
            True if the agent was present and removed; False otherwise.
        """
        with self._lock:
            try:
                self._remote_agents.remove(agent)
                return True
            except ValueError:
                return False

    @property
    def export_patterns(self) -> list[str]:
        """Currently configured export patterns (read-only copy)."""
        return list(self._export_patterns)

    @property
    def remote_agents(self) -> list[str]:
        """Currently configured remote agents (read-only copy)."""
        with self._lock:
            return list(self._remote_agents)

    @property
    def is_running(self) -> bool:
        """True if the bridge is registered with the broker."""
        return self._running

    def __repr__(self) -> str:
        return (
            f"<TransportBridge running={self._running} "
            f"export_patterns={self._export_patterns!r} "
            f"remote_agents={self._remote_agents!r}>"
        )
