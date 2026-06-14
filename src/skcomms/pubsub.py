"""
SKComms pub/sub engine — lightweight sovereign event distribution.

In-process publish/subscribe broker that enables real-time event
distribution across sovereign agents at 100+ node scale. No external
broker required. Optional transport bridge for cross-node delivery.

Topic naming convention:  <domain>.<entity>.<action>
    memory.stored           — new memory created
    memory.promoted         — memory promoted to higher tier
    agent.heartbeat         — agent alive signals
    agent.status            — status changes
    coord.task.created      — new task on coordination board
    coord.task.claimed      — task claimed by an agent
    coord.task.completed    — task marked done
    sync.push               — sync state pushed
    sync.pull               — sync state pulled
    trust.updated           — trust level changed

Wildcard matching:
    *   matches exactly one topic level   (e.g. agent.* matches agent.heartbeat)
    #   matches all remaining levels       (e.g. coord.# matches coord.task.claimed)

Usage:
    broker = PubSubBroker()
    broker.subscribe("memory.*", lambda msg: print(msg.topic))
    broker.publish("memory.stored", {"content": "hello"}, sender="opus")
"""

from __future__ import annotations

import logging
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("skcomms.pubsub")

# ---------------------------------------------------------------------------
# Predefined sovereign topics (documentation anchor — not enforced)
# ---------------------------------------------------------------------------

TOPIC_AGENT_HEARTBEAT = "agent.heartbeat"
TOPIC_AGENT_STATUS = "agent.status"
TOPIC_MEMORY_STORED = "memory.stored"
TOPIC_MEMORY_PROMOTED = "memory.promoted"
TOPIC_COORD_TASK_CREATED = "coord.task.created"
TOPIC_COORD_TASK_CLAIMED = "coord.task.claimed"
TOPIC_COORD_TASK_COMPLETED = "coord.task.completed"
TOPIC_SYNC_PUSH = "sync.push"
TOPIC_SYNC_PULL = "sync.pull"
TOPIC_TRUST_UPDATED = "trust.updated"


# ---------------------------------------------------------------------------
# PubSubMessage model
# ---------------------------------------------------------------------------


class PubSubMessage(BaseModel):
    """A single published event on the sovereign pub/sub bus.

    Attributes:
        topic: The exact topic this message was published to.
            Uses dot-notation: ``<domain>.<entity>.<action>``.
        payload: Arbitrary JSON-serialisable event data.
        sender: Agent name or identifier that published the message.
            Defaults to ``"anonymous"`` when not provided.
        timestamp: UTC datetime when the message was created.
        message_id: UUID v4 uniquely identifying this message.
    """

    topic: str
    payload: dict[str, Any] = Field(default_factory=dict)
    sender: str = "anonymous"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# Internal subscription record
# ---------------------------------------------------------------------------


class _Subscription:
    """Internal record binding a topic pattern to a callback.

    Args:
        pattern: Raw subscriber pattern (supports ``*`` and ``#``).
        callback: Callable to invoke when a matching message arrives.
    """

    __slots__ = ("pattern", "callback", "_regex")

    def __init__(self, pattern: str, callback: Callable[[PubSubMessage], Any]) -> None:
        self.pattern = pattern
        self.callback = callback
        self._regex: re.Pattern[str] = _pattern_to_regex(pattern)

    def matches(self, topic: str) -> bool:
        """Return True if *topic* satisfies this subscription's pattern.

        Args:
            topic: Exact topic string from a published message.

        Returns:
            True when the topic matches the compiled regex.
        """
        return bool(self._regex.match(topic))

    def __repr__(self) -> str:
        return f"<_Subscription pattern={self.pattern!r}>"


# ---------------------------------------------------------------------------
# Wildcard → regex compiler
# ---------------------------------------------------------------------------


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile an MQTT-style topic pattern to a Python regex.

    Rules:
        * ``*``  — matches exactly one level (no dots).
        * ``#``  — matches one or more remaining levels (must be the last segment).
        * All other regex meta-characters are escaped.

    Args:
        pattern: Topic pattern with optional ``*`` and ``#`` wildcards.

    Returns:
        Compiled regex anchored at both ends (``^...$``).

    Raises:
        ValueError: If ``#`` appears in a non-terminal position.

    Examples:
        ``agent.*``      → matches ``agent.heartbeat`` but not ``agent.x.y``
        ``coord.#``      → matches ``coord.task.claimed`` and ``coord.foo``
        ``memory.stored``→ exact match only
    """
    segments = pattern.split(".")
    parts: list[str] = []

    for i, seg in enumerate(segments):
        is_last = i == len(segments) - 1

        if seg == "#":
            if not is_last:
                raise ValueError(f"'#' wildcard must be the last segment in pattern: {pattern!r}")
            # '#' matches one or more dot-separated levels
            parts.append(r"[^.]+(\.[^.]+)*")
        elif seg == "*":
            # '*' matches exactly one level (no dots)
            parts.append(r"[^.]+")
        else:
            parts.append(re.escape(seg))

    regex = r"\.".join(parts)
    return re.compile(f"^{regex}$")


# ---------------------------------------------------------------------------
# PubSubBroker
# ---------------------------------------------------------------------------


class PubSubBroker:
    """In-process sovereign pub/sub broker.

    Thread-safe. No external dependencies. Supports wildcard topic
    patterns. Suitable for 100+ concurrent subscribers.

    The broker runs entirely in-process. For cross-node delivery use
    :class:`~skcomms.pubsub_transport.TransportBridge` to wire the broker
    to SKComms transports.

    Args:
        name: Optional human-readable label for this broker instance.

    Example::

        broker = PubSubBroker()

        def on_heartbeat(msg: PubSubMessage) -> None:
            print(f"Heartbeat from {msg.sender}")

        broker.subscribe("agent.heartbeat", on_heartbeat)
        broker.publish("agent.heartbeat", {"node": "opus"}, sender="opus")

    Predefined topics:
        - ``agent.heartbeat``      — alive signals
        - ``agent.status``         — status changes
        - ``memory.stored``        — new memory created
        - ``memory.promoted``      — memory promoted to higher tier
        - ``coord.task.created``   — new task on coordination board
        - ``coord.task.claimed``   — task claimed by agent
        - ``coord.task.completed`` — task marked done
        - ``sync.push``            — sync state pushed
        - ``sync.pull``            — sync state pulled
        - ``trust.updated``        — trust level changed
    """

    def __init__(self, name: str = "default") -> None:
        self._name = name
        # Pattern → list of _Subscription (multiple callbacks per pattern allowed)
        self._subscriptions: list[_Subscription] = []
        self._lock = threading.RLock()
        # Track which exact topics have ever had messages published
        self._published_topics: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def subscribe(self, topic: str, callback: Callable[[PubSubMessage], Any]) -> None:
        """Register a callback for messages matching *topic*.

        The same callback can be subscribed to multiple patterns.
        Adding an identical (pattern, callback) pair a second time is
        a no-op.

        Args:
            topic: Topic pattern. Supports ``*`` (one level) and
                ``#`` (all remaining levels).
            callback: Callable that receives a :class:`PubSubMessage`.
                Invoked synchronously in the publishing thread.

        Raises:
            ValueError: If ``#`` appears in a non-terminal position.

        Example::

            broker.subscribe("memory.*", handle_memory)
            broker.subscribe("coord.#", handle_coord)
            broker.subscribe("agent.heartbeat", on_heartbeat)
        """
        with self._lock:
            # Prevent duplicate registrations
            for sub in self._subscriptions:
                if sub.pattern == topic and sub.callback is callback:
                    logger.debug(
                        "Broker[%s]: duplicate subscription ignored for %r",
                        self._name,
                        topic,
                    )
                    return
            sub = _Subscription(pattern=topic, callback=callback)
            self._subscriptions.append(sub)
            logger.debug(
                "Broker[%s]: subscribed to %r (%d total)",
                self._name,
                topic,
                len(self._subscriptions),
            )

    def unsubscribe(self, topic: str, callback: Callable[[PubSubMessage], Any]) -> bool:
        """Remove a callback previously registered for *topic*.

        Args:
            topic: The exact pattern string used in :meth:`subscribe`.
            callback: The exact callable to remove (identity comparison).

        Returns:
            True if the subscription was found and removed; False otherwise.
        """
        with self._lock:
            before = len(self._subscriptions)
            self._subscriptions = [
                s
                for s in self._subscriptions
                if not (s.pattern == topic and s.callback is callback)
            ]
            removed = len(self._subscriptions) < before
            if removed:
                logger.debug("Broker[%s]: unsubscribed from %r", self._name, topic)
            else:
                logger.debug(
                    "Broker[%s]: unsubscribe no-op for %r (not found)",
                    self._name,
                    topic,
                )
            return removed

    def publish(
        self,
        topic: str,
        message: dict[str, Any],
        sender: Optional[str] = None,
    ) -> int:
        """Publish *message* to all subscribers matching *topic*.

        Callbacks are invoked synchronously in the calling thread, in
        subscription-registration order. Exceptions raised by individual
        callbacks are caught and logged; other subscribers still receive
        the message.

        Args:
            topic: Exact topic string. Must not contain wildcards.
            message: Arbitrary JSON-serialisable payload dict.
            sender: Agent name or identifier. Defaults to ``"anonymous"``.

        Returns:
            Number of callbacks that were invoked.

        Raises:
            ValueError: If *topic* contains wildcard characters.
        """
        if "*" in topic or "#" in topic:
            raise ValueError(f"Published topic must not contain wildcards: {topic!r}")

        msg = PubSubMessage(
            topic=topic,
            payload=message,
            sender=sender or "anonymous",
        )

        with self._lock:
            matching: list[_Subscription] = [s for s in self._subscriptions if s.matches(topic)]
            self._published_topics.add(topic)

        logger.debug(
            "Broker[%s]: publishing to %r → %d subscriber(s)",
            self._name,
            topic,
            len(matching),
        )

        invoked = 0
        for sub in matching:
            try:
                sub.callback(msg)
                invoked += 1
            except Exception as exc:
                logger.warning(
                    "Broker[%s]: callback for %r raised %s: %s",
                    self._name,
                    sub.pattern,
                    type(exc).__name__,
                    exc,
                )

        return invoked

    def list_topics(self) -> list[str]:
        """Return active topics that have received at least one published message.

        Includes the subscriber count for each topic.

        Returns:
            Sorted list of topic strings that have had messages published.
        """
        with self._lock:
            return sorted(self._published_topics)

    def list_subscribers(self, topic: str) -> list[str]:
        """Return the patterns of subscriptions that would match *topic*.

        Useful for inspecting which handlers will be invoked when a
        message is published to *topic*.

        Args:
            topic: Exact topic string (no wildcards).

        Returns:
            List of matching subscription patterns (may contain duplicates
            if the same pattern is registered with multiple callbacks).
        """
        with self._lock:
            return [s.pattern for s in self._subscriptions if s.matches(topic)]

    def subscriber_count(self, topic: str) -> int:
        """Return the number of callbacks that would receive messages on *topic*.

        Args:
            topic: Exact topic string (no wildcards).

        Returns:
            Count of matching subscriptions.
        """
        with self._lock:
            return sum(1 for s in self._subscriptions if s.matches(topic))

    def all_patterns(self) -> list[str]:
        """Return all registered subscription patterns (may contain duplicates).

        Returns:
            List of pattern strings in registration order.
        """
        with self._lock:
            return [s.pattern for s in self._subscriptions]

    def clear(self) -> None:
        """Remove all subscriptions and reset topic tracking.

        Primarily for testing; use with caution in production.
        """
        with self._lock:
            self._subscriptions.clear()
            self._published_topics.clear()
        logger.debug("Broker[%s]: cleared all subscriptions", self._name)

    def __repr__(self) -> str:
        with self._lock:
            return (
                f"<PubSubBroker name={self._name!r} "
                f"subscriptions={len(self._subscriptions)} "
                f"topics={len(self._published_topics)}>"
            )


# ---------------------------------------------------------------------------
# Module-level default broker (singleton convenience)
# ---------------------------------------------------------------------------

#: Module-level default broker. Import and use directly for simple cases.
#: For multi-tenant or isolated testing scenarios, instantiate your own.
_default_broker: Optional[PubSubBroker] = None
_default_lock = threading.Lock()


def get_broker() -> PubSubBroker:
    """Return the module-level default :class:`PubSubBroker`.

    Creates the broker on first call (lazy singleton).

    Returns:
        The shared default PubSubBroker instance.
    """
    global _default_broker
    if _default_broker is None:
        with _default_lock:
            if _default_broker is None:
                _default_broker = PubSubBroker(name="global")
    return _default_broker
