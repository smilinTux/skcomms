"""
SKComms message models — the universal envelope format.

The envelope never changes. Only the delivery mechanism varies.
Every message gets wrapped in an envelope with identity, routing,
and metadata before touching any transport.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, Field, field_validator


class RoutingMode(str, Enum):
    """How the router selects transports for delivery."""

    FAILOVER = "failover"
    BROADCAST = "broadcast"
    STEALTH = "stealth"
    SPEED = "speed"


class MessageType(str, Enum):
    """Content type carried in the envelope payload."""

    TEXT = "text"
    FILE = "file"
    SEED = "seed"
    FEB = "feb"
    COMMAND = "command"
    ACK = "ack"
    HEARTBEAT = "heartbeat"
    WEBRTC_SIGNAL = "webrtc_signal"
    WEBRTC_FILE = "webrtc_file"
    SIGNING_REQUEST = "signing_request"
    SIGNING_RESPONSE = "signing_response"
    READ_RECEIPT = "read_receipt"


class Urgency(str, Enum):
    """Message urgency level — affects transport selection and retry."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class RoutingConfig(BaseModel):
    """Transport routing preferences for the envelope.

    Controls how the Router selects transports, retries on failure,
    and expires undeliverable messages.
    """

    mode: RoutingMode = RoutingMode.FAILOVER
    preferred_transports: list[str] = Field(default_factory=list)
    retry_max: int = 5
    retry_backoff: list[int] = Field(default_factory=lambda: [5, 15, 60, 300, 900])
    ttl: int = 86400
    ack_requested: bool = True


class MessagePayload(BaseModel):
    """The actual content of the message.

    Content is plaintext before encryption. When encrypted=True,
    the content field holds the PGP-armored ciphertext.
    """

    content: str
    content_type: Union[MessageType, str] = MessageType.TEXT
    encrypted: bool = False
    compressed: bool = False
    signature: Optional[str] = None

    @field_validator("content_type", mode="before")
    @classmethod
    def _coerce_content_type(cls, v: object) -> object:
        """Forward-compatible content_type coercion (typed-message contract).

        Known values are normalized to the :class:`MessageType` enum; any
        value we do not recognize is preserved verbatim as a plain string so
        a message kind introduced by a newer client round-trips losslessly
        and never fails validation on an older one. Unknown types degrade to
        a plain-body view (see :meth:`render`) instead of breaking.
        """
        if isinstance(v, MessageType):
            return v
        if isinstance(v, str):
            try:
                return MessageType(v)
            except ValueError:
                return v
        return v

    @property
    def is_known_type(self) -> bool:
        """True iff ``content_type`` is a recognized :class:`MessageType`."""
        return isinstance(self.content_type, MessageType)

    @property
    def content_type_str(self) -> str:
        """``content_type`` as a plain string, enum or not (display-safe)."""
        ct = self.content_type
        return ct.value if isinstance(ct, MessageType) else str(ct)

    def render(self) -> str:
        """Display text for this payload, with plain-body fallback.

        A recognized type may later gain a rich sub-view; an unrecognized
        type always falls back to the raw ``content`` body so an older client
        shows plain text instead of erroring on a newer message kind. Callers
        branch on :attr:`is_known_type` to pick a rich view.
        """
        return self.content


class MessageMetadata(BaseModel):
    """Envelope metadata for threading, deduplication, and ordering."""

    thread_id: Optional[str] = None
    in_reply_to: Optional[str] = None
    urgency: Urgency = Urgency.NORMAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    attempt: int = 0
    delivered_via: Optional[str] = None


# Maps Urgency levels to integer priorities (lower = higher urgency).
# Used by MessageEnvelope.priority and MessagePriorityQueue in core.py.
URGENCY_PRIORITY: dict[str, int] = {
    Urgency.CRITICAL: 0,
    Urgency.HIGH: 1,
    Urgency.NORMAL: 2,
    Urgency.LOW: 3,
}


class MessageEnvelope(BaseModel):
    """The universal SKComms message envelope.

    Every message — text, file, seed, FEB, command — gets wrapped
    in this envelope before touching any transport. The transport
    never sees inside. The envelope is the contract.

    Args:
        skcomms_version: Protocol version for forward compatibility.
        envelope_id: UUID v4 for deduplication across transports.
        sender: PGP fingerprint or agent name of the sender.
        recipient: PGP fingerprint or agent name of the recipient.
        payload: The encrypted/signed message content.
        routing: Transport selection and retry preferences.
        metadata: Threading, urgency, and delivery tracking.
    """

    skcomms_version: str = "1.0.0"
    envelope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender: str
    recipient: str
    payload: MessagePayload
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    metadata: MessageMetadata = Field(default_factory=MessageMetadata)

    def to_bytes(self) -> bytes:
        """Serialize the envelope to UTF-8 JSON bytes for transport.

        Returns:
            bytes: JSON-encoded envelope.
        """
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> MessageEnvelope:
        """Deserialize an envelope from UTF-8 JSON bytes.

        Args:
            data: JSON-encoded envelope bytes.

        Returns:
            MessageEnvelope: The deserialized envelope.

        Raises:
            ValueError: If the bytes are not a valid envelope.
        """
        return cls.model_validate_json(data)

    def make_read_receipt(self, sender: str) -> "MessageEnvelope":
        """Create a READ_RECEIPT envelope to tell the sender this message was read.

        Args:
            sender: The agent sending the read receipt (the reader's identity).

        Returns:
            MessageEnvelope: A READ_RECEIPT envelope referencing this message.
        """
        import json as _json

        content = _json.dumps(
            {
                "message_id": self.envelope_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        return MessageEnvelope(
            sender=sender,
            recipient=self.sender,
            payload=MessagePayload(
                content=content,
                content_type=MessageType.READ_RECEIPT,
            ),
            routing=RoutingConfig(
                mode=RoutingMode.FAILOVER,
                retry_max=2,
                ack_requested=False,
            ),
            metadata=MessageMetadata(
                in_reply_to=self.envelope_id,
                urgency=Urgency.LOW,
            ),
        )

    def make_ack(self, sender: str) -> "MessageEnvelope":
        """Create an ACK envelope in response to this message.

        Args:
            sender: The agent sending the acknowledgment.

        Returns:
            MessageEnvelope: An ACK envelope referencing this message.
        """
        return MessageEnvelope(
            sender=sender,
            recipient=self.sender,
            payload=MessagePayload(
                content=self.envelope_id,
                content_type=MessageType.ACK,
            ),
            routing=RoutingConfig(
                mode=RoutingMode.FAILOVER,
                retry_max=3,
                ack_requested=False,
            ),
            metadata=MessageMetadata(
                thread_id=self.metadata.thread_id,
                in_reply_to=self.envelope_id,
                urgency=Urgency.LOW,
            ),
        )

    @property
    def priority(self) -> int:
        """Numeric priority derived from urgency. Lower = more urgent.

        CRITICAL=0, HIGH=1, NORMAL=2, LOW=3.
        """
        return URGENCY_PRIORITY.get(self.metadata.urgency, 2)

    @property
    def is_ack(self) -> bool:
        """Check if this envelope is a delivery acknowledgment."""
        return self.payload.content_type == MessageType.ACK

    @property
    def is_expired(self) -> bool:
        """Check if this envelope has exceeded its TTL."""
        if self.metadata.expires_at:
            return datetime.now(timezone.utc) > self.metadata.expires_at
        age = (datetime.now(timezone.utc) - self.metadata.created_at).total_seconds()
        return age > self.routing.ttl
