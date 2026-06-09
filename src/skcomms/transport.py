"""
SKComm transport layer — pluggable delivery mechanisms.

Each transport is a pluggable module that knows how to send and
receive raw envelope bytes. The transport never sees inside the
envelope. It just delivers bytes from A to B.

Transports are the postal trucks. The envelope is the letter.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("skcomm.transport")


class TransportStatus(str, Enum):
    """Health state of a transport."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class TransportCategory(str, Enum):
    """Behavioral category for routing mode selection."""

    REALTIME = "realtime"
    FILE_BASED = "file_based"
    STEALTH = "stealth"
    OFFLINE = "offline"


class HealthStatus(BaseModel):
    """Detailed health report from a transport."""

    transport_name: str
    status: TransportStatus
    latency_ms: Optional[float] = None
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error: Optional[str] = None
    details: dict = Field(default_factory=dict)


class SendResult(BaseModel):
    """Outcome of a single send attempt through one transport."""

    success: bool
    transport_name: str
    envelope_id: str
    latency_ms: float = 0.0
    error: Optional[str] = None


class DeliveryReport(BaseModel):
    """Aggregate outcome of routing an envelope through one or more transports."""

    envelope_id: str
    delivered: bool
    attempts: list[SendResult] = Field(default_factory=list)

    @property
    def successful_transport(self) -> Optional[str]:
        """Name of the transport that delivered, if any."""
        for attempt in self.attempts:
            if attempt.success:
                return attempt.transport_name
        return None


class TransportError(Exception):
    """Raised by a transport on a send failure that warrants retry."""


class Transport(ABC):
    """Abstract base class for all SKComm transports.

    Every transport must implement five methods:
    - configure: load transport-specific settings
    - is_available: quick boolean health check
    - send: deliver envelope bytes to a recipient
    - receive: check for and return incoming envelope bytes
    - health_check: detailed health and latency report

    Attributes:
        name: Human-readable transport name (e.g., "syncthing", "file").
        priority: Lower number = higher priority in failover routing.
        category: Behavioral category for routing mode filtering.
    """

    name: str = "base"
    priority: int = 99
    category: TransportCategory = TransportCategory.FILE_BASED

    @abstractmethod
    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Transport settings from the config file.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Quick check if this transport is currently usable.

        Returns:
            True if the transport can likely send/receive right now.
        """

    @abstractmethod
    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Send encrypted envelope bytes to a recipient.

        Args:
            envelope_bytes: Serialized MessageEnvelope bytes.
            recipient: Recipient identifier (agent name or fingerprint).

        Returns:
            SendResult with success/failure and timing.
        """

    @abstractmethod
    def receive(self) -> list[bytes]:
        """Check for and return any incoming envelope bytes.

        Returns:
            List of raw envelope bytes, one per received message.
        """

    @abstractmethod
    def health_check(self) -> HealthStatus:
        """Detailed health and latency check.

        Returns:
            HealthStatus with current state, latency, and any errors.
        """
