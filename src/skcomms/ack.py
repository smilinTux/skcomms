"""
SKComms delivery acknowledgment tracker.

When a message is sent with ack_requested=True, the sender
records it as "pending ACK." When the receiver processes the
message, it automatically sends an ACK envelope back. When
the original sender receives the ACK, the pending entry is
resolved as "confirmed."

Pending ACKs that exceed the timeout are marked "timed_out"
and can be retried or escalated.

Persistence: pending ACKs are stored as JSON in ~/.skcapstone/skcomms/acks/
so they survive process restarts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from pydantic import BaseModel, Field

from .config import SKCOMMS_HOME
from .models import MessageEnvelope

logger = logging.getLogger("skcomms.ack")

ACKS_DIR_NAME = "acks"
ACK_SUFFIX = ".ack.json"
DEFAULT_ACK_TIMEOUT = 300


class AckStatus(str, Enum):
    """State of a pending acknowledgment."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    TIMED_OUT = "timed_out"


class PendingAck(BaseModel):
    """A tracked outbound message awaiting acknowledgment.

    Attributes:
        envelope_id: ID of the sent message.
        recipient: Who the message was sent to.
        sent_at: When the message was sent.
        ack_timeout: Seconds to wait for an ACK.
        status: Current ACK state.
        confirmed_at: When the ACK was received.
        confirmed_via: Transport that delivered the ACK.
    """

    envelope_id: str
    recipient: str
    sent_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ack_timeout: int = DEFAULT_ACK_TIMEOUT
    status: AckStatus = AckStatus.PENDING
    confirmed_at: Optional[datetime] = None
    confirmed_via: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        """Check if this ACK has timed out."""
        if self.status != AckStatus.PENDING:
            return False
        age = (datetime.now(timezone.utc) - self.sent_at).total_seconds()
        return age > self.ack_timeout


class AckTracker:
    """Tracks outbound messages awaiting delivery acknowledgment.

    Persists pending ACKs as JSON files. Resolves them when
    matching ACK envelopes are received. Detects timeouts.

    Args:
        acks_dir: Directory for ACK tracking files.
        default_timeout: Default seconds to wait for ACK.
        sender_verifier: Optional callable authenticating an ACK envelope
            against its claimed sender (CapAuth/PGP signature). Fails closed.
    """

    def __init__(
        self,
        acks_dir: Optional[Path] = None,
        default_timeout: int = DEFAULT_ACK_TIMEOUT,
        sender_verifier: Optional[Callable[[MessageEnvelope], bool]] = None,
    ):
        self._dir = acks_dir or Path(SKCOMMS_HOME).expanduser() / ACKS_DIR_NAME
        self._dir.mkdir(parents=True, exist_ok=True)
        self._default_timeout = default_timeout
        # Optional cryptographic authenticator for inbound ACKs. Given the ACK
        # envelope, returns True iff the ACK is authenticated (e.g. its CapAuth/
        # PGP signature verifies) as coming from its claimed sender. When wired
        # in, string identity alone is not trusted. Reuses the existing signing
        # stack (skcomms.signing.EnvelopeVerifier) — no new crypto scheme.
        self._sender_verifier = sender_verifier

    @property
    def acks_dir(self) -> Path:
        """Path to the ACK tracking directory."""
        return self._dir

    def track(self, envelope: MessageEnvelope) -> Optional[PendingAck]:
        """Begin tracking an outbound message for ACK.

        Only tracks if ack_requested is True on the envelope.

        Args:
            envelope: The sent message envelope.

        Returns:
            PendingAck if tracking started, None if ACK not requested.
        """
        if not envelope.routing.ack_requested:
            return None
        if envelope.is_ack:
            return None

        pending = PendingAck(
            envelope_id=envelope.envelope_id,
            recipient=envelope.recipient,
            ack_timeout=self._default_timeout,
        )

        path = self._dir / f"{envelope.envelope_id}{ACK_SUFFIX}"
        path.write_text(pending.model_dump_json(indent=2))
        logger.debug("Tracking ACK for %s -> %s", envelope.envelope_id[:8], envelope.recipient)
        return pending

    @staticmethod
    def _identity_matches(a: str, b: str) -> bool:
        """Compare two CapAuth identities (agent name or PGP fingerprint).

        Whitespace- and case-insensitive: a PGP fingerprint may be stored
        spaced or unspaced as it crosses different transports. Empty values
        never match (fail closed).
        """
        if not a or not b:
            return False
        return a.replace(" ", "").casefold() == b.replace(" ", "").casefold()

    def process_ack(self, ack_envelope: MessageEnvelope) -> Optional[PendingAck]:
        """Process a received ACK envelope and resolve the pending entry.

        The ACK's content holds the original envelope_id. Before an ACK is
        allowed to confirm delivery it is bound to the sender identity and
        checked for replay:

        * **Sender binding (anti-forgery).** Only the party the original
          message was delivered to (``pending.recipient``) may acknowledge it.
          An ACK whose ``sender`` is not that recipient is rejected, so a third
          party cannot forge a delivery confirmation just by learning the
          ``envelope_id``.
        * **Cryptographic authentication (optional).** When a ``sender_verifier``
          is wired in, the ACK's CapAuth/PGP signature must authenticate its
          claimed sender; string identity alone is not trusted. Fails closed.
        * **Replay / stale rejection.** An ACK may confirm a pending entry
          exactly once. A duplicate ACK for an already-confirmed message, or a
          stale ACK replayed after the entry timed out, does not mutate state
          (no re-confirmation, no resurrection).

        Args:
            ack_envelope: A received ACK-type envelope.

        Returns:
            The resolved PendingAck, or None if the ACK is unknown, forged,
            unauthenticated, or a replay.
        """
        if not ack_envelope.is_ack:
            return None

        original_id = ack_envelope.payload.content
        path = self._dir / f"{original_id}{ACK_SUFFIX}"

        if not path.exists():
            # No pending entry: a forged ACK for a message we never sent, or a
            # replay after the entry was purged. Either way, ignore.
            logger.debug("ACK for unknown envelope %s — ignoring", original_id[:8])
            return None

        try:
            pending = PendingAck.model_validate_json(path.read_text())
        except Exception as exc:
            logger.warning("Failed to read pending ACK %s: %s", original_id[:8], exc)
            return None

        # --- Sender-identity binding (anti-forgery) ------------------------
        if not self._identity_matches(ack_envelope.sender, pending.recipient):
            logger.warning(
                "Rejecting forged ACK for %s: sender %r != tracked recipient %r",
                original_id[:8], ack_envelope.sender, pending.recipient,
            )
            return None

        # --- Optional cryptographic authentication of the ACK sender -------
        if self._sender_verifier is not None:
            try:
                authenticated = bool(self._sender_verifier(ack_envelope))
            except Exception as exc:
                logger.warning(
                    "ACK sender verification errored for %s: %s", original_id[:8], exc
                )
                authenticated = False
            if not authenticated:
                logger.warning(
                    "Rejecting unauthenticated ACK for %s from %s (signature check failed)",
                    original_id[:8], ack_envelope.sender,
                )
                return None

        # --- Replay / stale protection -------------------------------------
        if pending.status == AckStatus.CONFIRMED:
            logger.debug(
                "Ignoring duplicate/replayed ACK for already-confirmed %s",
                original_id[:8],
            )
            return None
        if pending.status == AckStatus.TIMED_OUT:
            logger.warning("Rejecting stale ACK for timed-out %s", original_id[:8])
            return None

        pending.status = AckStatus.CONFIRMED
        pending.confirmed_at = datetime.now(timezone.utc)
        pending.confirmed_via = ack_envelope.metadata.delivered_via

        path.write_text(pending.model_dump_json(indent=2))
        logger.info("ACK confirmed for %s from %s", original_id[:8], ack_envelope.sender)
        return pending

    def get(self, envelope_id: str) -> Optional[PendingAck]:
        """Look up a pending ACK by envelope ID.

        Args:
            envelope_id: The original message's envelope ID.

        Returns:
            PendingAck or None if not tracked.
        """
        path = self._dir / f"{envelope_id}{ACK_SUFFIX}"
        if not path.exists():
            return None
        try:
            return PendingAck.model_validate_json(path.read_text())
        except Exception as exc:
            logger.debug("Failed to load ACK entry %s: %s", envelope_id[:8], exc)
            return None

    def list_pending(self) -> list[PendingAck]:
        """List all ACKs still awaiting confirmation.

        Returns:
            List of PendingAck with PENDING status.
        """
        return [a for a in self._load_all() if a.status == AckStatus.PENDING]

    def list_timed_out(self) -> list[PendingAck]:
        """List pending ACKs that have exceeded their timeout.

        Returns:
            List of PendingAck that should have been confirmed by now.
        """
        return [a for a in self._load_all() if a.status == AckStatus.PENDING and a.is_expired]

    def list_confirmed(self) -> list[PendingAck]:
        """List all confirmed ACKs.

        Returns:
            List of PendingAck with CONFIRMED status.
        """
        return [a for a in self._load_all() if a.status == AckStatus.CONFIRMED]

    def check_timeouts(self) -> list[PendingAck]:
        """Mark expired pending ACKs as timed_out and return them.

        Returns:
            List of ACKs that just timed out.
        """
        newly_timed_out: list[PendingAck] = []
        for pending in self._load_all():
            if pending.status == AckStatus.PENDING and pending.is_expired:
                pending.status = AckStatus.TIMED_OUT
                path = self._dir / f"{pending.envelope_id}{ACK_SUFFIX}"
                path.write_text(pending.model_dump_json(indent=2))
                newly_timed_out.append(pending)
                logger.warning("ACK timed out for %s", pending.envelope_id[:8])
        return newly_timed_out

    def purge_confirmed(self, max_age: int = 86400) -> int:
        """Remove confirmed ACKs older than max_age seconds.

        Args:
            max_age: Maximum age in seconds for confirmed ACKs.

        Returns:
            Number of ACK files removed.
        """
        removed = 0
        now = datetime.now(timezone.utc)
        for pending in self._load_all():
            if pending.status == AckStatus.CONFIRMED and pending.confirmed_at:
                age = (now - pending.confirmed_at).total_seconds()
                if age > max_age:
                    path = self._dir / f"{pending.envelope_id}{ACK_SUFFIX}"
                    if path.exists():
                        path.unlink()
                        removed += 1
        return removed

    def remove(self, envelope_id: str) -> bool:
        """Remove an ACK tracking entry.

        Args:
            envelope_id: The original message's envelope ID.

        Returns:
            True if the entry was found and removed.
        """
        path = self._dir / f"{envelope_id}{ACK_SUFFIX}"
        if path.exists():
            path.unlink()
            return True
        return False

    @property
    def pending_count(self) -> int:
        """Number of ACKs still pending."""
        return len(self.list_pending())

    def _load_all(self) -> list[PendingAck]:
        """Load all ACK tracking files."""
        results: list[PendingAck] = []
        for path in sorted(self._dir.glob(f"*{ACK_SUFFIX}")):
            try:
                results.append(PendingAck.model_validate_json(path.read_text()))
            except Exception as exc:
                logger.warning("Skipping corrupt ACK file %s: %s", path.name, exc)
        return results


def should_ack(envelope: MessageEnvelope) -> bool:
    """Check if a received envelope requests an ACK.

    Args:
        envelope: The received envelope.

    Returns:
        True if the envelope requests acknowledgment and is not itself an ACK.
    """
    return envelope.routing.ack_requested and not envelope.is_ack


def make_ack_envelope(envelope: MessageEnvelope, sender: str) -> MessageEnvelope:
    """Create an ACK envelope for a received message.

    Convenience wrapper around MessageEnvelope.make_ack().

    Args:
        envelope: The received message to acknowledge.
        sender: Our agent name (ACK sender).

    Returns:
        ACK envelope ready to send.
    """
    return envelope.make_ack(sender)
