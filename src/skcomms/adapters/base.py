"""
ChannelAdapter abstract base class (Batch C1).

Every platform bridge (Telegram, Slack, Discord, NC Talk, Matrix, …) must
implement this ABC.  The adapter owns the platform edge; the skcomms hub owns
the interior (identity resolution, memory write, advocacy dispatch).

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §4
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator, Optional

from .models import ChannelMessage, ChannelType, PlatformIdentity

# ---------------------------------------------------------------------------
# Capability / health models
# ---------------------------------------------------------------------------


@dataclass
class AdapterCapabilities:
    """
    Declare what this adapter can do.

    The hub uses these flags to decide whether to downgrade a rich
    outbound message before forwarding (e.g. strip a voice note to a
    transcript when voice_notes=False).
    """

    text: bool = True
    files: bool = True
    images: bool = True
    voice_notes: bool = False
    video: bool = False
    reactions: bool = False
    threads: bool = False  # inline threading (Slack threads, TG reply-chain)
    read_receipts: bool = False
    typing_hint: bool = False
    max_text_bytes: int = 4096  # platform message size limit


@dataclass
class AdapterHealth:
    """Point-in-time health snapshot for monitoring."""

    adapter_name: str
    connected: bool
    latency_ms: Optional[float]
    error: Optional[str] = None
    queued_outbound: int = 0  # messages waiting to be delivered


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class AdapterError(Exception):
    """Base class for all adapter errors."""


class AdapterAuthError(AdapterError):
    """Raised by connect() when credentials are invalid."""


class AdapterConnectError(AdapterError):
    """Raised by connect() when the platform is unreachable."""


class AdapterSendError(AdapterError):
    """Raised by send() on unrecoverable delivery failure."""


# ---------------------------------------------------------------------------
# ChannelAdapter ABC
# ---------------------------------------------------------------------------


class ChannelAdapter(ABC):
    """
    Abstract base class for all skcomms channel adapters.

    An adapter is the thin boundary between a foreign platform (Telegram,
    Slack, Discord, …) and the skcomms sovereign hub.  It does three things:

      1. Translate inbound platform events → ChannelMessage.
      2. Translate outbound ChannelMessage → platform API calls.
      3. Map FQID ↔ platform user/room identities.

    It does NOT:
      - Write to skmem-pg directly.
      - Resolve FQID trust levels (that is the hub's job).
      - Hold conversation state beyond what the platform provides.
      - Know about CapAuth keys.

    Lifecycle::

        adapter = TelegramAdapter(config)
        await adapter.connect()              # authenticate + start polling/webhook
        async for msg in adapter.inbound():  # yields normalized ChannelMessages
            await hub.dispatch_inbound(msg)
        await adapter.disconnect()

    Subclasses must set the class-level ``channel_type`` and ``adapter_name``
    attributes (not enforced by the ABC machinery so that ``__init_subclass__``
    stays simple, but validated at runtime by the registry).
    """

    # Subclasses must set these:
    channel_type: ChannelType
    adapter_name: str  # e.g. "telegram", "slack-sktechops"

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    @abstractmethod
    async def connect(self) -> None:
        """
        Authenticate with the platform and start the inbound loop.

        Raises:
            AdapterAuthError: If credentials are invalid.
            AdapterConnectError: If the platform is unreachable.
        """

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully stop the inbound loop and close any open connections."""

    @abstractmethod
    async def health(self) -> AdapterHealth:
        """
        Return a point-in-time health snapshot.

        Called by the adapter registry every 30 s; used by skmon and
        the ``skcomms adapter status`` CLI subcommand.
        """

    # -----------------------------------------------------------------------
    # Inbound (platform → skcomms)
    # -----------------------------------------------------------------------

    @abstractmethod
    async def inbound(self) -> AsyncIterator[ChannelMessage]:
        """
        Async generator that yields normalized ChannelMessages as they arrive.

        The hub calls ``async for msg in adapter.inbound(): …``.
        Implementations may use long-polling, webhooks, or WebSocket
        subscriptions — the caller does not care which.

        Yields:
            ChannelMessage: one per platform event.
        """

    # -----------------------------------------------------------------------
    # Outbound (skcomms → platform)
    # -----------------------------------------------------------------------

    @abstractmethod
    async def send(self, message: ChannelMessage) -> str:
        """
        Deliver a ChannelMessage to the platform.

        The hub calls this after resolving the outbound route.  Must handle
        rate limiting internally (back off + retry up to the adapter's
        configured timeout, then raise AdapterSendError).

        Args:
            message: Normalized outbound message.  The hub has already applied
                     capability downgrade (e.g. converted voice to a transcript
                     if voice_notes=False).

        Returns:
            The platform's message id for the delivered message (str).

        Raises:
            AdapterSendError: On unrecoverable failure.
        """

    # -----------------------------------------------------------------------
    # Identity mapping (FQID ↔ platform user/room)
    # -----------------------------------------------------------------------

    @abstractmethod
    async def resolve_fqid(self, platform_id: PlatformIdentity) -> Optional[str]:
        """
        Look up the FQID bound to this platform identity.

        Returns the FQID string (e.g. "chef@skworld.io") if a verified binding
        exists, or None if the platform user is unknown.

        The hub calls this on every inbound message and assigns a trust level
        accordingly.  Implementations should consult the adapter's local
        identity map first, then optionally query the CapAuth DID registry.
        """

    @abstractmethod
    async def bind_fqid(
        self,
        platform_id: PlatformIdentity,
        fqid: str,
        trust_level: str,
    ) -> None:
        """
        Persist a verified FQID ↔ platform-id binding.

        Called by the hub's identity-binding flow (e.g. when Chef types
        ``/bind chef@skworld.io`` in the Telegram group and the hub verifies
        the CapAuth challenge).  Implementations write to the adapter's own
        store (YAML / SQLite / skcapstone peers/).
        """

    # -----------------------------------------------------------------------
    # Capabilities declaration (not abstract — safe default provided)
    # -----------------------------------------------------------------------

    def capabilities(self) -> AdapterCapabilities:
        """
        Declare what this platform supports.

        Subclasses should override to return accurate flags.
        The hub uses these for outbound capability downgrade.
        """
        return AdapterCapabilities()
