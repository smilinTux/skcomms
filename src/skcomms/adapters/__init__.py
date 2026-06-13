"""
skcomms channel adapters (Batch C1 / C2 / C3 / C5).

Platform bridges translate between a foreign platform's wire format and the
normalized :class:`~skcomms.adapters.models.ChannelMessage`.  The
:class:`~skcomms.adapters.registry.AdapterRegistry` manages the set of live
adapters and enforces the P0 unified-memory contract.

Public surface::

    from skcomms.adapters import (
        ChannelAdapter,
        ChannelMessage,
        PlatformIdentity,
        AdapterCapabilities,
        AdapterHealth,
        AdapterRegistry,
        TelegramAdapter,
        SlackAdapter,
        DiscordAdapter,
        MatrixAdapter,
        ChannelType,
        MessageKind,
        TrustLevel,
    )

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md
"""

from .base import (
    AdapterAuthError,
    AdapterCapabilities,
    AdapterConnectError,
    AdapterError,
    AdapterHealth,
    AdapterSendError,
    ChannelAdapter,
)
from .discord import DiscordAdapter
from .matrix import MatrixAdapter
from .models import (
    ChannelMessage,
    ChannelType,
    MediaAttachment,
    MessageKind,
    PlatformIdentity,
    ResolvedIdentity,
    TrustLevel,
)
from .registry import AdapterRegistry
from .slack import SlackAdapter
from .telegram import TelegramAdapter

__all__ = [
    # ABC + health / capability models
    "ChannelAdapter",
    "AdapterCapabilities",
    "AdapterHealth",
    "AdapterError",
    "AdapterAuthError",
    "AdapterConnectError",
    "AdapterSendError",
    # Normalized message model
    "ChannelMessage",
    "ChannelType",
    "MessageKind",
    "PlatformIdentity",
    "ResolvedIdentity",
    "MediaAttachment",
    "TrustLevel",
    # Registry
    "AdapterRegistry",
    # Adapter implementations
    "TelegramAdapter",
    "SlackAdapter",
    "DiscordAdapter",
    "MatrixAdapter",
]
