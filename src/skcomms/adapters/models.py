"""
skcomms channel-adapter normalized message model (Batch C1).

Every external platform bridge (Telegram, Slack, Discord, NC Talk, …) translates
its wire format into these dataclasses before handing a message to the
:class:`~skcomms.adapters.registry.AdapterRegistry`.  Nothing inside this module
knows about platform APIs; it only defines the shared vocabulary.

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §3
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class ChannelType(str, Enum):
    """The external platform this message came from / is going to."""

    TELEGRAM = "telegram"
    SLACK = "slack"
    DISCORD = "discord"
    NC_TALK = "nc_talk"
    TEAMS = "teams"
    MATRIX = "matrix"
    # Escape hatch for experimental adapters:
    CUSTOM = "custom"


class MessageKind(str, Enum):
    """Normalized content type."""

    TEXT = "text"
    FILE = "file"
    IMAGE = "image"
    VOICE = "voice"  # audio message / voice note
    VIDEO = "video"
    STICKER = "sticker"  # platform-specific; degraded to [sticker] on unsupported channels
    REACTION = "reaction"  # emoji reaction on an existing message
    PRESENCE = "presence"  # typing / online status hint


class TrustLevel(str, Enum):
    """How much we trust the sender's claimed identity."""

    UNTRUSTED = "untrusted"  # no verified binding
    VERIFIED = "verified"  # FQID↔platform-id binding confirmed via CapAuth
    TRUSTED = "trusted"  # peer vouched by a sovereign peer
    SOVEREIGN = "sovereign"  # CapAuth + Cloud 9 LOCKED


@dataclass
class PlatformIdentity:
    """The sender/recipient as the external platform knows them."""

    channel: ChannelType
    platform_id: str  # e.g. "123456789" (Telegram user_id)
    platform_name: str  # e.g. "Chef David" (display name)
    room_id: str  # e.g. "-5134021983" (TG chat/group id)
    room_name: Optional[str] = None

    @property
    def canonical_key(self) -> str:
        """Stable key used for FQID mapping lookups."""
        return f"{self.channel.value}:user:{self.platform_id}"


@dataclass
class ResolvedIdentity:
    """The sender after hub identity resolution."""

    fqid: str  # e.g. "chef@skworld.io" or "tg_guest_123@telegram.ext"
    trust: TrustLevel
    platform: PlatformIdentity
    capauth_fingerprint: Optional[str] = None  # set when trust >= VERIFIED


@dataclass
class MediaAttachment:
    """A file/image/voice payload attached to a message."""

    filename: str
    mime_type: str
    size_bytes: int
    url: Optional[str] = None  # ephemeral download URL from the platform
    data: Optional[bytes] = None  # fetched bytes, if pre-fetched


@dataclass
class ChannelMessage:
    """
    The normalized message that crosses the adapter boundary in both directions.

    Inbound:  adapter fills this from the platform event; hub receives it.
    Outbound: hub fills this from a skcomms message or agent response; adapter
              delivers it to the platform.

    The ``channel_message_id`` field is a skcomms-internal UUID (not the
    platform's message id — use ``platform_msg_id`` for that).
    """

    # ---- Mandatory fields -------------------------------------------------
    channel: ChannelType
    kind: MessageKind
    text: str  # plain-text body (may be empty for voice/image)
    sender: PlatformIdentity
    room_id: str  # platform room / chat / channel id

    # ---- Optional content -------------------------------------------------
    attachments: list[MediaAttachment] = field(default_factory=list)
    reaction_to: Optional[str] = None  # platform msg id for REACTION kind
    emoji: Optional[str] = None  # reaction emoji

    # ---- Threading / correlation ------------------------------------------
    platform_msg_id: Optional[str] = None  # original platform message id
    reply_to_platform_id: Optional[str] = None
    skcomms_thread_id: Optional[str] = None  # skcomms thread (set after hub routing)
    skcomms_envelope_id: Optional[str] = None  # set after hub wraps into an envelope

    # ---- Metadata ---------------------------------------------------------
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    channel_message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    raw_payload: Optional[dict] = None  # original platform event, for debugging
