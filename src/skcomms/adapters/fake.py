"""
FakeAdapter — a token-free, network-free :class:`ChannelAdapter` implementation.

Used to exercise the registry + lifecycle + factory plumbing in CI without any
bot tokens or platform connectivity.  It implements every abstract method of
:class:`~skcomms.adapters.base.ChannelAdapter` against an in-memory queue.

Spec: docs/superpowers/plans/2026-06-13-tier3-adapter-runtime.md (Task 1)
"""

from __future__ import annotations

import asyncio
import uuid
from typing import AsyncIterator, Optional

from .base import AdapterHealth, ChannelAdapter
from .models import (
    ChannelMessage,
    ChannelType,
    MessageKind,
    PlatformIdentity,
)


class FakeAdapter(ChannelAdapter):
    """An in-memory adapter with no external dependencies.

    - ``connect``/``disconnect`` flip an internal connected flag.
    - ``health`` reports a real :class:`AdapterHealth`.
    - ``inbound`` drains an internal :class:`asyncio.Queue`; ``inject`` fills it.
    - ``send`` records the message and returns a synthetic message id.
    - ``resolve_fqid``/``bind_fqid`` are local stubs (no registry round-trip).
    """

    channel_type: ChannelType = ChannelType.CUSTOM

    def __init__(self, config: Optional[dict] = None) -> None:
        config = config or {}
        self.adapter_name: str = config.get("adapter_name", "fake")
        self._connected: bool = False
        self._queue: "asyncio.Queue[ChannelMessage]" = asyncio.Queue()
        self.sent: list[ChannelMessage] = []
        self._bindings: dict[str, str] = {}

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def health(self) -> AdapterHealth:
        return AdapterHealth(
            adapter_name=self.adapter_name,
            connected=self._connected,
            latency_ms=0.0,
            error=None,
            queued_outbound=self._queue.qsize(),
        )

    # -----------------------------------------------------------------------
    # Inbound (platform → skcomms)
    # -----------------------------------------------------------------------

    async def inbound(self) -> AsyncIterator[ChannelMessage]:
        while True:
            msg = await self._queue.get()
            yield msg

    # -----------------------------------------------------------------------
    # Outbound (skcomms → platform)
    # -----------------------------------------------------------------------

    async def send(self, message: ChannelMessage) -> str:
        self.sent.append(message)
        return uuid.uuid4().hex

    # -----------------------------------------------------------------------
    # Identity mapping
    # -----------------------------------------------------------------------

    async def resolve_fqid(self, platform_id: PlatformIdentity) -> Optional[str]:
        return self._bindings.get(platform_id.canonical_key)

    async def bind_fqid(
        self,
        platform_id: PlatformIdentity,
        fqid: str,
        trust_level: str,
    ) -> None:
        self._bindings[platform_id.canonical_key] = fqid

    # -----------------------------------------------------------------------
    # Test helpers (not part of the ABC)
    # -----------------------------------------------------------------------

    def make_message(self, text: str) -> ChannelMessage:
        """Build a minimal valid :class:`ChannelMessage` for tests."""
        sender = PlatformIdentity(
            channel=self.channel_type,
            platform_id="fake-user",
            platform_name="Fake User",
            room_id="fake-room",
        )
        return ChannelMessage(
            channel=self.channel_type,
            kind=MessageKind.TEXT,
            text=text,
            sender=sender,
            room_id="fake-room",
        )

    def inject(self, message: ChannelMessage) -> None:
        """Place a message onto the inbound queue (test driver)."""
        self._queue.put_nowait(message)
