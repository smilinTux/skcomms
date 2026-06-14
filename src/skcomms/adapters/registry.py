"""
AdapterRegistry — manages live channel adapters and routes messages (Batch C1/C3).

One registry per skcomms hub instance.  Loaded at daemon startup from the
adapter config block in ``~/.skcapstone/skcomms/config.yml`` (or the skcomms stack's
environment).

Key responsibilities:
  1. Start / stop adapters (connect / disconnect lifecycle).
  2. Receive inbound ChannelMessages from each adapter's async generator,
     resolve identity, and dispatch to the agent's memory + advocacy engine.
  3. Route outbound messages from the agent to the right adapter(s).
  4. Broadcast presence: the agent appears on ALL enabled adapters under a
     single FQID.

The P0 unified-memory contract is enforced here: every inbound message — from
every surface — passes through ``_dispatch``, which calls
``hub.memory.write_channel_message`` before handing control to the advocacy
engine.  Adapters never write to skmem-pg directly.

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §5
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

from .base import AdapterHealth, ChannelAdapter
from .models import ChannelMessage, ChannelType, MessageKind, TrustLevel

logger = logging.getLogger("skcomms.adapters")

# Type alias for the inbound handler callback the caller supplies when not
# using a full SkcommsHub (useful for testing and lightweight integrations).
InboundHandler = Callable[[ChannelMessage, str, TrustLevel], Awaitable[None]]


class AdapterRegistry:
    """
    Maintains the set of live channel adapters and routes messages.

    The registry can be used in two modes:

    1. **Hub mode** (production): pass a *hub* object that implements
       ``hub.memory.write_channel_message`` and ``hub.advocacy.on_channel_message``.
       The registry calls both on every inbound message.

    2. **Handler mode** (testing / lightweight): pass an *inbound_handler*
       coroutine instead.  The registry calls it with
       ``(msg, fqid, trust_level)`` for every dispatched message.

    If neither is provided, inbound messages are logged and dropped.
    """

    def __init__(
        self,
        hub: object = None,
        inbound_handler: Optional[InboundHandler] = None,
    ) -> None:
        self._hub = hub
        self._inbound_handler = inbound_handler
        self._adapters: dict[str, ChannelAdapter] = {}  # adapter_name → adapter
        self._tasks: dict[str, asyncio.Task] = {}

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def register(self, adapter: ChannelAdapter) -> None:
        """Add an adapter.  Must be called before start()."""
        self._adapters[adapter.adapter_name] = adapter
        logger.debug("registered adapter %s", adapter.adapter_name)

    def get(self, adapter_name: str) -> Optional[ChannelAdapter]:
        """Return a registered adapter by name, or None."""
        return self._adapters.get(adapter_name)

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        """Connect all registered adapters and launch their inbound loops."""
        for name, adapter in self._adapters.items():
            await adapter.connect()
            self._tasks[name] = asyncio.create_task(
                self._run_inbound(adapter),
                name=f"adapter-{name}",
            )
            logger.info("adapter %s started", name)

    async def stop(self) -> None:
        """Disconnect all adapters and cancel their inbound loop tasks."""
        for name, task in self._tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            logger.info("adapter %s task cancelled", name)
        for name, adapter in self._adapters.items():
            await adapter.disconnect()
            logger.info("adapter %s disconnected", name)
        self._tasks.clear()

    # -----------------------------------------------------------------------
    # Inbound pipeline
    # -----------------------------------------------------------------------

    async def _run_inbound(self, adapter: ChannelAdapter) -> None:
        """Drain the adapter's inbound generator and dispatch each message."""
        async for msg in adapter.inbound():
            try:
                await self._dispatch(adapter, msg)
            except Exception:
                logger.exception("dispatch error from %s", adapter.adapter_name)

    async def _dispatch(
        self,
        adapter: ChannelAdapter,
        msg: ChannelMessage,
    ) -> None:
        """
        Identity-resolve, assign trust, write to unified memory, and deliver
        to the agent's advocacy engine.

        This is the P0 unified-memory boundary: every surface writes
        through here, not via direct skmem-pg calls.

        Steps:
          1. Resolve sender FQID via the adapter's local identity map.
          2. Assign TrustLevel (VERIFIED if bound, UNTRUSTED otherwise).
          3. Mint a stable synthetic FQID for unbound senders.
          4. Write to unified memory (one skmem-pg of record).
          5. Hand to the advocacy engine for agent response.
        """
        # 1 + 2 + 3. Resolve FQID
        fqid = await adapter.resolve_fqid(msg.sender)
        trust = TrustLevel.VERIFIED if fqid else TrustLevel.UNTRUSTED
        if not fqid:
            # Mint a stable guest FQID for this platform identity
            fqid = f"{msg.sender.channel.value}_guest_{msg.sender.platform_id}@ext"

        # 4. Write to unified memory (one skmem-pg of record)
        if self._hub is not None:
            memory = getattr(self._hub, "memory", None)
            if memory is not None:
                await memory.write_channel_message(msg, fqid=fqid, trust=trust)

        # 5. Hand to the advocacy engine for agent response
        if self._inbound_handler is not None:
            await self._inbound_handler(msg, fqid, trust)
        elif self._hub is not None:
            advocacy = getattr(self._hub, "advocacy", None)
            if advocacy is not None:
                await advocacy.on_channel_message(msg, sender_fqid=fqid)
        else:
            logger.debug(
                "no handler; dropping inbound %s from %s",
                msg.kind.value,
                msg.sender.canonical_key,
            )

    # -----------------------------------------------------------------------
    # Outbound routing
    # -----------------------------------------------------------------------

    async def send_to_adapter(
        self,
        adapter_name: str,
        message: ChannelMessage,
    ) -> str:
        """
        Send an outbound message through a named adapter.

        Applies capability downgrade before delivery (e.g. voice → transcript
        if the adapter does not support voice notes).

        Args:
            adapter_name: Key in the registry (must be registered).
            message: Outbound ChannelMessage from the hub/agent.

        Returns:
            Platform message id from the adapter's send() call.

        Raises:
            KeyError: If *adapter_name* is not registered.
            AdapterSendError: On unrecoverable send failure.
        """
        adapter = self._adapters[adapter_name]
        caps = adapter.capabilities()
        message = self._downgrade(message, caps)
        return await adapter.send(message)

    # -----------------------------------------------------------------------
    # Presence
    # -----------------------------------------------------------------------

    async def broadcast_presence(self, agent_fqid: str, status: str) -> None:
        """Push an agent's presence update to all adapters that support it."""
        for adapter in self._adapters.values():
            if adapter.capabilities().typing_hint:
                set_presence = getattr(adapter, "set_presence", None)
                if set_presence is not None:
                    try:
                        await set_presence(agent_fqid, status)
                    except Exception:
                        logger.debug(
                            "presence update skipped on %s", adapter.adapter_name
                        )

    # -----------------------------------------------------------------------
    # Health
    # -----------------------------------------------------------------------

    async def health_all(self) -> dict[str, AdapterHealth]:
        """Collect health snapshots from all registered adapters (async)."""
        results: dict[str, AdapterHealth] = {}
        for name, adapter in self._adapters.items():
            try:
                results[name] = await adapter.health()
            except Exception as exc:
                results[name] = AdapterHealth(
                    adapter_name=name,
                    connected=False,
                    latency_ms=None,
                    error=str(exc),
                )
        return results

    # -----------------------------------------------------------------------
    # Capability downgrade (static helper)
    # -----------------------------------------------------------------------

    @staticmethod
    def _downgrade(msg: ChannelMessage, caps: "AdapterCapabilities") -> ChannelMessage:
        """
        Strip content the target adapter cannot render.

        Rules applied in order:

        1. ``VOICE`` + ``caps.voice_notes=False``
           → text = "[Voice note: {transcript}]", kind = TEXT, attachments cleared.
        2. ``IMAGE`` + ``caps.images=False``
           → text = "[Image: {filename}]", kind = TEXT, attachments cleared.
        3. text > ``caps.max_text_bytes``
           → truncate with "… [truncated]".

        A shallow copy of the message is made; the original is not modified.
        """
        import dataclasses

        from .base import AdapterCapabilities  # local import avoids circular

        msg = dataclasses.replace(msg)  # shallow copy

        if msg.kind == MessageKind.VOICE and not caps.voice_notes:
            transcript = msg.text or "[untranscribed voice note]"
            msg.kind = MessageKind.TEXT
            msg.text = f"[Voice note: {transcript}]"
            msg.attachments = []

        if msg.kind == MessageKind.IMAGE and not caps.images:
            names = ", ".join(a.filename for a in msg.attachments) or "image"
            msg.text = f"[Image: {names}]"
            msg.attachments = []
            msg.kind = MessageKind.TEXT

        if len(msg.text.encode()) > caps.max_text_bytes:
            trimmed = msg.text.encode()[: caps.max_text_bytes - 20].decode(
                errors="ignore"
            )
            msg.text = trimmed + " … [truncated]"

        return msg
