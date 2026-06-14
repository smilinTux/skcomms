"""
DiscordAdapter — Discord Gateway / REST channel adapter (Batch C3).

Receives events from a Discord guild via the Gateway (WebSocket) or a
poll-based REST fallback, normalises them into
:class:`~skcomms.adapters.models.ChannelMessage`, and delivers outbound
messages via the Discord REST API (``POST /channels/{id}/messages``).

The Discord client is **injectable** (pass ``discord_client`` to the
constructor) so the adapter is fully unit-testable without any live
credentials.

Config block in ``~/.skcapstone/skcomms/config.yml``::

    adapters:
      discord:
        enabled: true
        bot_token: "${DISCORD_BOT_TOKEN}"   # Bot token (required)
        poll_interval_s: 1
        guilds:
          skworld:
            guild_id: "1234567890"
            channels:
              general:
                channel_id: "9876543210"
                agent_fqid: "lumina@skworld.io"
        identity_store: "~/.skcapstone/skcomms/adapters/discord-ids.yaml"

Intents required (Gateway privileged intents)
---------------------------------------------
  MESSAGE_CONTENT   — to read message body
  GUILD_MESSAGES    — for messages in guild channels
  DIRECT_MESSAGES   — for DMs (if needed)
  GUILD_MEMBERS     — for member name resolution (optional)

Permissions required (OAuth2 bot invite)
-----------------------------------------
  Read Messages/View Channels, Send Messages, Read Message History,
  Attach Files, Add Reactions, Use Slash Commands

Implementation notes
--------------------
* The adapter accepts an optional ``discord_client`` satisfying
  :class:`DiscordClientProtocol`.  Tests pass :class:`FakeDiscordClient`;
  production builds pass a real ``discord.py``-based wrapper.
* ``bindings_store``: inject an in-memory dict to skip YAML I/O in tests.
* No live connections are made at import time or before ``connect()``.

TODO (post-C3, live wiring):
  - Wire real ``discord.py`` (or ``nextcord`` / ``hikari``) Gateway client
    in ``_build_discord_client``.
  - Implement reaction events (``MESSAGE_REACTION_ADD/REMOVE``).
  - Add file download for attachments.
  - Handle threaded replies (``message_reference``).
  - Implement ``set_presence`` (Discord typing indicators + Rich Presence).
  - Support slash commands (interaction events).

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §8
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, AsyncIterator, Optional, Protocol, runtime_checkable

from .base import (
    AdapterAuthError,
    AdapterCapabilities,
    AdapterConnectError,
    AdapterHealth,
    AdapterSendError,
    ChannelAdapter,
)
from .models import (
    ChannelMessage,
    ChannelType,
    MediaAttachment,
    MessageKind,
    PlatformIdentity,
)

logger = logging.getLogger("skcomms.adapters.discord")

# ---------------------------------------------------------------------------
# Injectable client protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class DiscordClientProtocol(Protocol):
    """
    Structural protocol for the injectable Discord client.

    Both the real ``discord.py``-based wrapper and :class:`FakeDiscordClient`
    satisfy this interface.
    """

    def is_connected(self) -> bool: ...

    async def login(self) -> dict: ...

    async def send_message(
        self,
        channel_id: str,
        content: str,
        *,
        message_reference: Optional[dict] = None,
    ) -> dict: ...

    async def send_file(
        self,
        channel_id: str,
        content: bytes,
        filename: str,
        *,
        caption: str = "",
    ) -> dict: ...

    def drain_events(self) -> list[dict]: ...

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...


# ---------------------------------------------------------------------------
# Real discord.py wrapper (satisfies DiscordClientProtocol)
# ---------------------------------------------------------------------------


class _DiscordPyClientWrapper:
    """
    Thin wrapper around a ``discord.py`` ``discord.Client`` that satisfies
    :class:`DiscordClientProtocol`.

    discord.py uses event callbacks (``on_message``) rather than a poll queue.
    This wrapper bridges that model by enqueuing ``MESSAGE_CREATE`` payloads in
    ``_event_queue``; :meth:`drain_events` flushes and returns them.

    The wrapper is built (but not connected) by
    :meth:`DiscordAdapter._build_discord_client`.  No network I/O occurs until
    :meth:`connect` is called.

    Token is stored as-is; discord.py accepts bare tokens (the "Bot " prefix
    is optional and appended automatically by the library if absent).

    Args:
        token: Bot token — from ``DISCORD_BOT_TOKEN`` env var or config.

    Notes:
        ``discord.py`` requires a running event loop for ``discord.Client``
        instantiation; we defer creation to :meth:`connect` to avoid issues
        when this is constructed outside an async context.
    """

    def __init__(self, token: str) -> None:
        self._token = token
        self._discord_client: Any = None  # discord.Client — created in connect()
        self._connected = False
        self._event_queue: list[dict] = []
        self._me: Optional[dict] = None

    # --- DiscordClientProtocol implementation ---

    def is_connected(self) -> bool:
        if self._discord_client is None:
            return False
        return not self._discord_client.is_closed()

    async def connect(self) -> None:
        """
        Build the discord.Client with the required intents and register the
        ``on_message`` callback that populates ``_event_queue``.

        Does NOT call ``discord.Client.start()`` / ``login()`` yet — that
        happens lazily when the caller calls :meth:`login` to retrieve the
        bot identity.  A bare ``connect()`` here is intentionally cheap.
        """
        import discord

        intents = discord.Intents.default()
        intents.message_content = True  # privileged — must be enabled in Dev Portal
        intents.guild_messages = True
        intents.dm_messages = True

        self._discord_client = discord.Client(intents=intents)

        # Register message-create callback to feed the drain queue
        @self._discord_client.event
        async def on_message(message: Any) -> None:
            # Build a dict that matches the shape DiscordAdapter._normalize expects
            payload: dict = {
                "type": "MESSAGE_CREATE",
                "id": str(message.id),
                "channel_id": str(message.channel.id),
                "content": message.content or "",
                "author": {
                    "id": str(message.author.id),
                    "username": getattr(message.author, "name", ""),
                    "global_name": getattr(message.author, "display_name", None),
                    "discriminator": getattr(message.author, "discriminator", "0"),
                    "bot": message.author.bot,
                },
                "attachments": [
                    {
                        "id": str(att.id),
                        "filename": att.filename,
                        "content_type": att.content_type or "application/octet-stream",
                        "size": att.size,
                        "url": att.url,
                    }
                    for att in message.attachments
                ],
            }
            guild = getattr(message, "guild", None)
            if guild is not None:
                payload["guild_id"] = str(guild.id)
            ref = getattr(message, "reference", None)
            if ref is not None and getattr(ref, "message_id", None) is not None:
                payload["message_reference"] = {
                    "message_id": str(ref.message_id),
                    "channel_id": str(ref.channel_id) if ref.channel_id else str(message.channel.id),
                }
            self._event_queue.append(payload)

        self._connected = True

    async def login(self) -> dict:
        """
        Authenticate with Discord and return the bot user dict.

        Calls ``discord.Client.login()`` which validates the token and populates
        ``client.user``.  Must be called after :meth:`connect`.

        Returns:
            Dict with ``id``, ``username``, ``discriminator``, ``bot`` keys.

        Raises:
            Exception: On invalid token or network failure.
        """
        if self._discord_client is None:
            raise RuntimeError("_DiscordPyClientWrapper.connect() must be called first")
        await self._discord_client.login(self._token)
        user = self._discord_client.user
        if user is None:
            return {}
        self._me = {
            "id": str(user.id),
            "username": str(user.name),
            "discriminator": getattr(user, "discriminator", "0"),
            "bot": user.bot,
        }
        return self._me

    async def send_message(
        self,
        channel_id: str,
        content: str,
        *,
        message_reference: Optional[dict] = None,
    ) -> dict:
        """
        Send a text message to a Discord channel via REST.

        Args:
            channel_id: Snowflake id string of the target channel.
            content: Message body (≤ 2 000 chars).
            message_reference: Optional reply reference dict with ``message_id``.

        Returns:
            Discord message object dict with ``id`` key.
        """
        if self._discord_client is None:
            raise RuntimeError("Not connected")
        channel = self._discord_client.get_channel(int(channel_id))
        if channel is None:
            # fetch_channel goes to the REST API; requires the bot to have access
            channel = await self._discord_client.fetch_channel(int(channel_id))
        kwargs: dict = {}
        if message_reference and message_reference.get("message_id"):
            import discord

            ref = discord.MessageReference(
                message_id=int(message_reference["message_id"]),
                channel_id=int(message_reference.get("channel_id", channel_id)),
                fail_if_not_exists=False,
            )
            kwargs["reference"] = ref
        sent = await channel.send(content, **kwargs)
        return {"id": str(sent.id), "channel_id": str(sent.channel.id)}

    async def send_file(
        self,
        channel_id: str,
        content: bytes,
        filename: str,
        *,
        caption: str = "",
    ) -> dict:
        """
        Upload a file to a Discord channel.

        Args:
            channel_id: Snowflake id string of the target channel.
            content: Raw file bytes.
            filename: Suggested filename for the attachment.
            caption: Optional text message sent alongside the file.

        Returns:
            Discord message object dict with ``id`` key.
        """
        if self._discord_client is None:
            raise RuntimeError("Not connected")
        import io

        import discord

        channel = self._discord_client.get_channel(int(channel_id))
        if channel is None:
            channel = await self._discord_client.fetch_channel(int(channel_id))
        fp = discord.File(io.BytesIO(content), filename=filename)
        sent = await channel.send(content=caption or None, file=fp)
        return {"id": str(sent.id), "channel_id": str(sent.channel.id)}

    def drain_events(self) -> list[dict]:
        """Flush and return all queued ``MESSAGE_CREATE`` payloads."""
        events = list(self._event_queue)
        self._event_queue.clear()
        return events

    async def disconnect(self) -> None:
        """Close the discord.py Gateway connection."""
        if self._discord_client is not None and not self._discord_client.is_closed():
            await self._discord_client.close()
        self._connected = False


# ---------------------------------------------------------------------------
# DiscordAdapter
# ---------------------------------------------------------------------------


class DiscordAdapter(ChannelAdapter):
    """
    Discord adapter using the Gateway + REST API (Batch C3).

    Args:
        config: Adapter config dict (see module docstring for shape).
        discord_client: Optional injectable client satisfying
            :class:`DiscordClientProtocol`.  Tests pass a
            :class:`~tests.test_discord_adapter.FakeDiscordClient`;
            production omits this arg and the adapter builds a real
            client from config.
        bindings_store: Optional dict used as the in-memory identity map
            instead of the YAML file on disk (useful for unit testing).
    """

    channel_type = ChannelType.DISCORD
    adapter_name = "discord"

    def __init__(
        self,
        config: dict,
        discord_client: Optional[DiscordClientProtocol] = None,
        bindings_store: Optional[dict[str, str]] = None,
    ) -> None:
        # --- Core config ---
        # bot_token: from config dict only; env fallback is in
        # _build_discord_client (called lazily when no client is injected).
        self._bot_token: str = config.get("bot_token", "")
        self._poll_s: float = config.get("poll_interval_s", 1)
        self._guilds: dict[str, dict] = config.get("guilds", {})
        self._id_store_path: str = config.get(
            "identity_store", "~/.skcapstone/skcomms/adapters/discord-ids.yaml"
        )

        # --- State ---
        self._running = False
        self._bot_user_id: Optional[str] = None
        self._bot_username: Optional[str] = None

        # --- Identity bindings ---
        self._bindings: dict[str, str] = (
            bindings_store if bindings_store is not None else {}
        )
        self._external_bindings = bindings_store is not None

        # --- Injectable client ---
        self._client: Optional[DiscordClientProtocol] = discord_client

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Authenticate with Discord and start the Gateway connection.

        When a real (or fake injectable) client is provided it calls
        ``login()`` to verify the token and retrieve the bot's identity.
        """
        if self._client is None:
            self._client = self._build_discord_client()

        if self._client is not None:
            await self._client.connect()
            try:
                me = await self._client.login()
            except Exception as exc:
                raise AdapterConnectError(
                    f"Discord login failed: {exc}"
                ) from exc

            if not me.get("id"):
                raise AdapterAuthError(
                    "Discord login did not return a valid user object — "
                    "check the bot token."
                )

            self._bot_user_id = me.get("id")
            self._bot_username = me.get("username")
            logger.info(
                "discord adapter connected as %s#%s (id=%s)",
                self._bot_username,
                me.get("discriminator", "0"),
                self._bot_user_id,
            )
        else:
            raise AdapterAuthError(
                "DiscordAdapter requires a bot_token. "
                "Set DISCORD_BOT_TOKEN or pass discord_client=."
            )

        if not self._external_bindings:
            self._load_bindings()

        self._running = True
        logger.info("discord adapter ready")

    async def disconnect(self) -> None:
        """Stop the inbound loop and close the Gateway connection."""
        self._running = False
        if self._client is not None and self._client.is_connected():
            await self._client.disconnect()
        logger.info("discord adapter disconnected")

    async def health(self) -> AdapterHealth:
        """Return a point-in-time health snapshot via login()."""
        import time

        if self._client is not None:
            connected = self._client.is_connected()
            t0 = time.monotonic()
            try:
                me = await self._client.login()
                latency_ms = (time.monotonic() - t0) * 1000
                ok = bool(me.get("id"))
                return AdapterHealth(
                    adapter_name=self.adapter_name,
                    connected=connected and ok,
                    latency_ms=latency_ms,
                    error=None if ok else "login returned no user id",
                )
            except Exception as exc:
                return AdapterHealth(
                    adapter_name=self.adapter_name,
                    connected=False,
                    latency_ms=None,
                    error=str(exc),
                )

        # Stub / no-client path
        return AdapterHealth(
            adapter_name=self.adapter_name,
            connected=self._running,
            latency_ms=None,
        )

    def capabilities(self) -> AdapterCapabilities:
        """Discord capabilities."""
        return AdapterCapabilities(
            text=True,
            files=True,
            images=True,
            voice_notes=False,   # Discord has voice channels but not voice messages (bots)
            video=False,
            reactions=True,
            threads=True,        # Discord threads + reply chains
            read_receipts=False,
            typing_hint=True,    # triggerTypingIndicator endpoint
            max_text_bytes=2000,  # Discord message limit = 2 000 chars
        )

    # -----------------------------------------------------------------------
    # Inbound (platform → skcomms)
    # -----------------------------------------------------------------------

    async def inbound(self) -> AsyncIterator[ChannelMessage]:
        """
        Drain Gateway events and yield one :class:`ChannelMessage` per event.

        The injectable client exposes :meth:`drain_events` which returns
        a list of raw Discord Gateway dispatch payloads (dicts).  In
        production, the real Gateway client enqueues ``MESSAGE_CREATE``
        events; tests push events directly into the fake client's queue.
        """
        while self._running:
            if self._client is not None:
                events = self._client.drain_events()
                for raw in events:
                    msg = self._normalize(raw)
                    if msg is not None:
                        yield msg
            await asyncio.sleep(self._poll_s)

    def _normalize(self, event: dict) -> Optional[ChannelMessage]:
        """
        Translate a raw Discord Gateway ``MESSAGE_CREATE`` payload into a
        :class:`ChannelMessage`.

        Handles:
        * Plain text messages
        * Messages with ``attachments`` (files + images)
        * ``message_reference`` → ``reply_to_platform_id``

        Bot messages (``author.bot == true``) are dropped to prevent
        self-echo.

        Discord event shape expected (``MESSAGE_CREATE`` ``d`` field)::

            {
              "id": "111",
              "channel_id": "C999",
              "guild_id": "G000",        # absent in DMs
              "author": {
                "id": "U222",
                "username": "Chef",
                "discriminator": "0",
                "bot": false,
              },
              "content": "Hello Lumina",
              "timestamp": "2026-06-13T00:00:00.000Z",
              "message_reference": {...}, # optional
              "attachments": [...],       # optional
            }
        """
        etype = event.get("type")
        # Support both raw Gateway dispatch dicts (with type) and the inner
        # data dict (without type, already the MESSAGE_CREATE payload).
        if etype is not None and etype != "MESSAGE_CREATE":
            logger.debug("discord: dropping event type=%s", etype)
            return None

        author = event.get("author", {})
        # Drop bot/webhook messages to avoid self-echo
        if author.get("bot", False) or author.get("webhook_id"):
            logger.debug(
                "discord: dropping bot/webhook message from %s", author.get("id")
            )
            return None

        user_id = author.get("id") or event.get("user_id", "unknown")
        discriminator = author.get("discriminator", "0")
        display = author.get("global_name") or author.get("username") or user_id
        if discriminator and discriminator != "0":
            display = f"{display}#{discriminator}"

        channel_id = event.get("channel_id", "unknown")
        guild_id = event.get("guild_id")  # None for DMs
        msg_id = event.get("id", "")

        # Build a room name from guild config if available
        room_name: Optional[str] = None
        if guild_id:
            for guild_cfg in self._guilds.values():
                if guild_cfg.get("guild_id") == guild_id:
                    channels_cfg: dict = guild_cfg.get("channels", {})
                    for ch_cfg in channels_cfg.values():
                        if ch_cfg.get("channel_id") == channel_id:
                            room_name = channel_id
                            break

        sender = PlatformIdentity(
            channel=ChannelType.DISCORD,
            platform_id=user_id,
            platform_name=display,
            room_id=channel_id,
            room_name=room_name,
        )

        # Determine kind + attachments
        kind = MessageKind.TEXT
        text: str = event.get("content") or ""
        attachments: list[MediaAttachment] = []

        raw_attachments: list[dict] = event.get("attachments", [])
        if raw_attachments:
            att = raw_attachments[0]
            mime = att.get("content_type", "application/octet-stream")
            size = att.get("size", 0)
            name = att.get("filename") or "file"
            url = att.get("url")
            if mime.startswith("image/"):
                kind = MessageKind.IMAGE
            else:
                kind = MessageKind.FILE
            attachments.append(
                MediaAttachment(
                    filename=name,
                    mime_type=mime,
                    size_bytes=size,
                    url=url,
                )
            )

        # Reply threading
        reply_to_id: Optional[str] = None
        ref = event.get("message_reference")
        if ref and ref.get("message_id"):
            reply_to_id = str(ref["message_id"])

        return ChannelMessage(
            channel=ChannelType.DISCORD,
            kind=kind,
            text=text,
            sender=sender,
            room_id=channel_id,
            platform_msg_id=msg_id,
            reply_to_platform_id=reply_to_id,
            attachments=attachments,
            raw_payload=event,
        )

    # -----------------------------------------------------------------------
    # Outbound (skcomms → platform)
    # -----------------------------------------------------------------------

    async def send(self, message: ChannelMessage) -> str:
        """
        Deliver a :class:`ChannelMessage` to Discord.

        Uses ``send_file`` for FILE/IMAGE with bytes, ``send_message``
        otherwise.  Returns the Discord message snowflake id.

        Raises:
            AdapterSendError: On unrecoverable failure or missing client.
        """
        if self._client is None:
            raise AdapterSendError(
                "DiscordAdapter.send() requires a connected client. "
                "Call connect() first."
            )

        channel_id = message.room_id

        # Build optional message_reference for replies
        msg_ref: Optional[dict] = None
        if message.reply_to_platform_id:
            msg_ref = {
                "message_id": message.reply_to_platform_id,
                "channel_id": channel_id,
            }

        try:
            if (
                message.kind in (MessageKind.FILE, MessageKind.IMAGE, MessageKind.VOICE)
                and message.attachments
                and message.attachments[0].data is not None
            ):
                att = message.attachments[0]
                result = await self._client.send_file(
                    channel_id,
                    att.data,
                    att.filename,
                    caption=message.text or "",
                )
            else:
                result = await self._client.send_message(
                    channel_id,
                    message.text,
                    message_reference=msg_ref,
                )

            msg_id = result.get("id")
            if not msg_id:
                raise AdapterSendError(
                    f"Discord API error: response missing 'id': {result}"
                )
            return str(msg_id)
        except AdapterSendError:
            raise
        except Exception as exc:
            raise AdapterSendError(
                f"Discord send failed for channel {channel_id}: {exc}"
            ) from exc

    # -----------------------------------------------------------------------
    # Identity mapping
    # -----------------------------------------------------------------------

    async def resolve_fqid(self, platform_id: PlatformIdentity) -> Optional[str]:
        """Return the FQID bound to this Discord user, or None."""
        return self._bindings.get(platform_id.canonical_key)

    async def bind_fqid(
        self,
        platform_id: PlatformIdentity,
        fqid: str,
        trust_level: str,
    ) -> None:
        """
        Persist a verified FQID ↔ Discord-user binding.

        Writes to ``_bindings`` in memory; also persists to YAML unless an
        external ``bindings_store`` was injected (test mode).
        """
        self._bindings[platform_id.canonical_key] = fqid
        logger.info(
            "bound %s → %s (trust=%s)", platform_id.canonical_key, fqid, trust_level
        )
        if not self._external_bindings:
            self._save_bindings()

    # -----------------------------------------------------------------------
    # Presence
    # -----------------------------------------------------------------------

    async def set_presence(self, agent_fqid: str, status: str) -> None:
        """
        Send a typing indicator to the configured channels.

        TODO: Implement via Discord ``POST /channels/{id}/typing`` for each
              active channel when ``capabilities().typing_hint == True``.
        """
        logger.debug("discord set_presence stub: agent=%s status=%s", agent_fqid, status)

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _build_discord_client(self) -> Optional[DiscordClientProtocol]:
        """
        Construct a real discord.py-based client wrapped to satisfy
        :class:`DiscordClientProtocol`.

        Returns ``None`` if ``discord.py`` is not installed or ``bot_token``
        is not configured.  No network connection is made here; that happens
        inside :meth:`connect` when the returned wrapper's ``connect()`` is
        called.

        Token resolution (in priority order):
          1. ``bot_token`` set in the config dict passed to ``__init__``.
          2. ``DISCORD_BOT_TOKEN`` environment variable.

        Install dep: ``pip install "skcomms[discord]"``
        """
        import os

        token = self._bot_token or os.environ.get("DISCORD_BOT_TOKEN", "")
        if not token:
            logger.warning(
                "DiscordAdapter: no bot_token configured and DISCORD_BOT_TOKEN not set. "
                "Pass discord_client= explicitly or set the env var."
            )
            return None
        try:
            import discord  # noqa: F401 — imported for availability check
        except ImportError:
            logger.warning(
                "discord.py not installed — install with: "
                "pip install 'skcomms[discord]'  (or: pip install discord.py)"
            )
            return None

        return _DiscordPyClientWrapper(token)

    def _load_bindings(self) -> None:
        """Load FQID bindings from the YAML identity store."""
        try:
            import yaml
        except ImportError:
            logger.warning("pyyaml not available — skipping bindings load")
            return
        p = Path(self._id_store_path).expanduser()
        if p.exists():
            try:
                loaded = yaml.safe_load(p.read_text()) or {}
                self._bindings.update(loaded)
                logger.debug("loaded %d binding(s) from %s", len(loaded), p)
            except Exception as exc:
                logger.warning("failed to load bindings from %s: %s", p, exc)

    def _save_bindings(self) -> None:
        """Persist FQID bindings to the YAML identity store."""
        try:
            import yaml
        except ImportError:
            logger.warning("pyyaml not available — skipping bindings save")
            return
        p = Path(self._id_store_path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            p.write_text(yaml.dump(self._bindings))
            logger.debug("saved %d binding(s) to %s", len(self._bindings), p)
        except Exception as exc:
            logger.warning("failed to save bindings to %s: %s", p, exc)
