"""
TelegramAdapter — Telegram Bot API channel adapter (Batch C2).

Replaces the bespoke Hermes path for the DR-Chiro group (chat id -5134021983)
and generalizes to any configured Telegram chat.

Config block in ``~/.skcomm/config.yml``::

    adapters:
      telegram:
        enabled: true
        bot_token: "${SKCOMMS_TG_BOT_TOKEN}"
        poll_interval_s: 2
        rooms:
          dr_chiro:
            chat_id: "-5134021983"
            agent_fqid: "lumina@skworld.io"
            allow_untrusted: true
        identity_store: "~/.skcomm/adapters/telegram-ids.yaml"

Implementation notes
--------------------
This skeleton uses raw ``httpx`` for clarity.  In production, replace the
``_poll`` / ``send`` internals with ``python-telegram-bot >= 20`` (async,
webhook support, auto-retry) by wrapping its ``Application`` object and
translating ``Update`` objects to ``ChannelMessage``.

The adapter is designed to be unit-testable without any Telegram credentials:
pass ``httpx_client_factory`` to inject a mock HTTP client, and
``bindings_store`` to supply an in-memory identity map instead of YAML on disk.

TODO (C2 live wiring):
  - Wire ``_poll`` to real ``getUpdates`` (currently stubbed — see method body).
  - Wire ``send`` to real Telegram ``sendMessage`` / ``sendDocument`` endpoints.
  - Add ``python-telegram-bot >= 20`` as an optional dep (``telegram`` extra).
  - Implement ``set_presence`` (typing indicator via ``sendChatAction``).
  - Handle Telegram reaction events (``message_reaction`` update type, Bot API 7.0+).
  - Implement media download in ``_normalize`` (fetch voice/photo bytes from
    ``getFile`` before yielding, or yield with url only and let the hub fetch).
  - Add per-room ``agent_fqid`` routing so the correct agent receives each room.
  - Support webhook mode (add ``set_webhook`` + FastAPI route) for lower latency.

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §6
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import AsyncIterator, Callable, Optional

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

logger = logging.getLogger("skcomms.adapters.telegram")

# ---------------------------------------------------------------------------
# Type alias for injectable HTTP client factory (for testing)
# ---------------------------------------------------------------------------
HttpxClientFactory = Callable[[], "httpx.AsyncClient"]  # type: ignore[name-defined]


class TelegramAdapter(ChannelAdapter):
    """
    Telegram Bot API adapter.

    Args:
        config: Adapter config dict (see module docstring for shape).
        httpx_client_factory: Optional factory for the async HTTP client.
            Defaults to ``httpx.AsyncClient`` if httpx is available.
            Tests pass a factory that returns a mock/stub client.
        bindings_store: Optional dict used as the in-memory identity map
            instead of the YAML file on disk.  Useful for unit testing.
    """

    channel_type = ChannelType.TELEGRAM
    adapter_name = "telegram"

    # Base URL for Bot API calls — separated for testing / proxy support.
    _API_BASE = "https://api.telegram.org"

    def __init__(
        self,
        config: dict,
        httpx_client_factory: Optional[HttpxClientFactory] = None,
        bindings_store: Optional[dict[str, str]] = None,
    ) -> None:
        self._token = config.get("bot_token", "")
        self._poll_s = config.get("poll_interval_s", 2)
        self._rooms: dict[str, dict] = config.get("rooms", {})
        self._id_store_path = config.get(
            "identity_store", "~/.skcomm/adapters/telegram-ids.yaml"
        )
        self._last_update_id: int = 0
        self._running = False

        # FQID bindings: canonical_key (str) → fqid (str)
        # If an external bindings_store is injected (tests), use it directly
        # (no YAML I/O).
        self._bindings: dict[str, str] = bindings_store if bindings_store is not None else {}
        self._external_bindings = bindings_store is not None

        # HTTP client factory — injected for tests, real httpx in production.
        self._httpx_factory = httpx_client_factory

        # Set when connected
        self._bot_username: Optional[str] = None

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Validate bot token and load identity bindings.

        TODO: Replace stub with real ``getMe`` call when httpx is available.
              Currently skips the network call to keep the skeleton importable
              in environments without ``httpx``.
        """
        if not self._token:
            raise AdapterAuthError("Telegram bot_token is not configured")

        # TODO: Uncomment when httpx is wired in production:
        #
        #   async with self._make_client() as c:
        #       r = await c.get(f"{self._API_BASE}/bot{self._token}/getMe")
        #       if r.status_code == 401:
        #           raise AdapterAuthError("invalid Telegram bot token")
        #       r.raise_for_status()
        #       me = r.json()["result"]
        #   self._bot_username = me.get("username")
        #   logger.info("telegram adapter connected as @%s", self._bot_username)

        self._bot_username = "telegram_bot"  # placeholder until real getMe

        if not self._external_bindings:
            self._load_bindings()

        self._running = True
        logger.info("telegram adapter connected (stub mode)")

    async def disconnect(self) -> None:
        """Stop the inbound polling loop."""
        self._running = False
        logger.info("telegram adapter disconnected")

    async def health(self) -> AdapterHealth:
        """
        Return a health snapshot.

        TODO: Perform a real ``getMe`` latency check when httpx is available.
        """
        # TODO: real latency check:
        #   async with self._make_client(timeout=5) as c:
        #       r = await c.get(f"{self._API_BASE}/bot{self._token}/getMe")
        #       return AdapterHealth(
        #           adapter_name=self.adapter_name,
        #           connected=r.status_code == 200,
        #           latency_ms=r.elapsed.total_seconds() * 1000,
        #       )
        return AdapterHealth(
            adapter_name=self.adapter_name,
            connected=self._running,
            latency_ms=None,
        )

    def capabilities(self) -> AdapterCapabilities:
        """Telegram Bot API capabilities."""
        return AdapterCapabilities(
            text=True,
            files=True,
            images=True,
            voice_notes=True,  # Telegram voice messages / audio
            video=True,
            reactions=True,  # emoji reactions (Bot API 7.0+)
            threads=True,  # reply-chain as thread
            read_receipts=False,
            typing_hint=True,
            max_text_bytes=4096,
        )

    # -----------------------------------------------------------------------
    # Inbound (platform → skcomms)
    # -----------------------------------------------------------------------

    async def inbound(self) -> AsyncIterator[ChannelMessage]:
        """
        Long-poll ``getUpdates`` and yield one ``ChannelMessage`` per event.

        TODO: Replace ``_poll`` stub with real Bot API long-polling or webhook
              integration.
        """
        while self._running:
            updates = await self._poll()
            for update in updates:
                msg = self._normalize(update)
                if msg is not None:
                    yield msg
            await asyncio.sleep(self._poll_s)

    async def _poll(self) -> list[dict]:
        """
        Fetch pending updates from Telegram.

        TODO: Implement real ``getUpdates`` call:

            params = {"offset": self._last_update_id + 1, "timeout": 10}
            async with self._make_client(timeout=15) as c:
                r = await c.get(
                    f"{self._API_BASE}/bot{self._token}/getUpdates",
                    params=params,
                )
                r.raise_for_status()
                updates = r.json().get("result", [])
                if updates:
                    self._last_update_id = updates[-1]["update_id"]
                return updates
        """
        # TODO: wire real getUpdates — stub returns empty list
        return []

    def _normalize(self, update: dict) -> Optional[ChannelMessage]:
        """
        Translate a raw Telegram ``Update`` dict into a ``ChannelMessage``.

        Handles text, photo, voice, document, and sticker updates.
        Unknown update types are dropped with a debug log.

        This method is pure (no I/O) and fully unit-testable by passing
        a synthetic update dict.

        Telegram update shapes handled:

        * ``update.message`` — new message
        * ``update.edited_message`` — edited message (treated as new inbound)
        * Subfields: ``text``, ``caption``, ``voice``, ``audio``, ``photo``,
          ``document``, ``sticker``

        TODO: Handle ``message_reaction`` for REACTION kind (Bot API 7.0+).
        TODO: Handle ``callback_query`` for inline keyboard interactions.
        """
        tg_msg = update.get("message") or update.get("edited_message")
        if not tg_msg:
            logger.debug("dropping unhandled update type: %s", list(update.keys()))
            return None

        chat = tg_msg["chat"]
        user = tg_msg.get("from", {})

        sender = PlatformIdentity(
            channel=ChannelType.TELEGRAM,
            platform_id=str(user.get("id", "unknown")),
            platform_name=(
                f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
                or user.get("username", "unknown")
            ),
            room_id=str(chat["id"]),
            room_name=chat.get("title") or chat.get("username"),
        )

        # Determine kind, text, and attachments
        kind = MessageKind.TEXT
        text: str = tg_msg.get("text") or tg_msg.get("caption") or ""
        attachments: list[MediaAttachment] = []

        if "voice" in tg_msg or "audio" in tg_msg:
            kind = MessageKind.VOICE
            blob = tg_msg.get("voice") or tg_msg.get("audio")
            attachments.append(
                MediaAttachment(
                    filename=blob.get("file_name", "voice.ogg"),
                    mime_type=blob.get("mime_type", "audio/ogg"),
                    size_bytes=blob.get("file_size", 0),
                    # TODO: populate url via getFile API call
                )
            )
        elif "photo" in tg_msg:
            kind = MessageKind.IMAGE
            photo = tg_msg["photo"][-1]  # largest size
            attachments.append(
                MediaAttachment(
                    filename="photo.jpg",
                    mime_type="image/jpeg",
                    size_bytes=photo.get("file_size", 0),
                    # TODO: populate url via getFile API call
                )
            )
        elif "document" in tg_msg:
            kind = MessageKind.FILE
            doc = tg_msg["document"]
            attachments.append(
                MediaAttachment(
                    filename=doc.get("file_name", "file"),
                    mime_type=doc.get("mime_type", "application/octet-stream"),
                    size_bytes=doc.get("file_size", 0),
                    # TODO: populate url via getFile API call
                )
            )
        elif "sticker" in tg_msg:
            kind = MessageKind.STICKER
            s = tg_msg["sticker"]
            text = s.get("emoji", "")

        return ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=kind,
            text=text,
            sender=sender,
            room_id=str(chat["id"]),
            platform_msg_id=str(tg_msg["message_id"]),
            reply_to_platform_id=(
                str(tg_msg["reply_to_message"]["message_id"])
                if "reply_to_message" in tg_msg
                else None
            ),
            attachments=attachments,
            raw_payload=update,
        )

    # -----------------------------------------------------------------------
    # Outbound (skcomms → platform)
    # -----------------------------------------------------------------------

    async def send(self, message: ChannelMessage) -> str:
        """
        Deliver a ChannelMessage to Telegram.

        TODO: Implement real ``sendMessage`` / ``sendDocument`` calls:

            params = {"chat_id": message.room_id}
            endpoint = "sendMessage"

            if message.kind in (MessageKind.TEXT, MessageKind.STICKER):
                params["text"] = message.text
                if message.reply_to_platform_id:
                    params["reply_to_message_id"] = message.reply_to_platform_id
            elif message.kind == MessageKind.FILE and message.attachments:
                endpoint = "sendDocument"
                params["caption"] = message.text
                # TODO: multipart upload for file bytes

            async with self._make_client() as c:
                r = await c.post(
                    f"{self._API_BASE}/bot{self._token}/{endpoint}",
                    json=params,
                )
                r.raise_for_status()
                result = r.json()["result"]
                return str(result["message_id"])

        For now, raise AdapterSendError so callers can distinguish "not wired"
        from a silent no-op.
        """
        # TODO: wire real sendMessage — stub raises to signal not-yet-implemented
        raise AdapterSendError(
            "TelegramAdapter.send() is not yet wired to the Bot API. "
            "Set bot_token and uncomment the real implementation."
        )

    # -----------------------------------------------------------------------
    # Identity mapping
    # -----------------------------------------------------------------------

    async def resolve_fqid(self, platform_id: PlatformIdentity) -> Optional[str]:
        """Return the FQID bound to this Telegram user, or None."""
        return self._bindings.get(platform_id.canonical_key)

    async def bind_fqid(
        self,
        platform_id: PlatformIdentity,
        fqid: str,
        trust_level: str,
    ) -> None:
        """
        Persist a verified FQID ↔ Telegram-user binding.

        Writes to the in-memory ``_bindings`` dict; also persists to disk as
        YAML unless an external bindings_store was injected (test mode).
        """
        self._bindings[platform_id.canonical_key] = fqid
        logger.info(
            "bound %s → %s (trust=%s)", platform_id.canonical_key, fqid, trust_level
        )
        if not self._external_bindings:
            self._save_bindings()

    # -----------------------------------------------------------------------
    # Presence (optional — capabilities().typing_hint = True)
    # -----------------------------------------------------------------------

    async def set_presence(self, agent_fqid: str, status: str) -> None:
        """
        Send a typing indicator to all configured rooms.

        TODO: Implement via ``sendChatAction`` (action="typing") for each
              room whose ``agent_fqid`` matches.
        """
        # TODO: wire sendChatAction per configured room
        logger.debug("set_presence stub called: agent=%s status=%s", agent_fqid, status)

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _make_client(self, timeout: float = 10.0):
        """
        Return an async HTTP client.

        Uses the injected factory (tests) or real httpx (production).
        """
        if self._httpx_factory is not None:
            return self._httpx_factory()
        try:
            import httpx

            return httpx.AsyncClient(timeout=timeout)
        except ImportError as exc:
            raise ImportError(
                "httpx is required for TelegramAdapter. "
                "Install it: pip install httpx"
            ) from exc

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
