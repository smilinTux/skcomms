"""
TelegramAdapter — Telethon (user-session) channel adapter (Batch C2).

Replaces the bespoke Hermes path for the DR-Chiro group (chat id -5134021983)
and generalizes to any configured Telegram chat.

Production back-end: **Telethon** (user session), which lets Lumina participate
as a first-class Telegram user rather than a bot — required for group membership
without an invite link and for reading message history in groups where the account
is already a member.

The Telethon client is **injectable** (pass ``telethon_client`` to the constructor)
so the adapter is fully unit-testable without any live credentials.

Config block in ``~/.skcomm/config.yml``::

    adapters:
      telegram:
        enabled: true
        # Telethon user-session path (preferred):
        session_file: "~/.skcapstone/agents/lumina/telegram.session"
        api_id: "${TELEGRAM_API_ID}"
        api_hash: "${TELEGRAM_API_HASH}"
        poll_interval_s: 2
        rooms:
          dr_chiro:
            chat_id: "-5134021983"
            agent_fqid: "lumina@skworld.io"
            allow_untrusted: true
        identity_store: "~/.skcomm/adapters/telegram-ids.yaml"

Known gap
---------
The Lumina user account is **not currently a member** of -5134021983 (DR-Chiro).
The adapter is wired and correct; polling that group will return an empty update
list (or a channel-not-found error) until the account is added to the group.
Validate end-to-end by adding the account first (see C2 runbook).

Implementation notes
--------------------
* The adapter accepts an optional ``telethon_client`` (a :class:`TelethonClientProtocol`
  instance).  Tests pass a :class:`FakeTelethonClient`; production builds pass a real
  ``telethon.TelegramClient``.
* An optional ``httpx_client_factory`` is retained for the Bot-API health check path —
  used only when ``telethon_client`` is *not* provided and ``bot_token`` is configured.
* ``bindings_store``: inject an in-memory dict to skip YAML I/O in tests.

TODO (post-C2, live wiring):
  - Implement ``set_presence`` (Telethon ``client.action(chat, 'typing')``).
  - Handle Telegram reaction events (Telethon ``events.MessageReacted``).
  - Implement media download in ``_normalize_telethon`` (``client.download_media``).
  - Add per-room ``agent_fqid`` routing so the correct agent receives each room.
  - Support webhook mode as a config option for lower latency (C3).
  - Handle the membership-gap for -5134021983 once Chef adds the account.

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §6
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Optional, Protocol, runtime_checkable

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
# Type aliases / protocols for injectable clients
# ---------------------------------------------------------------------------

HttpxClientFactory = Callable[[], "httpx.AsyncClient"]  # type: ignore[name-defined]


@runtime_checkable
class TelethonClientProtocol(Protocol):
    """
    Structural protocol for the injectable Telethon client.

    Both the real ``telethon.TelegramClient`` and the test-only
    :class:`FakeTelethonClient` satisfy this interface.
    """

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...

    def is_connected(self) -> bool: ...

    async def is_user_authorized(self) -> bool: ...

    async def get_me(self) -> Any: ...

    async def get_entity(self, entity: Any) -> Any: ...

    def iter_messages(
        self,
        entity: Any,
        *,
        min_id: int = 0,
        limit: Optional[int] = None,
    ) -> Any:
        """Returns an async iterable of Message objects."""
        ...

    async def send_message(self, entity: Any, message: str, **kwargs: Any) -> Any: ...

    async def send_file(self, entity: Any, file: Any, **kwargs: Any) -> Any: ...


# ---------------------------------------------------------------------------
# TelegramAdapter
# ---------------------------------------------------------------------------


class TelegramAdapter(ChannelAdapter):
    """
    Telegram adapter using a **Telethon user session** (Batch C2).

    Args:
        config: Adapter config dict (see module docstring for shape).
        telethon_client: Optional injectable Telethon client (or compatible stub).
            When provided, ``_poll`` and ``send`` use this client directly.
            Tests pass a :class:`FakeTelethonClient`; production omits this arg
            and the adapter builds a real ``telethon.TelegramClient`` from config.
        httpx_client_factory: Optional factory for a health-check HTTP client.
            Used only for the Bot-API ``getMe`` health check when ``bot_token``
            is configured and no Telethon client is available.
        bindings_store: Optional dict used as the in-memory identity map instead
            of the YAML file on disk.  Useful for unit testing.
    """

    channel_type = ChannelType.TELEGRAM
    adapter_name = "telegram"

    # Base URL for Bot API calls (health check fallback).
    _API_BASE = "https://api.telegram.org"

    def __init__(
        self,
        config: dict,
        telethon_client: Optional[TelethonClientProtocol] = None,
        httpx_client_factory: Optional[HttpxClientFactory] = None,
        bindings_store: Optional[dict[str, str]] = None,
    ) -> None:
        # --- Core config ---
        self._token = config.get("bot_token", "")
        self._api_id = config.get("api_id")
        self._api_hash = config.get("api_hash")
        self._session_file = config.get(
            "session_file", "~/.skcapstone/agents/lumina/telegram.session"
        )
        self._poll_s = config.get("poll_interval_s", 2)
        self._rooms: dict[str, dict] = config.get("rooms", {})
        self._id_store_path = config.get(
            "identity_store", "~/.skcomm/adapters/telegram-ids.yaml"
        )

        # --- State ---
        # Tracks the highest message_id we have already seen per chat_id.
        # Used so we only yield *new* messages on each poll cycle.
        self._last_seen_id: dict[str, int] = {}
        self._running = False

        # --- Identity bindings ---
        # In-memory dict: canonical_key → fqid
        self._bindings: dict[str, str] = (
            bindings_store if bindings_store is not None else {}
        )
        self._external_bindings = bindings_store is not None

        # --- Injectable clients ---
        self._telethon: Optional[TelethonClientProtocol] = telethon_client
        self._httpx_factory = httpx_client_factory

        # --- Set after connect ---
        self._bot_username: Optional[str] = None
        self._me: Any = None  # Telethon User/me object

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Authenticate with Telegram and load identity bindings.

        When a real Telethon client is provided (or built from config), calls
        ``client.connect()`` and verifies authorization.  In stub/test mode
        (``FakeTelethonClient``), the same code path runs but hits the fake.
        """
        # Build a real Telethon client if none was injected and we have creds.
        if self._telethon is None:
            self._telethon = self._build_telethon_client()

        if self._telethon is not None:
            await self._telethon.connect()
            authorized = await self._telethon.is_user_authorized()
            if not authorized:
                raise AdapterAuthError(
                    "Telegram user session is not authorized. "
                    "Run the Telethon auth flow first: "
                    f"session_file={self._session_file}"
                )
            self._me = await self._telethon.get_me()
            username = getattr(self._me, "username", None) or getattr(
                self._me, "id", "unknown"
            )
            logger.info("telegram adapter connected as @%s (user session)", username)
        elif self._token:
            # Bot API fallback: only verify the token when an httpx_client_factory
            # is injected (i.e. in tests or explicit live mode).  Without a factory
            # the real httpx call is skipped to keep the adapter importable in
            # environments without network access (matches the C1 skeleton behaviour).
            if self._httpx_factory is not None:
                try:
                    async with self._make_httpx_client() as c:
                        r = await c.get(f"{self._API_BASE}/bot{self._token}/getMe")
                        if r.status_code == 401:
                            raise AdapterAuthError("invalid Telegram bot token")
                        r.raise_for_status()
                        me = r.json()["result"]
                        self._bot_username = me.get("username")
                except AdapterAuthError:
                    raise
                except Exception as exc:
                    raise AdapterConnectError(
                        f"Telegram Bot API unreachable: {exc}"
                    ) from exc
            else:
                # Stub mode — no live getMe; set a placeholder username.
                self._bot_username = "telegram_bot"
            logger.info(
                "telegram adapter connected as @%s (bot mode)",
                self._bot_username or self._token[:8] + "…",
            )
        else:
            raise AdapterAuthError(
                "TelegramAdapter requires either a Telethon client / session_file+api_id+api_hash "
                "or a bot_token."
            )

        if not self._external_bindings:
            self._load_bindings()

        self._running = True
        logger.info("telegram adapter ready")

    async def disconnect(self) -> None:
        """Stop the inbound polling loop and disconnect the Telethon client."""
        self._running = False
        if self._telethon is not None and self._telethon.is_connected():
            await self._telethon.disconnect()
        logger.info("telegram adapter disconnected")

    async def health(self) -> AdapterHealth:
        """
        Return a point-in-time health snapshot.

        Uses the Telethon client's ``is_connected()`` / ``get_me()`` if available,
        or the Bot API ``getMe`` latency check as a fallback.
        """
        import time

        if self._telethon is not None:
            connected = self._telethon.is_connected()
            t0 = time.monotonic()
            try:
                me = await self._telethon.get_me()
                latency_ms = (time.monotonic() - t0) * 1000
                chat_ids = [
                    room.get("chat_id") for room in self._rooms.values() if room.get("chat_id")
                ]
                return AdapterHealth(
                    adapter_name=self.adapter_name,
                    connected=connected and me is not None,
                    latency_ms=latency_ms,
                    error=None,
                    queued_outbound=0,
                )
            except Exception as exc:
                return AdapterHealth(
                    adapter_name=self.adapter_name,
                    connected=False,
                    latency_ms=None,
                    error=str(exc),
                )

        # Bot API fallback — only hit the network when an httpx_client_factory
        # is injected; otherwise report the local _running flag (stub mode).
        if self._token and self._httpx_factory is not None:
            try:
                async with self._make_httpx_client(timeout=5.0) as c:
                    t0 = time.monotonic()
                    r = await c.get(f"{self._API_BASE}/bot{self._token}/getMe")
                    latency_ms = (time.monotonic() - t0) * 1000
                    return AdapterHealth(
                        adapter_name=self.adapter_name,
                        connected=r.status_code == 200,
                        latency_ms=latency_ms,
                    )
            except Exception as exc:
                return AdapterHealth(
                    adapter_name=self.adapter_name,
                    connected=False,
                    latency_ms=None,
                    error=str(exc),
                )

        # Stub / no-factory path: report local running state.
        return AdapterHealth(
            adapter_name=self.adapter_name,
            connected=self._running,
            latency_ms=None,
        )

    def capabilities(self) -> AdapterCapabilities:
        """Telegram capabilities (user session or bot — same surface)."""
        return AdapterCapabilities(
            text=True,
            files=True,
            images=True,
            voice_notes=True,  # Telegram voice messages / audio
            video=True,
            reactions=True,  # emoji reactions (Bot API 7.0+ / Telethon)
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
        Long-poll for new messages and yield one ``ChannelMessage`` per event.

        When a Telethon client is present, iterates ``client.iter_messages``
        for each configured room, advancing the per-chat ``_last_seen_id``
        watermark so only *new* messages are surfaced on each cycle.

        When no Telethon client is available (e.g. legacy Bot API mode), calls
        ``_poll`` (which returns raw update dicts) and normalises them via
        ``_normalize``.
        """
        while self._running:
            if self._telethon is not None:
                updates = await self._poll_telethon()
                for msg in updates:
                    yield msg
            else:
                raw_updates = await self._poll()
                for update in raw_updates:
                    msg = self._normalize(update)
                    if msg is not None:
                        yield msg
            await asyncio.sleep(self._poll_s)

    async def _poll_telethon(self) -> list[ChannelMessage]:
        """
        Fetch new messages from all configured rooms via Telethon.

        Advances the per-chat ``_last_seen_id`` watermark on each call.
        Returns a list (not a generator) so the caller can yield each item
        after releasing the lock.
        """
        results: list[ChannelMessage] = []
        for room_name, room_cfg in self._rooms.items():
            chat_id = room_cfg.get("chat_id")
            if not chat_id:
                continue
            min_id = self._last_seen_id.get(chat_id, 0)
            new_max = min_id
            try:
                async for tg_msg in self._telethon.iter_messages(
                    chat_id, min_id=min_id, limit=100
                ):
                    msg_id = getattr(tg_msg, "id", 0)
                    if msg_id > new_max:
                        new_max = msg_id
                    normalized = self._normalize_telethon(tg_msg, chat_id, room_cfg)
                    if normalized is not None:
                        results.append(normalized)
            except Exception:
                logger.exception("poll error for room %s (chat_id=%s)", room_name, chat_id)
            if new_max > min_id:
                self._last_seen_id[chat_id] = new_max
        return results

    def _normalize_telethon(
        self, tg_msg: Any, chat_id: str, room_cfg: dict
    ) -> Optional[ChannelMessage]:
        """
        Translate a Telethon ``Message`` object into a ``ChannelMessage``.

        Handles text, voice/audio, photo, document, and sticker payloads.

        Args:
            tg_msg: A ``telethon.tl.types.Message`` (or compatible stub).
            chat_id: The string chat id for the room this message came from.
            room_cfg: The room config dict (contains ``agent_fqid`` etc.).
        """
        # Sender information
        sender_obj = getattr(tg_msg, "sender", None) or getattr(tg_msg, "from_id", None)
        if sender_obj is None:
            # Channel post with no explicit sender — treat as service message
            logger.debug("dropping Telethon message with no sender: id=%s", tg_msg.id)
            return None

        sender_id = str(getattr(sender_obj, "id", "unknown"))
        first = getattr(sender_obj, "first_name", "") or ""
        last = getattr(sender_obj, "last_name", "") or ""
        username = getattr(sender_obj, "username", None)
        platform_name = f"{first} {last}".strip() or username or sender_id

        # Room/chat info
        chat = getattr(tg_msg, "chat", None) or getattr(tg_msg, "peer_id", None)
        room_name_val = (
            getattr(chat, "title", None)
            or getattr(chat, "username", None)
            or room_cfg.get("agent_fqid")
        )

        sender = PlatformIdentity(
            channel=ChannelType.TELEGRAM,
            platform_id=sender_id,
            platform_name=platform_name,
            room_id=str(chat_id),
            room_name=room_name_val,
        )

        # Determine kind, text, and attachments
        kind = MessageKind.TEXT
        text: str = getattr(tg_msg, "text", "") or getattr(tg_msg, "message", "") or ""
        attachments: list[MediaAttachment] = []

        media = getattr(tg_msg, "media", None)
        if media is not None:
            # Duck-type on attributes rather than class-name to work with real
            # Telethon objects (MessageMediaDocument / MessageMediaPhoto) and
            # with injectable test stubs alike.
            doc = getattr(media, "document", None)
            photo = getattr(media, "photo", None)
            if doc is not None:
                # MessageMediaDocument — could be voice, audio, or generic file
                attrs = getattr(doc, "attributes", [])
                is_voice = any(
                    hasattr(a, "voice") and getattr(a, "voice", False) for a in attrs
                )
                is_audio = any(hasattr(a, "voice") for a in attrs)  # DocumentAttributeAudio
                filename_attr = next(
                    (a for a in attrs if hasattr(a, "file_name")),
                    None,
                )
                fname = (
                    getattr(filename_attr, "file_name", None)
                    or ("voice.ogg" if is_voice else "file")
                )
                mime = getattr(doc, "mime_type", "application/octet-stream") or "application/octet-stream"
                size = getattr(doc, "size", 0) or 0
                if is_voice or is_audio:
                    kind = MessageKind.VOICE
                else:
                    kind = MessageKind.FILE
                attachments.append(
                    MediaAttachment(filename=fname, mime_type=mime, size_bytes=size)
                )
            elif photo is not None:
                # MessageMediaPhoto
                sizes = getattr(photo, "sizes", [])
                photo_size = getattr(sizes[-1], "size", 0) if sizes else 0
                kind = MessageKind.IMAGE
                attachments.append(
                    MediaAttachment(
                        filename="photo.jpg",
                        mime_type="image/jpeg",
                        size_bytes=photo_size or 0,
                    )
                )
        elif getattr(tg_msg, "sticker", None):
            kind = MessageKind.STICKER
            sticker = tg_msg.sticker
            # Telethon sticker emoji is in DocumentAttributeSticker
            attrs = getattr(sticker, "attributes", []) if sticker else []
            emoji = ""
            for a in attrs:
                if "DocumentAttributeSticker" in type(a).__name__:
                    emoji = getattr(a, "alt", "") or ""
                    break
            text = emoji

        reply_to_id: Optional[str] = None
        reply_header = getattr(tg_msg, "reply_to", None)
        if reply_header is not None:
            reply_to_id = str(getattr(reply_header, "reply_to_msg_id", None) or "")
            if reply_to_id == "None" or reply_to_id == "":
                reply_to_id = None

        return ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=kind,
            text=text,
            sender=sender,
            room_id=str(chat_id),
            platform_msg_id=str(tg_msg.id),
            reply_to_platform_id=reply_to_id,
            attachments=attachments,
            raw_payload=None,  # Telethon objects are not JSON-serialisable; omit
        )

    async def _poll(self) -> list[dict]:
        """
        Fetch pending updates from Telegram Bot API (legacy / fallback path).

        Used when no Telethon client is provided and ``bot_token`` is configured.
        Advances ``_last_update_id`` so duplicate updates are not replayed.
        """
        # _last_update_id is stored per-adapter (not per-room) for Bot API mode
        last_id = getattr(self, "_last_update_id", 0)
        params = {"offset": last_id + 1, "timeout": 10}
        try:
            async with self._make_httpx_client(timeout=15.0) as c:
                r = await c.get(
                    f"{self._API_BASE}/bot{self._token}/getUpdates",
                    params=params,
                )
                r.raise_for_status()
                updates = r.json().get("result", [])
                if updates:
                    self._last_update_id = updates[-1]["update_id"]
                return updates
        except Exception:
            logger.exception("poll error (Bot API)")
            return []

    def _normalize(self, update: dict) -> Optional[ChannelMessage]:
        """
        Translate a raw Telegram Bot API ``Update`` dict into a ``ChannelMessage``.

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

        Uses the Telethon client if available, otherwise the Bot API via httpx.
        Returns the platform message id as a string.

        Raises:
            AdapterSendError: On unrecoverable failure.
        """
        if self._telethon is not None:
            return await self._send_telethon(message)
        if self._token:
            return await self._send_bot_api(message)
        raise AdapterSendError(
            "TelegramAdapter.send() requires either a Telethon client or a bot_token. "
            "Neither is configured."
        )

    async def _send_telethon(self, message: ChannelMessage) -> str:
        """
        Deliver via Telethon client.

        Currently supports TEXT and STICKER (send_message) and FILE (send_file).
        Voice/Image with bytes payload will be added when media download is wired.
        """
        chat_id = message.room_id
        try:
            if message.kind in (MessageKind.TEXT, MessageKind.STICKER):
                reply_to = (
                    int(message.reply_to_platform_id)
                    if message.reply_to_platform_id
                    else None
                )
                sent = await self._telethon.send_message(
                    chat_id,
                    message.text,
                    reply_to=reply_to,
                )
                return str(getattr(sent, "id", "unknown"))
            elif message.kind in (MessageKind.FILE, MessageKind.IMAGE, MessageKind.VOICE):
                if message.attachments and message.attachments[0].data is not None:
                    att = message.attachments[0]
                    sent = await self._telethon.send_file(
                        chat_id,
                        att.data,
                        caption=message.text or None,
                        force_document=(message.kind == MessageKind.FILE),
                    )
                    return str(getattr(sent, "id", "unknown"))
                else:
                    # No local bytes — fall through to text-only message with caption
                    sent = await self._telethon.send_message(chat_id, message.text)
                    return str(getattr(sent, "id", "unknown"))
            else:
                # Unsupported kind — send as text
                sent = await self._telethon.send_message(chat_id, message.text)
                return str(getattr(sent, "id", "unknown"))
        except Exception as exc:
            raise AdapterSendError(
                f"Telethon send failed for chat {chat_id}: {exc}"
            ) from exc

    async def _send_bot_api(self, message: ChannelMessage) -> str:
        """
        Deliver via Telegram Bot API (httpx fallback path).

        Handles text and file messages.  Voice/Image upload is a TODO.
        """
        params: dict = {"chat_id": message.room_id}
        endpoint = "sendMessage"

        if message.kind in (MessageKind.TEXT, MessageKind.STICKER):
            params["text"] = message.text
            if message.reply_to_platform_id:
                params["reply_to_message_id"] = message.reply_to_platform_id
        elif message.kind == MessageKind.FILE and message.attachments:
            endpoint = "sendDocument"
            params["caption"] = message.text
            # TODO: multipart upload for file bytes
        else:
            params["text"] = message.text

        try:
            async with self._make_httpx_client() as c:
                r = await c.post(
                    f"{self._API_BASE}/bot{self._token}/{endpoint}",
                    json=params,
                )
                r.raise_for_status()
                result = r.json()["result"]
                return str(result["message_id"])
        except Exception as exc:
            raise AdapterSendError(
                f"Bot API send failed (endpoint={endpoint}): {exc}"
            ) from exc

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
    # Presence (optional — capabilities().typing_hint = True)
    # -----------------------------------------------------------------------

    async def set_presence(self, agent_fqid: str, status: str) -> None:
        """
        Send a typing indicator to all configured rooms.

        TODO: Implement via Telethon ``async with client.action(chat, 'typing'): ...``
              or Bot API ``sendChatAction`` for each room whose ``agent_fqid`` matches.
        """
        logger.debug("set_presence stub called: agent=%s status=%s", agent_fqid, status)

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _build_telethon_client(self) -> Optional[Any]:
        """
        Attempt to construct a real Telethon client from config.

        Returns None if Telethon is not installed or config is incomplete.
        """
        if not self._api_id or not self._api_hash:
            return None
        try:
            from telethon import TelegramClient

            session_path = str(Path(self._session_file).expanduser())
            return TelegramClient(session_path, int(self._api_id), self._api_hash)
        except ImportError:
            logger.warning(
                "Telethon not installed — user session mode unavailable. "
                "Install with: pip install telethon"
            )
            return None

    def _make_httpx_client(self, timeout: float = 10.0):
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
                "httpx is required for the TelegramAdapter Bot API path. "
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
