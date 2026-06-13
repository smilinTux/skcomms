"""
Unit tests for TelegramAdapter — Batch C2 (Telethon user-session path).

All tests use a ``FakeTelethonClient`` that satisfies :class:`TelethonClientProtocol`
without making any network connections.  No real Telegram credentials are required.

Coverage:
  - FakeTelethonClient satisfies TelethonClientProtocol (structural check)
  - connect() / disconnect() lifecycle
  - connect() raises AdapterAuthError when unauthorized
  - health() reflects client state
  - _poll_telethon() watermarks advance correctly across two poll cycles
  - inbound() yields normalized ChannelMessages from fake Telethon messages
  - _normalize_telethon():
      * text message
      * voice/audio message (MessageMediaDocument + audio attribute)
      * photo message (MessageMediaPhoto)
      * file/document message (MessageMediaDocument, no audio attr)
      * sticker (sticker attr + DocumentAttributeSticker)
      * message with no sender is dropped
      * reply_to_msg_id propagated
  - send() routes to Telethon send_message (TEXT)
  - send() routes to Telethon send_file (FILE with bytes)
  - send() raises AdapterSendError on Telethon failure
  - send() with no client and no token raises AdapterSendError
  - DR-Chiro chat id (-5134021983) is the bound chat in room config
  - identity binding: resolve / bind round-trip (in-memory store)
  - capabilities() flags
  - set_presence() is a no-op stub (does not raise)
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Optional
from unittest.mock import AsyncMock

import pytest

from skcomms.adapters import (
    AdapterHealth,
    ChannelMessage,
    ChannelType,
    MediaAttachment,
    MessageKind,
    PlatformIdentity,
    TelegramAdapter,
    TrustLevel,
)
from skcomms.adapters.base import AdapterAuthError, AdapterSendError
from skcomms.adapters.telegram import TelethonClientProtocol

# ---------------------------------------------------------------------------
# Helpers — fake Telethon object tree
# ---------------------------------------------------------------------------


class FakeSentMessage:
    """Returned by FakeTelethonClient.send_message / send_file."""

    def __init__(self, msg_id: int = 1001) -> None:
        self.id = msg_id


class FakeUser:
    """Minimal stand-in for telethon.types.User."""

    def __init__(
        self,
        user_id: int = 123456789,
        first_name: str = "Chef",
        last_name: str = "David",
        username: str = "chefdavid",
    ) -> None:
        self.id = user_id
        self.first_name = first_name
        self.last_name = last_name
        self.username = username


class FakeChat:
    """Minimal stand-in for telethon.types.Chat / Channel."""

    def __init__(self, chat_id: int = -5134021983, title: str = "DR Chiro") -> None:
        self.id = chat_id
        self.title = title
        self.username = None


class _FakeDocumentAttributeAudio:
    """Mimics telethon.tl.types.DocumentAttributeAudio."""

    def __init__(self, voice: bool = False, duration: int = 5) -> None:
        self.voice = voice
        self.duration = duration


class _FakeDocumentAttributeFilename:
    """Mimics telethon.tl.types.DocumentAttributeFilename."""

    def __init__(self, file_name: str = "file.bin") -> None:
        self.file_name = file_name


class _FakeDocumentAttributeSticker:
    """Mimics telethon.tl.types.DocumentAttributeSticker."""

    def __init__(self, alt: str = "😎") -> None:
        self.alt = alt


class FakeDocument:
    """Mimics telethon.tl.types.Document."""

    def __init__(
        self,
        doc_id: int = 999,
        mime_type: str = "application/octet-stream",
        size: int = 1024,
        attributes: Optional[list] = None,
    ) -> None:
        self.id = doc_id
        self.mime_type = mime_type
        self.size = size
        self.attributes = attributes or []


class FakePhotoSize:
    def __init__(self, size: int = 80000) -> None:
        self.size = size


class FakePhoto:
    def __init__(self, sizes: Optional[list] = None) -> None:
        self.sizes = sizes or [FakePhotoSize(1000), FakePhotoSize(80000)]


class FakeMediaDocument:
    """Mimics MessageMediaDocument — wraps a FakeDocument."""

    def __init__(self, document: FakeDocument) -> None:
        self.document = document


class FakeMediaPhoto:
    """Mimics MessageMediaPhoto."""

    def __init__(self, photo: Optional[FakePhoto] = None) -> None:
        self.photo = photo or FakePhoto()


class FakeReplyHeader:
    def __init__(self, reply_to_msg_id: int = 10) -> None:
        self.reply_to_msg_id = reply_to_msg_id


class FakeTGMessage:
    """
    Minimal Telethon Message stand-in.

    Only sets the attributes that ``_normalize_telethon`` reads.
    """

    def __init__(
        self,
        msg_id: int = 42,
        text: str = "",
        sender: Optional[FakeUser] = None,
        chat: Optional[FakeChat] = None,
        media: Any = None,
        sticker: Any = None,
        reply_to: Optional[FakeReplyHeader] = None,
    ) -> None:
        self.id = msg_id
        self.text = text
        self.message = text  # Telethon uses .message for the body
        self.sender = sender or FakeUser()
        self.chat = chat or FakeChat()
        self.media = media
        self.sticker = sticker
        self.reply_to = reply_to


# ---------------------------------------------------------------------------
# FakeTelethonClient — satisfies TelethonClientProtocol
# ---------------------------------------------------------------------------


class FakeTelethonClient:
    """
    In-memory Telethon client stub for unit testing.

    Pre-loads a message queue per chat_id.  ``iter_messages`` returns all
    messages with id > min_id (simulating real Telethon pagination behaviour).
    ``send_message`` / ``send_file`` capture calls and return a FakeSentMessage.

    By default, ``is_user_authorized()`` returns True.  Set
    ``authorized=False`` to simulate an unauthorized session.
    """

    def __init__(
        self,
        messages: Optional[dict[str, list[FakeTGMessage]]] = None,
        authorized: bool = True,
        me: Optional[FakeUser] = None,
        raise_on_send: bool = False,
    ) -> None:
        # chat_id (str) → list of FakeTGMessages available
        self._messages: dict[str, list[FakeTGMessage]] = messages or {}
        self._authorized = authorized
        self._me = me or FakeUser()
        self._connected = False
        self._raise_on_send = raise_on_send

        # Captured outbound calls
        self.sent_messages: list[dict] = []
        self.sent_files: list[dict] = []

    # --- Protocol implementation ---

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    async def is_user_authorized(self) -> bool:
        return self._authorized

    async def get_me(self) -> Optional[FakeUser]:
        if not self._authorized:
            return None
        return self._me

    async def get_entity(self, entity: Any) -> Any:
        return entity

    def iter_messages(
        self,
        entity: Any,
        *,
        min_id: int = 0,
        limit: Optional[int] = None,
    ) -> "_FakeAsyncIter":
        chat_id = str(entity)
        msgs = self._messages.get(chat_id, [])
        # Only yield messages with id > min_id
        filtered = [m for m in msgs if m.id > min_id]
        if limit is not None:
            filtered = filtered[:limit]
        return _FakeAsyncIter(filtered)

    async def send_message(self, entity: Any, message: str, **kwargs: Any) -> FakeSentMessage:
        if self._raise_on_send:
            raise RuntimeError("send_message: simulated failure")
        rec = {"entity": entity, "message": message, **kwargs}
        self.sent_messages.append(rec)
        return FakeSentMessage(msg_id=1001 + len(self.sent_messages))

    async def send_file(self, entity: Any, file: Any, **kwargs: Any) -> FakeSentMessage:
        if self._raise_on_send:
            raise RuntimeError("send_file: simulated failure")
        rec = {"entity": entity, "file": file, **kwargs}
        self.sent_files.append(rec)
        return FakeSentMessage(msg_id=2001 + len(self.sent_files))


class _FakeAsyncIter:
    """Async iterator wrapper for a plain list (returned by iter_messages)."""

    def __init__(self, items: list) -> None:
        self._items = iter(items)

    def __aiter__(self) -> "_FakeAsyncIter":
        return self

    async def __anext__(self) -> Any:
        try:
            return next(self._items)
        except StopIteration:
            raise StopAsyncIteration


# ---------------------------------------------------------------------------
# Verify FakeTelethonClient satisfies the protocol
# ---------------------------------------------------------------------------


def test_fake_client_satisfies_protocol():
    """FakeTelethonClient is a structural subtype of TelethonClientProtocol."""
    client = FakeTelethonClient()
    assert isinstance(client, TelethonClientProtocol), (
        "FakeTelethonClient does not satisfy TelethonClientProtocol. "
        "Missing methods: " + str(
            [m for m in ("connect", "disconnect", "is_connected",
                         "is_user_authorized", "get_me", "get_entity",
                         "iter_messages", "send_message", "send_file")
             if not hasattr(client, m)]
        )
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DR_CHIRO_CHAT_ID = "-5134021983"

DR_CHIRO_CONFIG = {
    "api_id": "12345",
    "api_hash": "fakeapihashhex",
    "session_file": "~/.skcapstone/agents/lumina/telegram.session",
    "poll_interval_s": 0,  # no sleep in tests
    "rooms": {
        "dr_chiro": {
            "chat_id": DR_CHIRO_CHAT_ID,
            "agent_fqid": "lumina@skworld.io",
            "allow_untrusted": True,
        }
    },
    "identity_store": "/tmp/test-telegram-ids.yaml",
}


def _make_adapter(
    client: Optional[FakeTelethonClient] = None,
    config: Optional[dict] = None,
    bindings: Optional[dict[str, str]] = None,
) -> TelegramAdapter:
    return TelegramAdapter(
        config=config or DR_CHIRO_CONFIG,
        telethon_client=client or FakeTelethonClient(),
        bindings_store=bindings or {},
    )


def _text_tg_msg(
    msg_id: int = 1,
    text: str = "hello",
    user_id: int = 111,
    chat_id: int = -5134021983,
) -> FakeTGMessage:
    return FakeTGMessage(
        msg_id=msg_id,
        text=text,
        sender=FakeUser(user_id=user_id, first_name="Chef", last_name="David"),
        chat=FakeChat(chat_id=chat_id, title="DR Chiro"),
    )


# ---------------------------------------------------------------------------
# A. Lifecycle tests
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_connect_sets_running_true(self):
        adapter = _make_adapter()
        assert not adapter._running
        await adapter.connect()
        assert adapter._running

    @pytest.mark.asyncio
    async def test_connect_calls_telethon_connect(self):
        client = FakeTelethonClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        assert client.is_connected()

    @pytest.mark.asyncio
    async def test_disconnect_sets_running_false(self):
        client = FakeTelethonClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not adapter._running

    @pytest.mark.asyncio
    async def test_disconnect_calls_telethon_disconnect(self):
        client = FakeTelethonClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_if_unauthorized(self):
        client = FakeTelethonClient(authorized=False)
        adapter = _make_adapter(client=client)
        with pytest.raises(AdapterAuthError, match="not authorized"):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_with_no_credentials(self):
        """No Telethon client, no token → AdapterAuthError."""
        adapter = TelegramAdapter(
            config={"poll_interval_s": 0},
            telethon_client=None,
            bindings_store={},
        )
        with pytest.raises(AdapterAuthError):
            await adapter.connect()


# ---------------------------------------------------------------------------
# B. Health tests
# ---------------------------------------------------------------------------


class TestHealth:
    @pytest.mark.asyncio
    async def test_health_connected_after_connect(self):
        adapter = _make_adapter()
        await adapter.connect()
        h = await adapter.health()
        assert h.connected is True
        assert h.adapter_name == "telegram"
        assert h.error is None

    @pytest.mark.asyncio
    async def test_health_disconnected_before_connect(self):
        client = FakeTelethonClient()
        # client.is_connected() returns False before connect()
        adapter = _make_adapter(client=client)
        h = await adapter.health()
        assert h.connected is False

    @pytest.mark.asyncio
    async def test_health_error_when_get_me_fails(self):
        client = FakeTelethonClient(authorized=False)
        # Connect normally isn't called here — we simulate a post-connect degradation.
        adapter = _make_adapter(client=client)
        # Force _running=True to bypass "not yet running" branch
        adapter._running = True
        # Client says "connected" but get_me returns None
        client._connected = True
        h = await adapter.health()
        # get_me returns None (unauthorized) → connected=False
        assert h.connected is False

    @pytest.mark.asyncio
    async def test_health_bound_chat_id_in_rooms(self):
        adapter = _make_adapter()
        await adapter.connect()
        # The DR-Chiro chat id must be in rooms config
        chat_ids = [
            room.get("chat_id")
            for room in adapter._rooms.values()
        ]
        assert DR_CHIRO_CHAT_ID in chat_ids, (
            f"DR-Chiro chat id {DR_CHIRO_CHAT_ID} not found in rooms: {chat_ids}"
        )


# ---------------------------------------------------------------------------
# C. _normalize_telethon tests
# ---------------------------------------------------------------------------


class TestNormalizeTelethon:
    def _adapter(self) -> TelegramAdapter:
        return _make_adapter()

    def _room_cfg(self) -> dict:
        return {"chat_id": DR_CHIRO_CHAT_ID, "agent_fqid": "lumina@skworld.io"}

    def test_text_message(self):
        adapter = self._adapter()
        tg_msg = _text_tg_msg(msg_id=42, text="Hello Lumina!")
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg is not None
        assert msg.kind == MessageKind.TEXT
        assert msg.text == "Hello Lumina!"
        assert msg.platform_msg_id == "42"
        assert msg.sender.platform_id == "111"
        assert msg.sender.platform_name == "Chef David"
        assert msg.room_id == DR_CHIRO_CHAT_ID
        assert msg.channel == ChannelType.TELEGRAM

    def test_voice_message(self):
        adapter = self._adapter()
        doc = FakeDocument(
            mime_type="audio/ogg",
            size=12345,
            attributes=[_FakeDocumentAttributeAudio(voice=True, duration=5)],
        )
        tg_msg = FakeTGMessage(
            msg_id=10,
            text="",
            media=FakeMediaDocument(document=doc),
        )
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg is not None
        assert msg.kind == MessageKind.VOICE
        assert len(msg.attachments) == 1
        assert msg.attachments[0].mime_type == "audio/ogg"
        assert msg.attachments[0].size_bytes == 12345
        assert msg.attachments[0].filename == "voice.ogg"

    def test_audio_message_non_voice(self):
        """Audio without voice=True → still VOICE kind."""
        adapter = self._adapter()
        doc = FakeDocument(
            mime_type="audio/mpeg",
            size=500,
            attributes=[_FakeDocumentAttributeAudio(voice=False)],
        )
        tg_msg = FakeTGMessage(msg_id=11, media=FakeMediaDocument(document=doc))
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg.kind == MessageKind.VOICE
        assert msg.attachments[0].mime_type == "audio/mpeg"

    def test_photo_message(self):
        adapter = self._adapter()
        tg_msg = FakeTGMessage(
            msg_id=20,
            text="look at this",
            media=FakeMediaPhoto(photo=FakePhoto(sizes=[FakePhotoSize(1000), FakePhotoSize(80000)])),
        )
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg is not None
        assert msg.kind == MessageKind.IMAGE
        assert msg.text == "look at this"
        assert msg.attachments[0].mime_type == "image/jpeg"
        assert msg.attachments[0].size_bytes == 80000  # last (largest) size

    def test_document_message(self):
        adapter = self._adapter()
        doc = FakeDocument(
            mime_type="application/pdf",
            size=204800,
            attributes=[_FakeDocumentAttributeFilename(file_name="report.pdf")],
        )
        tg_msg = FakeTGMessage(msg_id=30, media=FakeMediaDocument(document=doc))
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg is not None
        assert msg.kind == MessageKind.FILE
        assert msg.attachments[0].filename == "report.pdf"
        assert msg.attachments[0].mime_type == "application/pdf"

    def test_sticker_message(self):
        adapter = self._adapter()
        # Sticker: no media, but tg_msg.sticker is set
        sticker_doc = FakeDocument(
            attributes=[_FakeDocumentAttributeSticker(alt="😎")]
        )
        tg_msg = FakeTGMessage(msg_id=40, text="", sticker=sticker_doc)
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg is not None
        assert msg.kind == MessageKind.STICKER
        assert msg.text == "😎"

    def test_no_sender_returns_none(self):
        adapter = self._adapter()
        tg_msg = FakeTGMessage(msg_id=50, text="ghost")
        tg_msg.sender = None  # type: ignore[assignment]
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg is None

    def test_reply_to_propagated(self):
        adapter = self._adapter()
        tg_msg = FakeTGMessage(
            msg_id=60,
            text="reply",
            reply_to=FakeReplyHeader(reply_to_msg_id=15),
        )
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg is not None
        assert msg.reply_to_platform_id == "15"

    def test_no_reply_to_is_none(self):
        adapter = self._adapter()
        tg_msg = _text_tg_msg(msg_id=61, text="no reply")
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg.reply_to_platform_id is None

    def test_sender_full_name_concatenated(self):
        adapter = self._adapter()
        tg_msg = FakeTGMessage(
            msg_id=70,
            text="hi",
            sender=FakeUser(user_id=7, first_name="Queen", last_name="Lumina"),
        )
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg.sender.platform_name == "Queen Lumina"

    def test_sender_username_fallback(self):
        """When both first_name and last_name are empty, use username."""
        adapter = self._adapter()
        user = FakeUser(user_id=8, first_name="", last_name="", username="anonymous_tg")
        tg_msg = FakeTGMessage(msg_id=71, text="hi", sender=user)
        msg = adapter._normalize_telethon(tg_msg, DR_CHIRO_CHAT_ID, self._room_cfg())
        assert msg.sender.platform_name == "anonymous_tg"


# ---------------------------------------------------------------------------
# D. _poll_telethon watermark tests
# ---------------------------------------------------------------------------


class TestPollTelethon:
    @pytest.mark.asyncio
    async def test_poll_yields_messages_above_watermark(self):
        msgs = [_text_tg_msg(msg_id=i, text=f"msg-{i}") for i in range(1, 6)]
        client = FakeTelethonClient(messages={DR_CHIRO_CHAT_ID: msgs})
        adapter = _make_adapter(client=client)
        # watermark = 0 → all 5 messages returned
        results = await adapter._poll_telethon()
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_watermark_advances_after_first_poll(self):
        msgs = [_text_tg_msg(msg_id=i, text=f"msg-{i}") for i in range(1, 6)]
        client = FakeTelethonClient(messages={DR_CHIRO_CHAT_ID: msgs})
        adapter = _make_adapter(client=client)
        await adapter._poll_telethon()
        # Watermark should now be 5
        assert adapter._last_seen_id[DR_CHIRO_CHAT_ID] == 5

    @pytest.mark.asyncio
    async def test_second_poll_returns_only_new_messages(self):
        msgs_batch1 = [_text_tg_msg(msg_id=i) for i in range(1, 4)]
        msgs_batch2 = [_text_tg_msg(msg_id=i) for i in range(1, 6)]
        client = FakeTelethonClient(messages={DR_CHIRO_CHAT_ID: msgs_batch1})
        adapter = _make_adapter(client=client)
        # First poll: see messages 1, 2, 3
        first = await adapter._poll_telethon()
        assert len(first) == 3
        # Simulate new messages appearing (expand the fake client's queue)
        client._messages[DR_CHIRO_CHAT_ID] = msgs_batch2
        # Second poll: should only see messages 4, 5 (ids > 3)
        second = await adapter._poll_telethon()
        assert len(second) == 2
        ids = [int(m.platform_msg_id) for m in second]
        assert ids == [4, 5]

    @pytest.mark.asyncio
    async def test_poll_empty_room_returns_empty_list(self):
        client = FakeTelethonClient(messages={})
        adapter = _make_adapter(client=client)
        results = await adapter._poll_telethon()
        assert results == []

    @pytest.mark.asyncio
    async def test_poll_error_does_not_propagate(self):
        """poll_telethon swallows per-room exceptions and returns partial results."""

        class BrokenClient(FakeTelethonClient):
            def iter_messages(self, entity, *, min_id=0, limit=None):
                class _Boom:
                    def __aiter__(self):
                        return self

                    async def __anext__(self):
                        raise RuntimeError("simulated network failure")

                return _Boom()

        client = BrokenClient()
        adapter = _make_adapter(client=client)
        results = await adapter._poll_telethon()
        # Should return empty, not raise
        assert results == []


# ---------------------------------------------------------------------------
# E. inbound() generator tests
# ---------------------------------------------------------------------------


class TestInbound:
    @pytest.mark.asyncio
    async def test_inbound_yields_one_message(self):
        msgs = [_text_tg_msg(msg_id=1, text="hi")]
        client = FakeTelethonClient(messages={DR_CHIRO_CHAT_ID: msgs})
        adapter = _make_adapter(client=client)
        await adapter.connect()

        collected: list[ChannelMessage] = []
        # Drain one cycle then stop
        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False  # stop after first batch

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].text == "hi"

    @pytest.mark.asyncio
    async def test_inbound_stops_when_not_running(self):
        client = FakeTelethonClient(messages={DR_CHIRO_CHAT_ID: []})
        adapter = _make_adapter(client=client)
        await adapter.connect()
        adapter._running = False  # stop immediately

        collected = []
        async for m in adapter.inbound():
            collected.append(m)
        assert collected == []

    @pytest.mark.asyncio
    async def test_inbound_dr_chiro_group_binding(self):
        """Messages from -5134021983 have room_id == DR_CHIRO_CHAT_ID."""
        msgs = [_text_tg_msg(msg_id=5, text="DR chiro msg", chat_id=-5134021983)]
        client = FakeTelethonClient(messages={DR_CHIRO_CHAT_ID: msgs})
        adapter = _make_adapter(client=client)
        await adapter.connect()

        collected: list[ChannelMessage] = []
        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].room_id == DR_CHIRO_CHAT_ID


# ---------------------------------------------------------------------------
# F. send() via Telethon
# ---------------------------------------------------------------------------


class TestSendTelethon:
    @pytest.mark.asyncio
    async def test_send_text_calls_send_message(self):
        client = FakeTelethonClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=MessageKind.TEXT,
            text="Hello DR Chiro",
            sender=PlatformIdentity(
                channel=ChannelType.TELEGRAM,
                platform_id="111",
                platform_name="Chef",
                room_id=DR_CHIRO_CHAT_ID,
            ),
            room_id=DR_CHIRO_CHAT_ID,
        )
        platform_id = await adapter.send(msg)
        assert platform_id.isdigit()
        assert len(client.sent_messages) == 1
        assert client.sent_messages[0]["message"] == "Hello DR Chiro"

    @pytest.mark.asyncio
    async def test_send_returns_platform_message_id(self):
        client = FakeTelethonClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=MessageKind.TEXT,
            text="id test",
            sender=PlatformIdentity(
                channel=ChannelType.TELEGRAM,
                platform_id="1",
                platform_name="A",
                room_id=DR_CHIRO_CHAT_ID,
            ),
            room_id=DR_CHIRO_CHAT_ID,
        )
        pid = await adapter.send(msg)
        assert pid == "1002"  # FakeSentMessage: 1001 + 1

    @pytest.mark.asyncio
    async def test_send_file_with_bytes_calls_send_file(self):
        client = FakeTelethonClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        attachment = MediaAttachment(
            filename="doc.pdf",
            mime_type="application/pdf",
            size_bytes=1024,
            data=b"%PDF fake",
        )
        msg = ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=MessageKind.FILE,
            text="Here is the file",
            sender=PlatformIdentity(
                channel=ChannelType.TELEGRAM,
                platform_id="1",
                platform_name="A",
                room_id=DR_CHIRO_CHAT_ID,
            ),
            room_id=DR_CHIRO_CHAT_ID,
            attachments=[attachment],
        )
        await adapter.send(msg)
        assert len(client.sent_files) == 1
        assert client.sent_files[0]["file"] == b"%PDF fake"

    @pytest.mark.asyncio
    async def test_send_with_reply_to_passes_reply_kwarg(self):
        client = FakeTelethonClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=MessageKind.TEXT,
            text="reply body",
            sender=PlatformIdentity(
                channel=ChannelType.TELEGRAM,
                platform_id="1",
                platform_name="A",
                room_id=DR_CHIRO_CHAT_ID,
            ),
            room_id=DR_CHIRO_CHAT_ID,
            reply_to_platform_id="55",
        )
        await adapter.send(msg)
        assert client.sent_messages[0].get("reply_to") == 55

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_on_telethon_failure(self):
        client = FakeTelethonClient(raise_on_send=True)
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=MessageKind.TEXT,
            text="will fail",
            sender=PlatformIdentity(
                channel=ChannelType.TELEGRAM,
                platform_id="1",
                platform_name="A",
                room_id=DR_CHIRO_CHAT_ID,
            ),
            room_id=DR_CHIRO_CHAT_ID,
        )
        with pytest.raises(AdapterSendError, match="Telethon send failed"):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_no_client_no_token_raises_adapter_send_error(self):
        """No Telethon client, no bot_token → AdapterSendError."""
        adapter = TelegramAdapter(
            config={"poll_interval_s": 0},
            telethon_client=None,
            bindings_store={},
        )
        msg = ChannelMessage(
            channel=ChannelType.TELEGRAM,
            kind=MessageKind.TEXT,
            text="orphan",
            sender=PlatformIdentity(
                channel=ChannelType.TELEGRAM,
                platform_id="1",
                platform_name="X",
                room_id=DR_CHIRO_CHAT_ID,
            ),
            room_id=DR_CHIRO_CHAT_ID,
        )
        with pytest.raises(AdapterSendError):
            await adapter.send(msg)


# ---------------------------------------------------------------------------
# G. Identity binding
# ---------------------------------------------------------------------------


class TestIdentityBinding:
    @pytest.mark.asyncio
    async def test_resolve_unknown_returns_none(self):
        adapter = _make_adapter()
        pid = PlatformIdentity(
            channel=ChannelType.TELEGRAM,
            platform_id="999",
            platform_name="Guest",
            room_id=DR_CHIRO_CHAT_ID,
        )
        assert await adapter.resolve_fqid(pid) is None

    @pytest.mark.asyncio
    async def test_bind_and_resolve(self):
        adapter = _make_adapter()
        pid = PlatformIdentity(
            channel=ChannelType.TELEGRAM,
            platform_id="42",
            platform_name="Chef",
            room_id=DR_CHIRO_CHAT_ID,
        )
        await adapter.bind_fqid(pid, "chef@skworld.io", "verified")
        assert await adapter.resolve_fqid(pid) == "chef@skworld.io"

    @pytest.mark.asyncio
    async def test_preloaded_bindings_resolve(self):
        pid = PlatformIdentity(
            channel=ChannelType.TELEGRAM,
            platform_id="100",
            platform_name="Lumina",
            room_id=DR_CHIRO_CHAT_ID,
        )
        bindings = {pid.canonical_key: "lumina@skworld.io"}
        adapter = _make_adapter(bindings=bindings)
        assert await adapter.resolve_fqid(pid) == "lumina@skworld.io"

    @pytest.mark.asyncio
    async def test_bind_overrides_existing(self):
        pid = PlatformIdentity(
            channel=ChannelType.TELEGRAM,
            platform_id="7",
            platform_name="Old",
            room_id=DR_CHIRO_CHAT_ID,
        )
        bindings = {pid.canonical_key: "old@example.com"}
        adapter = _make_adapter(bindings=bindings)
        await adapter.bind_fqid(pid, "new@example.com", "trusted")
        assert await adapter.resolve_fqid(pid) == "new@example.com"

    @pytest.mark.asyncio
    async def test_dr_chiro_chef_binding(self):
        """
        Simulates binding Chef's Telegram user id to chef@skworld.io.

        This is the real binding that will be set up when the account
        is a member of -5134021983.  Demonstrates the full round-trip.
        """
        chef_tg_id = "12345678"  # placeholder — real id TBD after account joins group
        pid = PlatformIdentity(
            channel=ChannelType.TELEGRAM,
            platform_id=chef_tg_id,
            platform_name="Chef David",
            room_id=DR_CHIRO_CHAT_ID,
            room_name="PROJECT: DR Chiro AI",
        )
        adapter = _make_adapter()
        # Initially unbound
        assert await adapter.resolve_fqid(pid) is None
        # After /bind flow
        await adapter.bind_fqid(pid, "chef@skworld.io", "verified")
        assert await adapter.resolve_fqid(pid) == "chef@skworld.io"
        assert pid.canonical_key == f"telegram:user:{chef_tg_id}"


# ---------------------------------------------------------------------------
# H. Capabilities
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_telegram_capabilities(self):
        adapter = _make_adapter()
        caps = adapter.capabilities()
        assert caps.text is True
        assert caps.files is True
        assert caps.images is True
        assert caps.voice_notes is True
        assert caps.video is True
        assert caps.reactions is True
        assert caps.threads is True
        assert caps.read_receipts is False
        assert caps.typing_hint is True
        assert caps.max_text_bytes == 4096


# ---------------------------------------------------------------------------
# I. set_presence stub
# ---------------------------------------------------------------------------


class TestSetPresence:
    @pytest.mark.asyncio
    async def test_set_presence_does_not_raise(self):
        adapter = _make_adapter()
        # Should not raise even though it's a stub
        await adapter.set_presence("lumina@skworld.io", "typing")
