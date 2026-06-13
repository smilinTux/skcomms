"""
Unit tests for the ChannelAdapter interface, AdapterRegistry, and TelegramAdapter.

Coverage:
  - ChannelMessage / PlatformIdentity / MediaAttachment models
  - AdapterCapabilities defaults and override
  - AdapterHealth
  - AdapterRegistry: register, inbound routing, FQID resolution, trust assignment,
    outbound send routing, capability downgrade
  - TelegramAdapter._normalize (text / voice / image / file / sticker)
  - TelegramAdapter identity binding (resolve / bind, in-memory store)
  - Fake in-memory adapter (FakeAdapter) exercising the full registry pipeline

All tests are pure-unit: no network, no filesystem I/O, no real Telegram token.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional

import pytest

from skcomms.adapters import (
    AdapterCapabilities,
    AdapterHealth,
    AdapterRegistry,
    ChannelAdapter,
    ChannelMessage,
    ChannelType,
    MediaAttachment,
    MessageKind,
    PlatformIdentity,
    TelegramAdapter,
    TrustLevel,
)
from skcomms.adapters.base import AdapterSendError

# ---------------------------------------------------------------------------
# Helpers — shared test data builders
# ---------------------------------------------------------------------------


def _platform_id(
    channel: ChannelType = ChannelType.TELEGRAM,
    platform_id: str = "111",
    platform_name: str = "Alice",
    room_id: str = "-5134021983",
    room_name: str = "DR Chiro",
) -> PlatformIdentity:
    return PlatformIdentity(
        channel=channel,
        platform_id=platform_id,
        platform_name=platform_name,
        room_id=room_id,
        room_name=room_name,
    )


def _text_msg(text: str = "hello", room_id: str = "-5134021983") -> ChannelMessage:
    return ChannelMessage(
        channel=ChannelType.TELEGRAM,
        kind=MessageKind.TEXT,
        text=text,
        sender=_platform_id(room_id=room_id),
        room_id=room_id,
    )


# ---------------------------------------------------------------------------
# A. Model tests
# ---------------------------------------------------------------------------


class TestPlatformIdentity:
    def test_canonical_key(self):
        pid = _platform_id(channel=ChannelType.TELEGRAM, platform_id="123456789")
        assert pid.canonical_key == "telegram:user:123456789"

    def test_canonical_key_discord(self):
        pid = _platform_id(channel=ChannelType.DISCORD, platform_id="987")
        assert pid.canonical_key == "discord:user:987"


class TestChannelMessage:
    def test_defaults_are_populated(self):
        msg = _text_msg()
        assert msg.channel_message_id  # UUID auto-set
        assert msg.timestamp is not None
        assert msg.attachments == []
        assert msg.skcomms_thread_id is None

    def test_distinct_ids_per_instance(self):
        a = _text_msg()
        b = _text_msg()
        assert a.channel_message_id != b.channel_message_id

    def test_attachment_optional_fields(self):
        att = MediaAttachment(filename="f.jpg", mime_type="image/jpeg", size_bytes=1024)
        assert att.url is None
        assert att.data is None


class TestAdapterCapabilities:
    def test_defaults(self):
        caps = AdapterCapabilities()
        assert caps.text is True
        assert caps.voice_notes is False
        assert caps.max_text_bytes == 4096

    def test_override(self):
        caps = AdapterCapabilities(voice_notes=True, max_text_bytes=2000)
        assert caps.voice_notes is True
        assert caps.max_text_bytes == 2000


class TestAdapterHealth:
    def test_connected(self):
        h = AdapterHealth(adapter_name="fake", connected=True, latency_ms=12.5)
        assert h.connected is True
        assert h.error is None

    def test_error_state(self):
        h = AdapterHealth(
            adapter_name="fake", connected=False, latency_ms=None, error="timeout"
        )
        assert h.error == "timeout"


# ---------------------------------------------------------------------------
# B. Fake in-memory adapter (shared by registry tests)
# ---------------------------------------------------------------------------


class FakeAdapter(ChannelAdapter):
    """
    In-memory adapter for unit-testing the registry.

    Pre-loaded with a queue of messages to yield from inbound().
    Captures all send() calls for assertion.
    """

    channel_type = ChannelType.CUSTOM
    adapter_name = "fake"

    def __init__(
        self,
        messages: Optional[list[ChannelMessage]] = None,
        fqid_map: Optional[dict[str, str]] = None,
        caps: Optional[AdapterCapabilities] = None,
    ) -> None:
        self._queue: list[ChannelMessage] = messages or []
        self._fqid_map: dict[str, str] = fqid_map or {}
        self._caps = caps or AdapterCapabilities()
        self.sent: list[ChannelMessage] = []
        self.connected = False

    async def connect(self) -> None:
        self.connected = True

    async def disconnect(self) -> None:
        self.connected = False

    async def health(self) -> AdapterHealth:
        return AdapterHealth(
            adapter_name=self.adapter_name,
            connected=self.connected,
            latency_ms=1.0,
        )

    def capabilities(self) -> AdapterCapabilities:
        return self._caps

    async def inbound(self) -> AsyncIterator[ChannelMessage]:
        for msg in self._queue:
            yield msg

    async def send(self, message: ChannelMessage) -> str:
        self.sent.append(message)
        return f"fake-msg-{len(self.sent)}"

    async def resolve_fqid(self, platform_id: PlatformIdentity) -> Optional[str]:
        return self._fqid_map.get(platform_id.canonical_key)

    async def bind_fqid(
        self, platform_id: PlatformIdentity, fqid: str, trust_level: str
    ) -> None:
        self._fqid_map[platform_id.canonical_key] = fqid


# ---------------------------------------------------------------------------
# C. AdapterRegistry tests
# ---------------------------------------------------------------------------


class TestAdapterRegistryRegistration:
    def test_register_and_get(self):
        reg = AdapterRegistry()
        adapter = FakeAdapter()
        reg.register(adapter)
        assert reg.get("fake") is adapter

    def test_get_unknown_returns_none(self):
        reg = AdapterRegistry()
        assert reg.get("nope") is None

    def test_send_to_unregistered_raises_keyerror(self):
        reg = AdapterRegistry()
        with pytest.raises(KeyError):
            asyncio.get_event_loop().run_until_complete(
                reg.send_to_adapter("ghost", _text_msg())
            )


class TestAdapterRegistryInbound:
    """Inbound messages are dispatched to the handler with correct FQID + trust."""

    @pytest.mark.asyncio
    async def test_inbound_routes_to_handler(self):
        """3 messages → handler called 3 times."""
        msgs = [_text_msg(f"msg-{i}") for i in range(3)]
        adapter = FakeAdapter(messages=msgs)

        received: list[tuple[ChannelMessage, str, TrustLevel]] = []

        async def handler(msg: ChannelMessage, fqid: str, trust: TrustLevel) -> None:
            received.append((msg, fqid, trust))

        reg = AdapterRegistry(inbound_handler=handler)
        reg.register(adapter)
        await reg.start()
        # inbound() is exhausted synchronously by FakeAdapter, so tasks finish fast
        await asyncio.sleep(0)  # yield to event loop

        assert len(received) == 3

    @pytest.mark.asyncio
    async def test_known_sender_gets_verified_trust(self):
        """A sender in the adapter's fqid_map gets TrustLevel.VERIFIED."""
        pid = _platform_id(platform_id="42")
        msg = _text_msg()
        msg.sender = pid

        fqid_map = {pid.canonical_key: "chef@skworld.io"}
        adapter = FakeAdapter(messages=[msg], fqid_map=fqid_map)

        received: list[tuple[ChannelMessage, str, TrustLevel]] = []

        async def handler(m: ChannelMessage, fqid: str, trust: TrustLevel) -> None:
            received.append((m, fqid, trust))

        reg = AdapterRegistry(inbound_handler=handler)
        reg.register(adapter)
        await reg.start()
        await asyncio.sleep(0)

        assert len(received) == 1
        _, fqid, trust = received[0]
        assert fqid == "chef@skworld.io"
        assert trust == TrustLevel.VERIFIED

    @pytest.mark.asyncio
    async def test_unknown_sender_gets_untrusted_trust_and_synthetic_fqid(self):
        """A sender without a binding gets UNTRUSTED + a stable synthetic FQID."""
        pid = _platform_id(channel=ChannelType.TELEGRAM, platform_id="999")
        msg = _text_msg()
        msg.sender = pid

        adapter = FakeAdapter(messages=[msg])  # empty fqid_map

        received: list[tuple[ChannelMessage, str, TrustLevel]] = []

        async def handler(m: ChannelMessage, fqid: str, trust: TrustLevel) -> None:
            received.append((m, fqid, trust))

        reg = AdapterRegistry(inbound_handler=handler)
        reg.register(adapter)
        await reg.start()
        await asyncio.sleep(0)

        _, fqid, trust = received[0]
        assert trust == TrustLevel.UNTRUSTED
        assert fqid == "telegram_guest_999@ext"

    @pytest.mark.asyncio
    async def test_multiple_adapters_all_dispatch(self):
        """Messages from two different adapters both arrive at the handler."""
        a1 = FakeAdapter(messages=[_text_msg("from-a1")])
        a1.adapter_name = "fake-a1"
        a1.channel_type = ChannelType.TELEGRAM

        a2 = FakeAdapter(messages=[_text_msg("from-a2"), _text_msg("also-a2")])
        a2.adapter_name = "fake-a2"
        a2.channel_type = ChannelType.SLACK

        received: list[ChannelMessage] = []

        async def handler(m: ChannelMessage, fqid: str, trust: TrustLevel) -> None:
            received.append(m)

        reg = AdapterRegistry(inbound_handler=handler)
        reg.register(a1)
        reg.register(a2)
        await reg.start()
        await asyncio.sleep(0)

        assert len(received) == 3


class TestAdapterRegistryOutbound:
    @pytest.mark.asyncio
    async def test_send_routes_to_correct_adapter(self):
        """send_to_adapter delivers only to the named adapter."""
        a1 = FakeAdapter()
        a1.adapter_name = "fake-a1"
        a2 = FakeAdapter()
        a2.adapter_name = "fake-a2"

        reg = AdapterRegistry()
        reg.register(a1)
        reg.register(a2)

        msg = _text_msg("outbound")
        await reg.send_to_adapter("fake-a1", msg)

        assert len(a1.sent) == 1
        assert len(a2.sent) == 0
        assert a1.sent[0].text == "outbound"

    @pytest.mark.asyncio
    async def test_send_returns_platform_msg_id(self):
        adapter = FakeAdapter()
        reg = AdapterRegistry()
        reg.register(adapter)

        platform_id = await reg.send_to_adapter("fake", _text_msg())
        assert platform_id == "fake-msg-1"


# ---------------------------------------------------------------------------
# D. Capability downgrade tests
# ---------------------------------------------------------------------------


class TestCapabilityDowngrade:
    def _downgrade(self, msg, caps):
        return AdapterRegistry._downgrade(msg, caps)

    def test_voice_downgraded_to_text_when_not_supported(self):
        msg = _text_msg("I said hello")
        msg.kind = MessageKind.VOICE
        caps = AdapterCapabilities(voice_notes=False)
        result = self._downgrade(msg, caps)
        assert result.kind == MessageKind.TEXT
        assert result.text == "[Voice note: I said hello]"
        assert result.attachments == []

    def test_voice_not_downgraded_when_supported(self):
        msg = _text_msg("I said hello")
        msg.kind = MessageKind.VOICE
        caps = AdapterCapabilities(voice_notes=True)
        result = self._downgrade(msg, caps)
        assert result.kind == MessageKind.VOICE

    def test_image_downgraded_when_not_supported(self):
        msg = _text_msg("")
        msg.kind = MessageKind.IMAGE
        msg.attachments = [MediaAttachment("photo.jpg", "image/jpeg", 1024)]
        caps = AdapterCapabilities(images=False)
        result = self._downgrade(msg, caps)
        assert result.kind == MessageKind.TEXT
        assert "photo.jpg" in result.text
        assert result.attachments == []

    def test_text_truncated_at_max_bytes(self):
        long_text = "x" * 5000
        msg = _text_msg(long_text)
        caps = AdapterCapabilities(max_text_bytes=100)
        result = self._downgrade(msg, caps)
        assert len(result.text.encode()) <= 120  # 100 - 20 + len("… [truncated]")
        assert result.text.endswith(" … [truncated]")

    def test_short_text_not_truncated(self):
        msg = _text_msg("short")
        caps = AdapterCapabilities(max_text_bytes=4096)
        result = self._downgrade(msg, caps)
        assert result.text == "short"

    def test_downgrade_makes_shallow_copy(self):
        """Original message is not mutated."""
        msg = _text_msg("untouched")
        msg.kind = MessageKind.VOICE
        caps = AdapterCapabilities(voice_notes=False)
        result = self._downgrade(msg, caps)
        # Original kind unchanged
        assert msg.kind == MessageKind.VOICE
        assert result.kind == MessageKind.TEXT

    def test_voice_with_empty_text_uses_fallback(self):
        msg = _text_msg("")
        msg.kind = MessageKind.VOICE
        caps = AdapterCapabilities(voice_notes=False)
        result = self._downgrade(msg, caps)
        assert result.text == "[Voice note: [untranscribed voice note]]"


# ---------------------------------------------------------------------------
# E. AdapterRegistry.health_all
# ---------------------------------------------------------------------------


class TestHealthAll:
    @pytest.mark.asyncio
    async def test_health_all_returns_snapshot_per_adapter(self):
        a1 = FakeAdapter()
        a1.adapter_name = "a1"
        a1.connected = True
        a2 = FakeAdapter()
        a2.adapter_name = "a2"
        a2.connected = False

        reg = AdapterRegistry()
        reg.register(a1)
        reg.register(a2)

        snapshots = await reg.health_all()
        assert "a1" in snapshots
        assert "a2" in snapshots
        assert snapshots["a1"].connected is True
        assert snapshots["a2"].connected is False


# ---------------------------------------------------------------------------
# F. TelegramAdapter._normalize tests
# ---------------------------------------------------------------------------


class TestTelegramAdapterNormalize:
    """Test _normalize without any live Telegram credentials."""

    def _adapter(self) -> TelegramAdapter:
        return TelegramAdapter(
            config={"bot_token": "fake-token"},
            bindings_store={},
        )

    def _make_update(self, **msg_fields) -> dict:
        base = {
            "update_id": 1,
            "message": {
                "message_id": 42,
                "from": {
                    "id": 123456789,
                    "first_name": "Chef",
                    "last_name": "David",
                    "username": "chefdavid",
                },
                "chat": {
                    "id": -5134021983,
                    "title": "DR Chiro",
                    "type": "group",
                },
                "date": 1718000000,
                **msg_fields,
            },
        }
        return base

    def test_text_message(self):
        adapter = self._adapter()
        update = self._make_update(text="Hello Lumina!")
        msg = adapter._normalize(update)
        assert msg is not None
        assert msg.kind == MessageKind.TEXT
        assert msg.text == "Hello Lumina!"
        assert msg.platform_msg_id == "42"
        assert msg.sender.platform_id == "123456789"
        assert msg.sender.room_id == "-5134021983"
        assert msg.channel == ChannelType.TELEGRAM
        assert msg.raw_payload == update

    def test_text_message_with_reply(self):
        adapter = self._adapter()
        update = self._make_update(
            text="reply",
            reply_to_message={"message_id": 10},
        )
        msg = adapter._normalize(update)
        assert msg.reply_to_platform_id == "10"

    def test_voice_message(self):
        adapter = self._adapter()
        update = self._make_update(
            voice={
                "file_id": "abc",
                "duration": 5,
                "mime_type": "audio/ogg",
                "file_size": 12345,
            }
        )
        msg = adapter._normalize(update)
        assert msg.kind == MessageKind.VOICE
        assert len(msg.attachments) == 1
        assert msg.attachments[0].mime_type == "audio/ogg"
        assert msg.attachments[0].size_bytes == 12345

    def test_photo_message(self):
        adapter = self._adapter()
        update = self._make_update(
            caption="look at this",
            photo=[
                {"file_id": "small", "width": 100, "height": 100, "file_size": 1000},
                {"file_id": "large", "width": 800, "height": 600, "file_size": 80000},
            ],
        )
        msg = adapter._normalize(update)
        assert msg.kind == MessageKind.IMAGE
        assert msg.text == "look at this"
        assert msg.attachments[0].mime_type == "image/jpeg"
        assert msg.attachments[0].size_bytes == 80000  # largest size used

    def test_document_message(self):
        adapter = self._adapter()
        update = self._make_update(
            document={
                "file_id": "xyz",
                "file_name": "report.pdf",
                "mime_type": "application/pdf",
                "file_size": 204800,
            }
        )
        msg = adapter._normalize(update)
        assert msg.kind == MessageKind.FILE
        assert msg.attachments[0].filename == "report.pdf"
        assert msg.attachments[0].mime_type == "application/pdf"

    def test_sticker_message(self):
        adapter = self._adapter()
        update = self._make_update(sticker={"file_id": "stk1", "emoji": "😎"})
        msg = adapter._normalize(update)
        assert msg.kind == MessageKind.STICKER
        assert msg.text == "😎"

    def test_unknown_update_type_returns_none(self):
        adapter = self._adapter()
        # An update with no message / edited_message (e.g. channel_post)
        update = {"update_id": 99, "channel_post": {"text": "ignored"}}
        result = adapter._normalize(update)
        assert result is None

    def test_sender_display_name_concatenated(self):
        adapter = self._adapter()
        update = {
            "update_id": 1,
            "message": {
                "message_id": 1,
                "from": {"id": 7, "first_name": "Queen", "last_name": "Lumina"},
                "chat": {"id": 100, "type": "private"},
                "date": 0,
                "text": "hi",
            },
        }
        msg = adapter._normalize(update)
        assert msg.sender.platform_name == "Queen Lumina"

    def test_edited_message_treated_as_inbound(self):
        """edited_message updates yield a ChannelMessage (not None)."""
        adapter = self._adapter()
        update = {
            "update_id": 2,
            "edited_message": {
                "message_id": 55,
                "from": {"id": 1, "first_name": "A"},
                "chat": {"id": 9, "type": "private"},
                "date": 0,
                "text": "edited text",
            },
        }
        msg = adapter._normalize(update)
        assert msg is not None
        assert msg.text == "edited text"


# ---------------------------------------------------------------------------
# G. TelegramAdapter identity binding
# ---------------------------------------------------------------------------


class TestTelegramAdapterIdentity:
    def _adapter(self, fqid_map=None) -> TelegramAdapter:
        return TelegramAdapter(
            config={"bot_token": "fake"},
            bindings_store=fqid_map or {},
        )

    @pytest.mark.asyncio
    async def test_resolve_returns_none_for_unknown(self):
        adapter = self._adapter()
        pid = _platform_id(platform_id="999")
        assert await adapter.resolve_fqid(pid) is None

    @pytest.mark.asyncio
    async def test_bind_then_resolve(self):
        adapter = self._adapter()
        pid = _platform_id(platform_id="42")
        await adapter.bind_fqid(pid, "chef@skworld.io", "verified")
        assert await adapter.resolve_fqid(pid) == "chef@skworld.io"

    @pytest.mark.asyncio
    async def test_preloaded_bindings(self):
        pid = _platform_id(platform_id="100")
        bindings = {pid.canonical_key: "lumina@skworld.io"}
        adapter = self._adapter(fqid_map=bindings)
        assert await adapter.resolve_fqid(pid) == "lumina@skworld.io"

    @pytest.mark.asyncio
    async def test_bind_overrides_existing(self):
        pid = _platform_id(platform_id="7")
        bindings = {pid.canonical_key: "old@example.com"}
        adapter = self._adapter(fqid_map=bindings)
        await adapter.bind_fqid(pid, "new@example.com", "trusted")
        assert await adapter.resolve_fqid(pid) == "new@example.com"


# ---------------------------------------------------------------------------
# H. TelegramAdapter lifecycle (no network)
# ---------------------------------------------------------------------------


class TestTelegramAdapterLifecycle:
    @pytest.mark.asyncio
    async def test_connect_sets_running_true(self):
        adapter = TelegramAdapter(
            config={"bot_token": "fake-token"},
            bindings_store={},
        )
        assert not adapter._running
        await adapter.connect()
        assert adapter._running

    @pytest.mark.asyncio
    async def test_disconnect_sets_running_false(self):
        adapter = TelegramAdapter(
            config={"bot_token": "fake-token"},
            bindings_store={},
        )
        await adapter.connect()
        await adapter.disconnect()
        assert not adapter._running

    @pytest.mark.asyncio
    async def test_connect_raises_on_empty_token(self):
        from skcomms.adapters.base import AdapterAuthError

        adapter = TelegramAdapter(config={"bot_token": ""}, bindings_store={})
        with pytest.raises(AdapterAuthError):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_stub(self):
        """send() is not wired — must raise AdapterSendError, not silently pass."""
        adapter = TelegramAdapter(
            config={"bot_token": "fake-token"},
            bindings_store={},
        )
        with pytest.raises(AdapterSendError):
            await adapter.send(_text_msg())

    @pytest.mark.asyncio
    async def test_health_returns_connected_state(self):
        adapter = TelegramAdapter(
            config={"bot_token": "fake-token"},
            bindings_store={},
        )
        await adapter.connect()
        h = await adapter.health()
        assert h.connected is True
        assert h.adapter_name == "telegram"

    def test_capabilities(self):
        adapter = TelegramAdapter(config={"bot_token": "x"}, bindings_store={})
        caps = adapter.capabilities()
        assert caps.voice_notes is True
        assert caps.reactions is True
        assert caps.typing_hint is True
        assert caps.max_text_bytes == 4096


# ---------------------------------------------------------------------------
# I. __init__.py public surface
# ---------------------------------------------------------------------------


class TestPackagePublicSurface:
    def test_all_exports_importable(self):
        from skcomms import adapters  # noqa: F401

        names = [
            "ChannelAdapter",
            "AdapterCapabilities",
            "AdapterHealth",
            "AdapterRegistry",
            "ChannelMessage",
            "ChannelType",
            "MessageKind",
            "PlatformIdentity",
            "TrustLevel",
            "TelegramAdapter",
        ]
        for name in names:
            assert hasattr(adapters, name), f"skcomms.adapters missing: {name}"
