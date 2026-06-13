"""
Unit tests for DiscordAdapter — Batch C3.

All tests use a ``FakeDiscordClient`` that satisfies :class:`DiscordClientProtocol`
without making any network connections.  No real Discord credentials are required.

Coverage:
  - FakeDiscordClient satisfies DiscordClientProtocol (structural check)
  - connect() / disconnect() lifecycle
  - connect() raises AdapterAuthError when login returns no id
  - connect() raises AdapterAuthError with no client and no token
  - connect() raises AdapterConnectError when login raises
  - connect() stores bot user_id + username
  - health() reflects client state
  - health() error when login raises
  - _normalize():
      * text message → ChannelMessage (TEXT)
      * bot author message dropped (returns None)
      * webhook message dropped
      * unknown event type dropped
      * file attachment → FILE kind
      * image attachment → IMAGE kind
      * message_reference → reply_to_platform_id
      * message with no message_reference has reply_to_platform_id=None
      * global_name used over username for display name
      * discriminator appended when not "0"
  - inbound() yields normalized ChannelMessages from fake client events
  - inbound() stops when _running=False
  - send() routes to send_message (TEXT)
  - send() routes to send_message with message_reference (reply)
  - send() routes to send_file (FILE with bytes)
  - send() raises AdapterSendError when response missing id
  - send() raises AdapterSendError on client exception
  - send() raises AdapterSendError when no client
  - identity binding: resolve / bind round-trip (in-memory store)
  - capabilities() flags
  - set_presence() is a no-op stub (does not raise)
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import pytest

from skcomms.adapters import (
    AdapterHealth,
    ChannelMessage,
    ChannelType,
    DiscordAdapter,
    MediaAttachment,
    MessageKind,
    PlatformIdentity,
    TrustLevel,
)
from skcomms.adapters.base import AdapterAuthError, AdapterConnectError, AdapterSendError
from skcomms.adapters.discord import DiscordClientProtocol

# ---------------------------------------------------------------------------
# FakeDiscordClient — satisfies DiscordClientProtocol
# ---------------------------------------------------------------------------


class FakeDiscordClient:
    """
    In-memory Discord client stub for unit testing.

    Pre-loads an event queue via ``push_event``.  ``drain_events`` flushes
    and returns the queued events.  ``send_message`` / ``send_file``
    capture calls and return fake responses.
    """

    def __init__(
        self,
        authorized: bool = True,
        bot_user_id: str = "BOT_LUMINA",
        bot_username: str = "Lumina",
        discriminator: str = "0",
        raise_on_login: bool = False,
        raise_on_send: bool = False,
    ) -> None:
        self._authorized = authorized
        self._bot_user_id = bot_user_id
        self._bot_username = bot_username
        self._discriminator = discriminator
        self._raise_on_login = raise_on_login
        self._raise_on_send = raise_on_send
        self._connected = False
        self._event_queue: list[dict] = []

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

    async def login(self) -> dict:
        if self._raise_on_login:
            raise RuntimeError("login: simulated failure")
        if not self._authorized:
            return {}  # no "id" → AdapterAuthError
        return {
            "id": self._bot_user_id,
            "username": self._bot_username,
            "discriminator": self._discriminator,
            "bot": True,
        }

    async def send_message(
        self,
        channel_id: str,
        content: str,
        *,
        message_reference: Optional[dict] = None,
    ) -> dict:
        if self._raise_on_send:
            raise RuntimeError("send_message: simulated failure")
        rec = {
            "channel_id": channel_id,
            "content": content,
            "message_reference": message_reference,
        }
        self.sent_messages.append(rec)
        return {
            "id": f"MSGID_{len(self.sent_messages)}",
            "channel_id": channel_id,
            "content": content,
        }

    async def send_file(
        self,
        channel_id: str,
        content: bytes,
        filename: str,
        *,
        caption: str = "",
    ) -> dict:
        if self._raise_on_send:
            raise RuntimeError("send_file: simulated failure")
        rec = {
            "channel_id": channel_id,
            "content": content,
            "filename": filename,
            "caption": caption,
        }
        self.sent_files.append(rec)
        return {
            "id": f"FILEID_{len(self.sent_files)}",
            "channel_id": channel_id,
        }

    def drain_events(self) -> list[dict]:
        events = list(self._event_queue)
        self._event_queue.clear()
        return events

    # --- Test helpers ---

    def push_event(self, event: dict) -> None:
        """Enqueue a fake Discord Gateway event for consumption by inbound()."""
        self._event_queue.append(event)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DISCORD_CHANNEL_ID = "CH_999"
DISCORD_GUILD_ID = "GLD_001"

DISCORD_CONFIG = {
    "bot_token": "Bot fake-discord-token",
    "poll_interval_s": 0,
    "guilds": {
        "skworld": {
            "guild_id": DISCORD_GUILD_ID,
            "channels": {
                "general": {
                    "channel_id": DISCORD_CHANNEL_ID,
                    "agent_fqid": "lumina@skworld.io",
                }
            },
        }
    },
    "identity_store": "/tmp/test-discord-ids.yaml",
}


def _make_adapter(
    client: Optional[FakeDiscordClient] = None,
    config: Optional[dict] = None,
    bindings: Optional[dict[str, str]] = None,
) -> DiscordAdapter:
    return DiscordAdapter(
        config=config or DISCORD_CONFIG,
        discord_client=client or FakeDiscordClient(),
        bindings_store=bindings or {},
    )


def _text_event(
    user_id: str = "U111",
    username: str = "Chef",
    text: str = "hello",
    channel_id: str = DISCORD_CHANNEL_ID,
    msg_id: str = "MSG_001",
    guild_id: str = DISCORD_GUILD_ID,
    bot: bool = False,
) -> dict:
    return {
        "type": "MESSAGE_CREATE",
        "id": msg_id,
        "channel_id": channel_id,
        "guild_id": guild_id,
        "author": {
            "id": user_id,
            "username": username,
            "discriminator": "0",
            "bot": bot,
        },
        "content": text,
        "attachments": [],
    }


# ---------------------------------------------------------------------------
# Verify FakeDiscordClient satisfies the protocol
# ---------------------------------------------------------------------------


def test_fake_client_satisfies_protocol():
    """FakeDiscordClient is a structural subtype of DiscordClientProtocol."""
    client = FakeDiscordClient()
    assert isinstance(client, DiscordClientProtocol), (
        "FakeDiscordClient does not satisfy DiscordClientProtocol. "
        "Missing methods: "
        + str(
            [
                m
                for m in (
                    "is_connected",
                    "login",
                    "send_message",
                    "send_file",
                    "drain_events",
                    "connect",
                    "disconnect",
                )
                if not hasattr(client, m)
            ]
        )
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
    async def test_connect_calls_client_connect(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        assert client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_stores_bot_user_id(self):
        client = FakeDiscordClient(bot_user_id="BOT_123", bot_username="Lumina")
        adapter = _make_adapter(client=client)
        await adapter.connect()
        assert adapter._bot_user_id == "BOT_123"
        assert adapter._bot_username == "Lumina"

    @pytest.mark.asyncio
    async def test_disconnect_sets_running_false(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not adapter._running

    @pytest.mark.asyncio
    async def test_disconnect_calls_client_disconnect(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_when_login_returns_no_id(self):
        client = FakeDiscordClient(authorized=False)
        adapter = _make_adapter(client=client)
        with pytest.raises(AdapterAuthError, match="bot token"):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_connect_error_when_login_raises(self):
        client = FakeDiscordClient(raise_on_login=True)
        adapter = _make_adapter(client=client)
        with pytest.raises(AdapterConnectError, match="login failed"):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_with_no_credentials(self):
        """No discord_client, no token → AdapterAuthError."""
        adapter = DiscordAdapter(
            config={"poll_interval_s": 0},
            discord_client=None,
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
        assert h.adapter_name == "discord"
        assert h.error is None

    @pytest.mark.asyncio
    async def test_health_disconnected_before_connect(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        h = await adapter.health()
        assert h.connected is False

    @pytest.mark.asyncio
    async def test_health_error_when_login_raises(self):
        client = FakeDiscordClient(raise_on_login=True)
        adapter = _make_adapter(client=client)
        adapter._running = True
        client._connected = True
        h = await adapter.health()
        assert h.connected is False
        assert h.error is not None

    @pytest.mark.asyncio
    async def test_health_latency_is_float_after_connect(self):
        adapter = _make_adapter()
        await adapter.connect()
        h = await adapter.health()
        assert h.latency_ms is not None
        assert h.latency_ms >= 0.0


# ---------------------------------------------------------------------------
# C. _normalize tests
# ---------------------------------------------------------------------------


class TestNormalize:
    def _adapter(self) -> DiscordAdapter:
        return _make_adapter()

    def test_text_message(self):
        adapter = self._adapter()
        event = _text_event(user_id="U111", username="Chef", text="Hello Lumina!")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.TEXT
        assert msg.text == "Hello Lumina!"
        assert msg.sender.platform_id == "U111"
        assert msg.room_id == DISCORD_CHANNEL_ID
        assert msg.channel == ChannelType.DISCORD
        assert msg.platform_msg_id == "MSG_001"

    def test_bot_message_dropped(self):
        adapter = self._adapter()
        event = _text_event(bot=True, text="I am a bot")
        msg = adapter._normalize(event)
        assert msg is None

    def test_webhook_message_dropped(self):
        adapter = self._adapter()
        event = {
            **_text_event(text="webhook msg"),
            "author": {
                "id": "W001",
                "username": "Webhook",
                "discriminator": "0000",
                "bot": False,
                "webhook_id": "WH001",
            },
        }
        msg = adapter._normalize(event)
        assert msg is None

    def test_unknown_event_type_dropped(self):
        adapter = self._adapter()
        event = {"type": "GUILD_CREATE", "id": "something"}
        msg = adapter._normalize(event)
        assert msg is None

    def test_file_attachment_becomes_file_kind(self):
        adapter = self._adapter()
        event = {
            **_text_event(text="see file"),
            "attachments": [
                {
                    "id": "ATT001",
                    "filename": "doc.pdf",
                    "content_type": "application/pdf",
                    "size": 102400,
                    "url": "https://cdn.discordapp.com/attachments/doc.pdf",
                }
            ],
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.FILE
        assert len(msg.attachments) == 1
        assert msg.attachments[0].filename == "doc.pdf"
        assert msg.attachments[0].mime_type == "application/pdf"
        assert msg.attachments[0].size_bytes == 102400

    def test_image_attachment_becomes_image_kind(self):
        adapter = self._adapter()
        event = {
            **_text_event(text=""),
            "attachments": [
                {
                    "id": "ATT002",
                    "filename": "screenshot.png",
                    "content_type": "image/png",
                    "size": 51200,
                    "url": "https://cdn.discordapp.com/attachments/screenshot.png",
                }
            ],
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.IMAGE
        assert msg.attachments[0].mime_type == "image/png"

    def test_message_reference_becomes_reply_to_platform_id(self):
        adapter = self._adapter()
        event = {
            **_text_event(text="reply"),
            "message_reference": {
                "message_id": "ORIGINAL_MSG",
                "channel_id": DISCORD_CHANNEL_ID,
            },
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.reply_to_platform_id == "ORIGINAL_MSG"

    def test_no_message_reference_reply_is_none(self):
        adapter = self._adapter()
        event = _text_event(text="top level")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.reply_to_platform_id is None

    def test_global_name_preferred_over_username(self):
        adapter = self._adapter()
        event = _text_event(username="internal_name", text="hi")
        event["author"]["global_name"] = "Chef David"
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.sender.platform_name == "Chef David"

    def test_discriminator_appended_when_not_zero(self):
        adapter = self._adapter()
        event = _text_event(username="OldUser", text="hi")
        event["author"]["discriminator"] = "1234"
        event["author"].pop("global_name", None)
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.sender.platform_name == "OldUser#1234"

    def test_data_dict_without_type_key_is_accepted(self):
        """Adapter handles MESSAGE_CREATE d-field (no outer type key)."""
        adapter = self._adapter()
        event = _text_event(text="no type key")
        del event["type"]
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.text == "no type key"


# ---------------------------------------------------------------------------
# D. inbound() generator tests
# ---------------------------------------------------------------------------


class TestInbound:
    @pytest.mark.asyncio
    async def test_inbound_yields_one_message(self):
        client = FakeDiscordClient()
        client.push_event(_text_event(text="hi discord"))
        adapter = _make_adapter(client=client)
        await adapter.connect()

        collected: list[ChannelMessage] = []

        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].text == "hi discord"

    @pytest.mark.asyncio
    async def test_inbound_stops_when_not_running(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        adapter._running = False

        collected = []
        async for m in adapter.inbound():
            collected.append(m)
        assert collected == []

    @pytest.mark.asyncio
    async def test_inbound_drops_bot_messages(self):
        """Bot messages should be filtered by _normalize before yielding."""
        client = FakeDiscordClient()
        client.push_event(_text_event(text="bot noise", bot=True))
        client.push_event(_text_event(text="real message", msg_id="MSG_002"))
        adapter = _make_adapter(client=client)
        await adapter.connect()

        collected: list[ChannelMessage] = []

        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].text == "real message"


# ---------------------------------------------------------------------------
# E. send() tests
# ---------------------------------------------------------------------------


class TestSend:
    @pytest.mark.asyncio
    async def test_send_text_calls_send_message(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.DISCORD,
            kind=MessageKind.TEXT,
            text="Hello Discord!",
            sender=PlatformIdentity(
                channel=ChannelType.DISCORD,
                platform_id="U111",
                platform_name="Chef",
                room_id=DISCORD_CHANNEL_ID,
            ),
            room_id=DISCORD_CHANNEL_ID,
        )
        msg_id = await adapter.send(msg)
        assert msg_id == "MSGID_1"
        assert len(client.sent_messages) == 1
        assert client.sent_messages[0]["content"] == "Hello Discord!"
        assert client.sent_messages[0]["channel_id"] == DISCORD_CHANNEL_ID

    @pytest.mark.asyncio
    async def test_send_with_reply_passes_message_reference(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.DISCORD,
            kind=MessageKind.TEXT,
            text="reply text",
            sender=PlatformIdentity(
                channel=ChannelType.DISCORD,
                platform_id="U111",
                platform_name="Chef",
                room_id=DISCORD_CHANNEL_ID,
            ),
            room_id=DISCORD_CHANNEL_ID,
            reply_to_platform_id="ORIGINAL_MSG",
        )
        await adapter.send(msg)
        ref = client.sent_messages[0]["message_reference"]
        assert ref is not None
        assert ref["message_id"] == "ORIGINAL_MSG"

    @pytest.mark.asyncio
    async def test_send_file_with_bytes_calls_send_file(self):
        client = FakeDiscordClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        attachment = MediaAttachment(
            filename="image.png",
            mime_type="image/png",
            size_bytes=2048,
            data=b"\x89PNG fake",
        )
        msg = ChannelMessage(
            channel=ChannelType.DISCORD,
            kind=MessageKind.IMAGE,
            text="look at this",
            sender=PlatformIdentity(
                channel=ChannelType.DISCORD,
                platform_id="U1",
                platform_name="Chef",
                room_id=DISCORD_CHANNEL_ID,
            ),
            room_id=DISCORD_CHANNEL_ID,
            attachments=[attachment],
        )
        file_id = await adapter.send(msg)
        assert file_id == "FILEID_1"
        assert client.sent_files[0]["content"] == b"\x89PNG fake"
        assert client.sent_files[0]["filename"] == "image.png"

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_when_response_missing_id(self):
        """send_message returning a dict without 'id' → AdapterSendError."""

        class BadClient(FakeDiscordClient):
            async def send_message(self, channel_id, content, **kwargs):
                return {"channel_id": channel_id}  # missing "id"

        client = BadClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.DISCORD,
            kind=MessageKind.TEXT,
            text="will fail",
            sender=PlatformIdentity(
                channel=ChannelType.DISCORD,
                platform_id="U1",
                platform_name="A",
                room_id=DISCORD_CHANNEL_ID,
            ),
            room_id=DISCORD_CHANNEL_ID,
        )
        with pytest.raises(AdapterSendError, match="missing 'id'"):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_on_client_exception(self):
        client = FakeDiscordClient(raise_on_send=True)
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.DISCORD,
            kind=MessageKind.TEXT,
            text="exception path",
            sender=PlatformIdentity(
                channel=ChannelType.DISCORD,
                platform_id="U1",
                platform_name="A",
                room_id=DISCORD_CHANNEL_ID,
            ),
            room_id=DISCORD_CHANNEL_ID,
        )
        with pytest.raises(AdapterSendError):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_with_no_client(self):
        """No client → AdapterSendError without network call."""
        adapter = DiscordAdapter(
            config={"poll_interval_s": 0},
            discord_client=None,
            bindings_store={},
        )
        msg = ChannelMessage(
            channel=ChannelType.DISCORD,
            kind=MessageKind.TEXT,
            text="orphan",
            sender=PlatformIdentity(
                channel=ChannelType.DISCORD,
                platform_id="U1",
                platform_name="X",
                room_id=DISCORD_CHANNEL_ID,
            ),
            room_id=DISCORD_CHANNEL_ID,
        )
        with pytest.raises(AdapterSendError):
            await adapter.send(msg)


# ---------------------------------------------------------------------------
# F. Identity binding
# ---------------------------------------------------------------------------


class TestIdentityBinding:
    @pytest.mark.asyncio
    async def test_resolve_unknown_returns_none(self):
        adapter = _make_adapter()
        pid = PlatformIdentity(
            channel=ChannelType.DISCORD,
            platform_id="U999",
            platform_name="Guest",
            room_id=DISCORD_CHANNEL_ID,
        )
        assert await adapter.resolve_fqid(pid) is None

    @pytest.mark.asyncio
    async def test_bind_and_resolve(self):
        adapter = _make_adapter()
        pid = PlatformIdentity(
            channel=ChannelType.DISCORD,
            platform_id="U42",
            platform_name="Chef",
            room_id=DISCORD_CHANNEL_ID,
        )
        await adapter.bind_fqid(pid, "chef@skworld.io", "verified")
        assert await adapter.resolve_fqid(pid) == "chef@skworld.io"

    @pytest.mark.asyncio
    async def test_preloaded_bindings_resolve(self):
        pid = PlatformIdentity(
            channel=ChannelType.DISCORD,
            platform_id="U100",
            platform_name="Lumina",
            room_id=DISCORD_CHANNEL_ID,
        )
        bindings = {pid.canonical_key: "lumina@skworld.io"}
        adapter = _make_adapter(bindings=bindings)
        assert await adapter.resolve_fqid(pid) == "lumina@skworld.io"

    @pytest.mark.asyncio
    async def test_bind_overrides_existing(self):
        pid = PlatformIdentity(
            channel=ChannelType.DISCORD,
            platform_id="U7",
            platform_name="Old",
            room_id=DISCORD_CHANNEL_ID,
        )
        bindings = {pid.canonical_key: "old@example.com"}
        adapter = _make_adapter(bindings=bindings)
        await adapter.bind_fqid(pid, "new@example.com", "trusted")
        assert await adapter.resolve_fqid(pid) == "new@example.com"

    @pytest.mark.asyncio
    async def test_canonical_key_format(self):
        pid = PlatformIdentity(
            channel=ChannelType.DISCORD,
            platform_id="CHEF_DISCORD_7",
            platform_name="Chef",
            room_id=DISCORD_CHANNEL_ID,
        )
        assert pid.canonical_key == "discord:user:CHEF_DISCORD_7"


# ---------------------------------------------------------------------------
# G. Capabilities
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_discord_capabilities(self):
        adapter = _make_adapter()
        caps = adapter.capabilities()
        assert caps.text is True
        assert caps.files is True
        assert caps.images is True
        assert caps.voice_notes is False
        assert caps.video is False
        assert caps.reactions is True
        assert caps.threads is True
        assert caps.read_receipts is False
        assert caps.typing_hint is True
        assert caps.max_text_bytes == 2000


# ---------------------------------------------------------------------------
# H. set_presence stub
# ---------------------------------------------------------------------------


class TestSetPresence:
    @pytest.mark.asyncio
    async def test_set_presence_does_not_raise(self):
        adapter = _make_adapter()
        await adapter.set_presence("lumina@skworld.io", "typing")
