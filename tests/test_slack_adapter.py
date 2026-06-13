"""
Unit tests for SlackAdapter — Batch C3.

All tests use a ``FakeSlackClient`` that satisfies :class:`SlackClientProtocol`
without making any network connections.  No real Slack credentials are required.

Coverage:
  - FakeSlackClient satisfies SlackClientProtocol (structural check)
  - connect() / disconnect() lifecycle
  - connect() raises AdapterAuthError when auth_test returns ok=false
  - connect() raises AdapterAuthError with no client and no token
  - connect() raises AdapterConnectError when auth_test raises
  - health() reflects client state
  - health() error when auth_test raises
  - _normalize():
      * text message → ChannelMessage (TEXT)
      * bot_message subtype dropped (returns None)
      * message_changed subtype dropped
      * unknown event type dropped
      * file attachment → FILE kind
      * image attachment → IMAGE kind
      * thread_ts → reply_to_platform_id
      * top-level message ts == thread_ts → reply_to_platform_id is None
  - inbound() yields normalized ChannelMessages from fake client events
  - inbound() stops when _running=False
  - send() routes to post_message (TEXT)
  - send() routes to upload_file (FILE with bytes)
  - send() with thread_ts passes thread_ts to post_message
  - send() raises AdapterSendError when post_message returns ok=false
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
    MediaAttachment,
    MessageKind,
    PlatformIdentity,
    SlackAdapter,
    TrustLevel,
)
from skcomms.adapters.base import AdapterAuthError, AdapterConnectError, AdapterSendError
from skcomms.adapters.slack import SlackClientProtocol

# ---------------------------------------------------------------------------
# FakeSlackClient — satisfies SlackClientProtocol
# ---------------------------------------------------------------------------


class FakeSlackClient:
    """
    In-memory Slack client stub for unit testing.

    Pre-loads an event queue via ``push_event``.  ``drain_events`` flushes
    and returns the queued events.  ``post_message`` / ``upload_file``
    capture calls and return fake responses.
    """

    def __init__(
        self,
        authorized: bool = True,
        bot_user_id: str = "U_LUMINA",
        team: str = "SKWorld",
        raise_on_auth: bool = False,
        raise_on_send: bool = False,
    ) -> None:
        self._authorized = authorized
        self._bot_user_id = bot_user_id
        self._team = team
        self._raise_on_auth = raise_on_auth
        self._raise_on_send = raise_on_send
        self._connected = False
        self._event_queue: list[dict] = []

        # Captured outbound calls
        self.posted_messages: list[dict] = []
        self.uploaded_files: list[dict] = []

    # --- Protocol implementation ---

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    async def auth_test(self) -> dict:
        if self._raise_on_auth:
            raise RuntimeError("auth_test: simulated failure")
        if not self._authorized:
            return {"ok": False, "error": "invalid_auth"}
        return {
            "ok": True,
            "user_id": self._bot_user_id,
            "user": "lumina",
            "team": self._team,
            "team_id": "T0001",
            "bot_id": "B0001",
        }

    async def post_message(
        self,
        channel: str,
        text: str,
        *,
        thread_ts: Optional[str] = None,
        blocks: Optional[list] = None,
    ) -> dict:
        if self._raise_on_send:
            raise RuntimeError("post_message: simulated failure")
        rec = {"channel": channel, "text": text, "thread_ts": thread_ts, "blocks": blocks}
        self.posted_messages.append(rec)
        return {"ok": True, "ts": f"1234567890.{len(self.posted_messages):06d}"}

    async def upload_file(
        self,
        channel: str,
        content: bytes,
        filename: str,
        *,
        initial_comment: str = "",
    ) -> dict:
        if self._raise_on_send:
            raise RuntimeError("upload_file: simulated failure")
        rec = {
            "channel": channel,
            "content": content,
            "filename": filename,
            "initial_comment": initial_comment,
        }
        self.uploaded_files.append(rec)
        return {"ok": True, "ts": f"9876543210.{len(self.uploaded_files):06d}"}

    def drain_events(self) -> list[dict]:
        events = list(self._event_queue)
        self._event_queue.clear()
        return events

    # --- Test helpers ---

    def push_event(self, event: dict) -> None:
        """Enqueue a fake Slack event for consumption by inbound()."""
        self._event_queue.append(event)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SLACK_CHANNEL_ID = "C0123456789"

SLACK_CONFIG = {
    "bot_token": "xoxb-fake-token",
    "app_token": "xapp-fake-token",
    "poll_interval_s": 0,
    "channels": {
        "sktechops": {
            "channel_id": SLACK_CHANNEL_ID,
            "agent_fqid": "lumina@skworld.io",
        }
    },
    "identity_store": "/tmp/test-slack-ids.yaml",
}


def _make_adapter(
    client: Optional[FakeSlackClient] = None,
    config: Optional[dict] = None,
    bindings: Optional[dict[str, str]] = None,
) -> SlackAdapter:
    return SlackAdapter(
        config=config or SLACK_CONFIG,
        slack_client=client or FakeSlackClient(),
        bindings_store=bindings or {},
    )


def _text_event(
    user: str = "U111",
    text: str = "hello",
    channel: str = SLACK_CHANNEL_ID,
    ts: str = "1234567890.000001",
) -> dict:
    return {
        "type": "message",
        "channel": channel,
        "user": user,
        "username": "chef_slack",
        "text": text,
        "ts": ts,
    }


# ---------------------------------------------------------------------------
# Verify FakeSlackClient satisfies the protocol
# ---------------------------------------------------------------------------


def test_fake_client_satisfies_protocol():
    """FakeSlackClient is a structural subtype of SlackClientProtocol."""
    client = FakeSlackClient()
    assert isinstance(client, SlackClientProtocol), (
        "FakeSlackClient does not satisfy SlackClientProtocol. "
        "Missing methods: "
        + str(
            [
                m
                for m in (
                    "is_connected",
                    "auth_test",
                    "post_message",
                    "upload_file",
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
        client = FakeSlackClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        assert client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_stores_bot_user_id(self):
        client = FakeSlackClient(bot_user_id="U_LUMINA")
        adapter = _make_adapter(client=client)
        await adapter.connect()
        assert adapter._bot_user_id == "U_LUMINA"

    @pytest.mark.asyncio
    async def test_disconnect_sets_running_false(self):
        client = FakeSlackClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not adapter._running

    @pytest.mark.asyncio
    async def test_disconnect_calls_client_disconnect(self):
        client = FakeSlackClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_when_ok_false(self):
        client = FakeSlackClient(authorized=False)
        adapter = _make_adapter(client=client)
        with pytest.raises(AdapterAuthError):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_connect_error_when_auth_test_raises(self):
        client = FakeSlackClient(raise_on_auth=True)
        adapter = _make_adapter(client=client)
        with pytest.raises(AdapterConnectError, match="auth_test failed"):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_with_no_credentials(self):
        """No slack_client, no token → AdapterAuthError."""
        adapter = SlackAdapter(
            config={"poll_interval_s": 0},
            slack_client=None,
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
        assert h.adapter_name == "slack"
        assert h.error is None

    @pytest.mark.asyncio
    async def test_health_disconnected_before_connect(self):
        client = FakeSlackClient()
        adapter = _make_adapter(client=client)
        h = await adapter.health()
        assert h.connected is False

    @pytest.mark.asyncio
    async def test_health_error_when_auth_test_raises(self):
        client = FakeSlackClient(raise_on_auth=True)
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
    def _adapter(self) -> SlackAdapter:
        return _make_adapter()

    def test_text_message(self):
        adapter = self._adapter()
        event = _text_event(user="U111", text="Hello from Slack")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.TEXT
        assert msg.text == "Hello from Slack"
        assert msg.sender.platform_id == "U111"
        assert msg.room_id == SLACK_CHANNEL_ID
        assert msg.channel == ChannelType.SLACK
        assert msg.platform_msg_id == event["ts"]

    def test_bot_message_dropped(self):
        adapter = self._adapter()
        event = {**_text_event(), "subtype": "bot_message"}
        msg = adapter._normalize(event)
        assert msg is None

    def test_message_changed_dropped(self):
        adapter = self._adapter()
        event = {**_text_event(), "subtype": "message_changed"}
        msg = adapter._normalize(event)
        assert msg is None

    def test_message_deleted_dropped(self):
        adapter = self._adapter()
        event = {**_text_event(), "subtype": "message_deleted"}
        msg = adapter._normalize(event)
        assert msg is None

    def test_unknown_event_type_dropped(self):
        adapter = self._adapter()
        event = {"type": "reaction_added", "channel": SLACK_CHANNEL_ID}
        msg = adapter._normalize(event)
        assert msg is None

    def test_file_attachment_becomes_file_kind(self):
        adapter = self._adapter()
        event = {
            "type": "message",
            "channel": SLACK_CHANNEL_ID,
            "user": "U222",
            "text": "see attachment",
            "ts": "1000.0001",
            "files": [
                {
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "size": 204800,
                    "url_private": "https://files.slack.com/report.pdf",
                }
            ],
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.FILE
        assert len(msg.attachments) == 1
        assert msg.attachments[0].filename == "report.pdf"
        assert msg.attachments[0].mime_type == "application/pdf"
        assert msg.attachments[0].size_bytes == 204800

    def test_image_attachment_becomes_image_kind(self):
        adapter = self._adapter()
        event = {
            "type": "message",
            "channel": SLACK_CHANNEL_ID,
            "user": "U333",
            "text": "",
            "ts": "2000.0001",
            "files": [
                {
                    "name": "photo.png",
                    "mimetype": "image/png",
                    "size": 51200,
                    "url_private": "https://files.slack.com/photo.png",
                }
            ],
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.IMAGE
        assert msg.attachments[0].mime_type == "image/png"

    def test_thread_ts_becomes_reply_to_platform_id(self):
        adapter = self._adapter()
        event = {
            "type": "message",
            "channel": SLACK_CHANNEL_ID,
            "user": "U444",
            "text": "reply in thread",
            "ts": "3000.0002",
            "thread_ts": "3000.0001",  # different from ts → this is a reply
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.reply_to_platform_id == "3000.0001"

    def test_thread_ts_same_as_ts_is_not_reply(self):
        """A thread root has thread_ts == ts → not a reply."""
        adapter = self._adapter()
        ts = "4000.0001"
        event = {
            "type": "message",
            "channel": SLACK_CHANNEL_ID,
            "user": "U555",
            "text": "thread root",
            "ts": ts,
            "thread_ts": ts,
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.reply_to_platform_id is None

    def test_app_mention_normalized(self):
        adapter = self._adapter()
        event = {
            "type": "app_mention",
            "channel": SLACK_CHANNEL_ID,
            "user": "U666",
            "text": "<@U_LUMINA> hey",
            "ts": "5000.0001",
        }
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.text == "<@U_LUMINA> hey"


# ---------------------------------------------------------------------------
# D. inbound() generator tests
# ---------------------------------------------------------------------------


class TestInbound:
    @pytest.mark.asyncio
    async def test_inbound_yields_one_message(self):
        client = FakeSlackClient()
        client.push_event(_text_event(text="hi slack"))
        adapter = _make_adapter(client=client)
        await adapter.connect()

        collected: list[ChannelMessage] = []

        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False  # stop after first batch

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].text == "hi slack"

    @pytest.mark.asyncio
    async def test_inbound_stops_when_not_running(self):
        client = FakeSlackClient()
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
        client = FakeSlackClient()
        client.push_event({**_text_event(text="bot noise"), "subtype": "bot_message"})
        client.push_event(_text_event(text="real message"))
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
    async def test_send_text_calls_post_message(self):
        client = FakeSlackClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.SLACK,
            kind=MessageKind.TEXT,
            text="Hello Slack!",
            sender=PlatformIdentity(
                channel=ChannelType.SLACK,
                platform_id="U111",
                platform_name="Chef",
                room_id=SLACK_CHANNEL_ID,
            ),
            room_id=SLACK_CHANNEL_ID,
        )
        ts = await adapter.send(msg)
        assert ts.startswith("1234567890.")
        assert len(client.posted_messages) == 1
        assert client.posted_messages[0]["text"] == "Hello Slack!"
        assert client.posted_messages[0]["channel"] == SLACK_CHANNEL_ID

    @pytest.mark.asyncio
    async def test_send_with_thread_ts_passes_thread_ts(self):
        client = FakeSlackClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.SLACK,
            kind=MessageKind.TEXT,
            text="threaded reply",
            sender=PlatformIdentity(
                channel=ChannelType.SLACK,
                platform_id="U111",
                platform_name="Chef",
                room_id=SLACK_CHANNEL_ID,
            ),
            room_id=SLACK_CHANNEL_ID,
            reply_to_platform_id="1000.0001",
        )
        await adapter.send(msg)
        assert client.posted_messages[0]["thread_ts"] == "1000.0001"

    @pytest.mark.asyncio
    async def test_send_file_with_bytes_calls_upload_file(self):
        client = FakeSlackClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        attachment = MediaAttachment(
            filename="report.pdf",
            mime_type="application/pdf",
            size_bytes=1024,
            data=b"%PDF fake",
        )
        msg = ChannelMessage(
            channel=ChannelType.SLACK,
            kind=MessageKind.FILE,
            text="Here is the file",
            sender=PlatformIdentity(
                channel=ChannelType.SLACK,
                platform_id="U111",
                platform_name="Chef",
                room_id=SLACK_CHANNEL_ID,
            ),
            room_id=SLACK_CHANNEL_ID,
            attachments=[attachment],
        )
        await adapter.send(msg)
        assert len(client.uploaded_files) == 1
        assert client.uploaded_files[0]["content"] == b"%PDF fake"
        assert client.uploaded_files[0]["filename"] == "report.pdf"

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_on_ok_false(self):
        """post_message returning ok=false → AdapterSendError."""

        class BadClient(FakeSlackClient):
            async def post_message(self, channel, text, **kwargs):
                return {"ok": False, "error": "channel_not_found"}

        client = BadClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.SLACK,
            kind=MessageKind.TEXT,
            text="will fail",
            sender=PlatformIdentity(
                channel=ChannelType.SLACK,
                platform_id="U1",
                platform_name="A",
                room_id=SLACK_CHANNEL_ID,
            ),
            room_id=SLACK_CHANNEL_ID,
        )
        with pytest.raises(AdapterSendError, match="Slack API error"):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_on_client_exception(self):
        client = FakeSlackClient(raise_on_send=True)
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = ChannelMessage(
            channel=ChannelType.SLACK,
            kind=MessageKind.TEXT,
            text="exception path",
            sender=PlatformIdentity(
                channel=ChannelType.SLACK,
                platform_id="U1",
                platform_name="A",
                room_id=SLACK_CHANNEL_ID,
            ),
            room_id=SLACK_CHANNEL_ID,
        )
        with pytest.raises(AdapterSendError):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_with_no_client(self):
        """No client → AdapterSendError without network call."""
        adapter = SlackAdapter(
            config={"poll_interval_s": 0},
            slack_client=None,
            bindings_store={},
        )
        msg = ChannelMessage(
            channel=ChannelType.SLACK,
            kind=MessageKind.TEXT,
            text="orphan",
            sender=PlatformIdentity(
                channel=ChannelType.SLACK,
                platform_id="U1",
                platform_name="X",
                room_id=SLACK_CHANNEL_ID,
            ),
            room_id=SLACK_CHANNEL_ID,
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
            channel=ChannelType.SLACK,
            platform_id="U999",
            platform_name="Guest",
            room_id=SLACK_CHANNEL_ID,
        )
        assert await adapter.resolve_fqid(pid) is None

    @pytest.mark.asyncio
    async def test_bind_and_resolve(self):
        adapter = _make_adapter()
        pid = PlatformIdentity(
            channel=ChannelType.SLACK,
            platform_id="U42",
            platform_name="Chef",
            room_id=SLACK_CHANNEL_ID,
        )
        await adapter.bind_fqid(pid, "chef@skworld.io", "verified")
        assert await adapter.resolve_fqid(pid) == "chef@skworld.io"

    @pytest.mark.asyncio
    async def test_preloaded_bindings_resolve(self):
        pid = PlatformIdentity(
            channel=ChannelType.SLACK,
            platform_id="U100",
            platform_name="Lumina",
            room_id=SLACK_CHANNEL_ID,
        )
        bindings = {pid.canonical_key: "lumina@skworld.io"}
        adapter = _make_adapter(bindings=bindings)
        assert await adapter.resolve_fqid(pid) == "lumina@skworld.io"

    @pytest.mark.asyncio
    async def test_bind_overrides_existing(self):
        pid = PlatformIdentity(
            channel=ChannelType.SLACK,
            platform_id="U7",
            platform_name="Old",
            room_id=SLACK_CHANNEL_ID,
        )
        bindings = {pid.canonical_key: "old@example.com"}
        adapter = _make_adapter(bindings=bindings)
        await adapter.bind_fqid(pid, "new@example.com", "trusted")
        assert await adapter.resolve_fqid(pid) == "new@example.com"

    @pytest.mark.asyncio
    async def test_canonical_key_format(self):
        pid = PlatformIdentity(
            channel=ChannelType.SLACK,
            platform_id="U_CHEF_42",
            platform_name="Chef",
            room_id=SLACK_CHANNEL_ID,
        )
        assert pid.canonical_key == "slack:user:U_CHEF_42"


# ---------------------------------------------------------------------------
# G. Capabilities
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_slack_capabilities(self):
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
        assert caps.typing_hint is False
        assert caps.max_text_bytes == 40000


# ---------------------------------------------------------------------------
# H. set_presence stub
# ---------------------------------------------------------------------------


class TestSetPresence:
    @pytest.mark.asyncio
    async def test_set_presence_does_not_raise(self):
        adapter = _make_adapter()
        await adapter.set_presence("lumina@skworld.io", "typing")
