"""
Unit tests for MatrixAdapter — C5.

All tests use a ``FakeMatrixClient`` that satisfies :class:`MatrixClientProtocol`
without making any network connections.  No live Matrix homeserver is required.

Coverage:
  - FakeMatrixClient satisfies MatrixClientProtocol (structural check)
  - connect() / disconnect() lifecycle
  - connect() raises AdapterAuthError when whoami returns no user_id
  - connect() raises AdapterAuthError with no client and no token
  - connect() raises AdapterConnectError when whoami raises
  - connect() stores agent_user_id from whoami response
  - health() reflects client state after connect
  - health() returns disconnected before connect
  - health() reports error when whoami raises
  - health() latency_ms is a non-negative float after connect
  - _normalize():
      * m.text → ChannelMessage (TEXT)
      * m.image → IMAGE kind with MediaAttachment
      * m.file → FILE kind with MediaAttachment
      * m.audio → VOICE kind with MediaAttachment
      * m.video → VIDEO kind with MediaAttachment
      * m.notice → TEXT kind (bot notice)
      * non-m.room.message event type is dropped
      * missing sender is dropped
      * self-echo (agent_user_id == sender) is dropped
      * reply threading via m.relates_to / m.in_reply_to
      * message with no reply_to has reply_to_platform_id=None
      * room_id from sync envelope propagated to ChannelMessage
  - _poll_sync() advances next_batch watermark
  - _poll_sync() returns empty list on client error
  - inbound() in appservice mode: drain_events → _normalize → yield
  - inbound() in sync mode: poll_sync → yield
  - inbound() stops when _running=False
  - send() routes to client.send_message (TEXT)
  - send() builds correct m.image content for image with mxc URL
  - send() builds correct m.file content for file with mxc URL
  - send() falls back to m.text when no mxc URL on media message
  - send() raises AdapterSendError when response missing event_id
  - send() raises AdapterSendError on client exception
  - send() raises AdapterSendError when no client
  - identity binding: resolve_fqid unknown returns None
  - identity binding: bind_fqid + resolve_fqid round-trip
  - identity binding: preloaded bindings resolve
  - identity binding: bind overrides existing
  - canonical_key format for MXID
  - _mxid_display_name: well-formed MXID extracts localpart
  - _mxid_display_name: malformed MXID returns raw string
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
    MatrixAdapter,
    MediaAttachment,
    MessageKind,
    PlatformIdentity,
    TrustLevel,
)
from skcomms.adapters.base import AdapterAuthError, AdapterConnectError, AdapterSendError
from skcomms.adapters.matrix import (
    MatrixClientProtocol,
    _mxid_display_name,
)

# ---------------------------------------------------------------------------
# FakeMatrixClient — satisfies MatrixClientProtocol
# ---------------------------------------------------------------------------


class FakeMatrixClient:
    """
    In-memory Matrix client stub for unit testing.

    Supports both operational modes:

    * **sync mode**: ``sync()`` returns a pre-built response dict.  Tests can
      push new rooms data into ``_sync_response`` between calls.
    * **appservice / queue mode**: ``push_event`` enqueues raw Matrix room
      event dicts; ``drain_events`` flushes the queue.

    ``send_message`` captures calls and returns a fake ``{"event_id": ...}``.
    """

    def __init__(
        self,
        authorized: bool = True,
        user_id: str = "@lumina:skworld.io",
        raise_on_whoami: bool = False,
        raise_on_send: bool = False,
        initial_next_batch: str = "s0",
    ) -> None:
        self._authorized = authorized
        self._user_id = user_id
        self._raise_on_whoami = raise_on_whoami
        self._raise_on_send = raise_on_send
        self._connected = False

        # sync() state
        self._next_batch = initial_next_batch
        # Callers can replace this between poll cycles
        self._sync_rooms: dict[str, dict] = {}

        # Appservice / queue mode
        self._event_queue: list[dict] = []

        # Captured outbound calls
        self.sent_messages: list[dict] = []

    # --- Protocol implementation ---

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    async def whoami(self) -> dict:
        if self._raise_on_whoami:
            raise RuntimeError("whoami: simulated failure")
        if not self._authorized:
            return {}  # no "user_id" → AdapterAuthError
        return {"user_id": self._user_id}

    async def sync(
        self,
        since: Optional[str] = None,
        timeout_ms: int = 30000,
    ) -> dict:
        # Advance the token to simulate a real server
        next_token = f"s{int(self._next_batch[1:]) + 1}"
        self._next_batch = next_token
        return {
            "next_batch": next_token,
            "rooms": {
                "join": self._sync_rooms,
            },
        }

    async def send_message(
        self,
        room_id: str,
        content: dict,
        *,
        txn_id: str,
    ) -> dict:
        if self._raise_on_send:
            raise RuntimeError("send_message: simulated failure")
        rec = {"room_id": room_id, "content": content, "txn_id": txn_id}
        self.sent_messages.append(rec)
        return {"event_id": f"$EVENTID_{len(self.sent_messages)}"}

    def drain_events(self) -> list[dict]:
        events = list(self._event_queue)
        self._event_queue.clear()
        return events

    # --- Test helpers ---

    def push_event(self, event: dict) -> None:
        """Enqueue a fake Matrix room event for consumption by inbound()."""
        self._event_queue.append(event)

    def set_sync_room(self, room_id: str, events: list[dict]) -> None:
        """Pre-load events for a room into the sync response."""
        self._sync_rooms[room_id] = {
            "timeline": {"events": events}
        }


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

MATRIX_ROOM_ID = "!opaque1234:skworld.io"
MATRIX_HOMESERVER = "https://matrix.skworld.io"
AGENT_MXID = "@lumina:skworld.io"
CHEF_MXID = "@chef:skworld.io"

MATRIX_CONFIG = {
    "homeserver": MATRIX_HOMESERVER,
    "access_token": "syt_fake_access_token",
    "user_id": AGENT_MXID,
    "poll_interval_s": 0,  # no sleep in tests
    "appservice": False,
    "rooms": {
        "skworld_general": {
            "room_id": MATRIX_ROOM_ID,
            "agent_fqid": "lumina@skworld.io",
        }
    },
    "identity_store": "/tmp/test-matrix-ids.yaml",
}

APPSERVICE_CONFIG = {
    **MATRIX_CONFIG,
    "appservice": True,
    "appservice_token": "hs_fake_appservice_token",
}


def _make_adapter(
    client: Optional[FakeMatrixClient] = None,
    config: Optional[dict] = None,
    bindings: Optional[dict[str, str]] = None,
) -> MatrixAdapter:
    return MatrixAdapter(
        config=config or MATRIX_CONFIG,
        matrix_client=client or FakeMatrixClient(),
        bindings_store=bindings or {},
    )


def _text_event(
    sender: str = CHEF_MXID,
    body: str = "hello",
    event_id: str = "$EVT001",
    room_id: str = MATRIX_ROOM_ID,
    msgtype: str = "m.text",
    extra_content: Optional[dict] = None,
) -> dict:
    """Build a minimal ``m.room.message`` Matrix event dict."""
    content: dict = {"msgtype": msgtype, "body": body}
    if extra_content:
        content.update(extra_content)
    return {
        "type": "m.room.message",
        "event_id": event_id,
        "room_id": room_id,
        "sender": sender,
        "origin_server_ts": 1718150400000,
        "content": content,
    }


def _media_event(
    msgtype: str = "m.image",
    filename: str = "photo.jpg",
    mxc_url: str = "mxc://skworld.io/abc123",
    mime: str = "image/jpeg",
    size: int = 102400,
    sender: str = CHEF_MXID,
    event_id: str = "$EVT002",
    room_id: str = MATRIX_ROOM_ID,
) -> dict:
    """Build a minimal Matrix media event dict."""
    return {
        "type": "m.room.message",
        "event_id": event_id,
        "room_id": room_id,
        "sender": sender,
        "origin_server_ts": 1718150400000,
        "content": {
            "msgtype": msgtype,
            "body": filename,
            "url": mxc_url,
            "info": {
                "mimetype": mime,
                "size": size,
            },
        },
    }


# ---------------------------------------------------------------------------
# Verify FakeMatrixClient satisfies the protocol
# ---------------------------------------------------------------------------


def test_fake_client_satisfies_protocol():
    """FakeMatrixClient is a structural subtype of MatrixClientProtocol."""
    client = FakeMatrixClient()
    assert isinstance(client, MatrixClientProtocol), (
        "FakeMatrixClient does not satisfy MatrixClientProtocol. "
        "Missing methods: "
        + str(
            [
                m
                for m in (
                    "is_connected",
                    "whoami",
                    "sync",
                    "send_message",
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
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        assert client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_stores_agent_user_id_from_whoami(self):
        client = FakeMatrixClient(user_id="@lumina:skworld.io")
        # Config has no user_id — should be filled from whoami
        config = {**MATRIX_CONFIG}
        config.pop("user_id", None)
        adapter = MatrixAdapter(config=config, matrix_client=client, bindings_store={})
        await adapter.connect()
        assert adapter._agent_user_id == "@lumina:skworld.io"

    @pytest.mark.asyncio
    async def test_connect_keeps_config_user_id_when_present(self):
        client = FakeMatrixClient(user_id="@whoami:server.io")
        adapter = _make_adapter(client=client)
        await adapter.connect()
        # Config says AGENT_MXID, whoami says something else — config wins
        assert adapter._agent_user_id == AGENT_MXID

    @pytest.mark.asyncio
    async def test_disconnect_sets_running_false(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not adapter._running

    @pytest.mark.asyncio
    async def test_disconnect_calls_client_disconnect(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        await adapter.disconnect()
        assert not client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_when_whoami_returns_no_user_id(self):
        client = FakeMatrixClient(authorized=False)
        adapter = _make_adapter(client=client)
        with pytest.raises(AdapterAuthError, match="user_id"):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_connect_error_when_whoami_raises(self):
        client = FakeMatrixClient(raise_on_whoami=True)
        adapter = _make_adapter(client=client)
        with pytest.raises(AdapterConnectError, match="whoami failed"):
            await adapter.connect()

    @pytest.mark.asyncio
    async def test_connect_raises_adapter_auth_error_with_no_credentials(self):
        """No matrix_client, no access_token → AdapterAuthError."""
        adapter = MatrixAdapter(
            config={"poll_interval_s": 0},
            matrix_client=None,
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
        assert h.adapter_name == "matrix"
        assert h.error is None

    @pytest.mark.asyncio
    async def test_health_disconnected_before_connect(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        h = await adapter.health()
        assert h.connected is False

    @pytest.mark.asyncio
    async def test_health_error_when_whoami_raises(self):
        client = FakeMatrixClient(raise_on_whoami=True)
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

    @pytest.mark.asyncio
    async def test_health_no_client_returns_running_state(self):
        """Stub path: no client, running=True → connected=True."""
        adapter = MatrixAdapter(
            config={"poll_interval_s": 0},
            matrix_client=None,
            bindings_store={},
        )
        adapter._running = True
        h = await adapter.health()
        assert h.connected is True
        assert h.latency_ms is None


# ---------------------------------------------------------------------------
# C. _normalize tests
# ---------------------------------------------------------------------------


class TestNormalize:
    def _adapter(self) -> MatrixAdapter:
        return _make_adapter()

    def test_text_message(self):
        adapter = self._adapter()
        event = _text_event(sender=CHEF_MXID, body="Hello Lumina!", event_id="$E001")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.TEXT
        assert msg.text == "Hello Lumina!"
        assert msg.platform_msg_id == "$E001"
        assert msg.sender.platform_id == CHEF_MXID
        assert msg.sender.platform_name == "chef"
        assert msg.room_id == MATRIX_ROOM_ID
        assert msg.channel == ChannelType.MATRIX

    def test_image_message(self):
        adapter = self._adapter()
        event = _media_event(
            msgtype="m.image",
            filename="photo.jpg",
            mxc_url="mxc://skworld.io/abc123",
            mime="image/jpeg",
            size=102400,
        )
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.IMAGE
        assert len(msg.attachments) == 1
        att = msg.attachments[0]
        assert att.filename == "photo.jpg"
        assert att.mime_type == "image/jpeg"
        assert att.size_bytes == 102400
        assert att.url == "mxc://skworld.io/abc123"

    def test_file_message(self):
        adapter = self._adapter()
        event = _media_event(
            msgtype="m.file",
            filename="report.pdf",
            mxc_url="mxc://skworld.io/pdf123",
            mime="application/pdf",
            size=204800,
        )
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.FILE
        assert msg.attachments[0].mime_type == "application/pdf"
        assert msg.attachments[0].filename == "report.pdf"

    def test_audio_message_becomes_voice_kind(self):
        adapter = self._adapter()
        event = _media_event(
            msgtype="m.audio",
            filename="voice.ogg",
            mxc_url="mxc://skworld.io/ogg123",
            mime="audio/ogg",
            size=12345,
        )
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.VOICE
        assert msg.attachments[0].mime_type == "audio/ogg"

    def test_video_message(self):
        adapter = self._adapter()
        event = _media_event(
            msgtype="m.video",
            filename="clip.mp4",
            mxc_url="mxc://skworld.io/mp4123",
            mime="video/mp4",
            size=5000000,
        )
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.VIDEO
        assert msg.attachments[0].mime_type == "video/mp4"

    def test_notice_message_treated_as_text(self):
        """m.notice (bot notices) are normalized to TEXT kind."""
        adapter = self._adapter()
        event = _text_event(msgtype="m.notice", body="I am a notice")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.kind == MessageKind.TEXT
        assert msg.text == "I am a notice"

    def test_non_room_message_event_dropped(self):
        """Events with type != m.room.message are silently dropped."""
        adapter = self._adapter()
        event = {
            "type": "m.room.member",
            "event_id": "$M001",
            "room_id": MATRIX_ROOM_ID,
            "sender": CHEF_MXID,
            "content": {"membership": "join"},
        }
        msg = adapter._normalize(event)
        assert msg is None

    def test_m_reaction_event_dropped(self):
        """m.reaction is not an m.room.message — must be dropped."""
        adapter = self._adapter()
        event = {
            "type": "m.reaction",
            "event_id": "$R001",
            "room_id": MATRIX_ROOM_ID,
            "sender": CHEF_MXID,
            "content": {
                "m.relates_to": {
                    "rel_type": "m.annotation",
                    "event_id": "$EVT001",
                    "key": "👍",
                }
            },
        }
        msg = adapter._normalize(event)
        assert msg is None

    def test_missing_sender_drops_event(self):
        adapter = self._adapter()
        event = _text_event(sender=CHEF_MXID, body="ghost")
        event["sender"] = ""  # empty sender
        msg = adapter._normalize(event)
        assert msg is None

    def test_self_echo_dropped(self):
        """Events where sender == agent_user_id are dropped."""
        adapter = _make_adapter()
        adapter._agent_user_id = AGENT_MXID
        event = _text_event(sender=AGENT_MXID, body="self echo")
        msg = adapter._normalize(event)
        assert msg is None

    def test_reply_threading_via_relates_to(self):
        """m.relates_to / m.in_reply_to propagates to reply_to_platform_id."""
        adapter = self._adapter()
        event = _text_event(
            body="reply to something",
            extra_content={
                "m.relates_to": {
                    "m.in_reply_to": {"event_id": "$PARENT_001"}
                }
            },
        )
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.reply_to_platform_id == "$PARENT_001"

    def test_no_reply_to_is_none(self):
        adapter = self._adapter()
        event = _text_event(body="top-level")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.reply_to_platform_id is None

    def test_room_id_from_event_propagated(self):
        """room_id embedded in the event ends up in ChannelMessage.room_id."""
        adapter = self._adapter()
        other_room = "!otherroom:matrix.org"
        event = _text_event(body="cross-room", room_id=other_room)
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.room_id == other_room

    def test_sender_platform_name_is_localpart_of_mxid(self):
        """@chef:skworld.io → platform_name = 'chef'."""
        adapter = self._adapter()
        event = _text_event(sender="@chef:skworld.io")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.sender.platform_name == "chef"

    def test_unknown_msgtype_dropped(self):
        """Custom / unknown msgtypes that are m.room.message but unknown type → dropped."""
        adapter = self._adapter()
        event = _text_event(msgtype="org.example.custom_type", body="custom")
        msg = adapter._normalize(event)
        assert msg is None

    def test_raw_payload_stored(self):
        """raw_payload on the ChannelMessage equals the original event dict."""
        adapter = self._adapter()
        event = _text_event(body="check raw")
        msg = adapter._normalize(event)
        assert msg is not None
        assert msg.raw_payload is event


# ---------------------------------------------------------------------------
# D. _poll_sync tests
# ---------------------------------------------------------------------------


class TestPollSync:
    @pytest.mark.asyncio
    async def test_poll_sync_advances_next_batch(self):
        client = FakeMatrixClient(initial_next_batch="s0")
        adapter = _make_adapter(client=client)
        assert adapter._next_batch is None  # before first sync
        results = await adapter._poll_sync()
        assert adapter._next_batch == "s1"

    @pytest.mark.asyncio
    async def test_poll_sync_returns_normalized_messages(self):
        client = FakeMatrixClient()
        event = _text_event(sender=CHEF_MXID, body="sync message", room_id=MATRIX_ROOM_ID)
        # The event in sync response doesn't carry room_id — the adapter adds it
        event_no_room = {k: v for k, v in event.items() if k != "room_id"}
        client.set_sync_room(MATRIX_ROOM_ID, [event_no_room])
        adapter = _make_adapter(client=client)
        results = await adapter._poll_sync()
        assert len(results) == 1
        assert results[0].text == "sync message"
        assert results[0].room_id == MATRIX_ROOM_ID

    @pytest.mark.asyncio
    async def test_poll_sync_drops_self_echo(self):
        client = FakeMatrixClient()
        self_event = _text_event(
            sender=AGENT_MXID,  # agent's own MXID
            body="my own message",
            room_id=MATRIX_ROOM_ID,
        )
        client.set_sync_room(MATRIX_ROOM_ID, [self_event])
        adapter = _make_adapter(client=client)
        results = await adapter._poll_sync()
        assert results == []

    @pytest.mark.asyncio
    async def test_poll_sync_returns_empty_on_error(self):
        """Network errors in sync() are swallowed; returns empty list."""

        class BrokenClient(FakeMatrixClient):
            async def sync(self, since=None, timeout_ms=30000):
                raise RuntimeError("simulated network failure")

        client = BrokenClient()
        adapter = _make_adapter(client=client)
        results = await adapter._poll_sync()
        assert results == []


# ---------------------------------------------------------------------------
# E. inbound() generator tests
# ---------------------------------------------------------------------------


class TestInbound:
    @pytest.mark.asyncio
    async def test_inbound_appservice_mode_yields_message(self):
        """In appservice mode, drain_events drives the inbound stream."""
        client = FakeMatrixClient()
        client.push_event(_text_event(body="appservice msg"))
        adapter = _make_adapter(client=client, config=APPSERVICE_CONFIG)
        await adapter.connect()

        collected: list[ChannelMessage] = []

        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].text == "appservice msg"

    @pytest.mark.asyncio
    async def test_inbound_sync_mode_yields_message(self):
        """In sync mode, _poll_sync drives the inbound stream."""
        client = FakeMatrixClient()
        event = _text_event(sender=CHEF_MXID, body="sync hello")
        # Don't include room_id in event body — adapter injects it from sync envelope
        event_no_room = {k: v for k, v in event.items() if k != "room_id"}
        client.set_sync_room(MATRIX_ROOM_ID, [event_no_room])

        # Use sync mode (appservice=False)
        adapter = _make_adapter(client=client, config=MATRIX_CONFIG)
        await adapter.connect()

        collected: list[ChannelMessage] = []

        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].text == "sync hello"

    @pytest.mark.asyncio
    async def test_inbound_stops_when_not_running(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()
        adapter._running = False

        collected = []
        async for m in adapter.inbound():
            collected.append(m)
        assert collected == []

    @pytest.mark.asyncio
    async def test_inbound_appservice_drops_unknown_event_types(self):
        """Non-m.room.message events pushed into appservice queue are dropped."""
        client = FakeMatrixClient()
        client.push_event({"type": "m.room.member", "sender": CHEF_MXID, "content": {}})
        client.push_event(_text_event(body="good msg"))
        adapter = _make_adapter(client=client, config=APPSERVICE_CONFIG)
        await adapter.connect()

        collected: list[ChannelMessage] = []

        async def _collect():
            async for m in adapter.inbound():
                collected.append(m)
                adapter._running = False

        await asyncio.wait_for(_collect(), timeout=2.0)
        assert len(collected) == 1
        assert collected[0].text == "good msg"


# ---------------------------------------------------------------------------
# F. send() tests
# ---------------------------------------------------------------------------


class TestSend:
    def _outbound_msg(
        self,
        kind: MessageKind = MessageKind.TEXT,
        text: str = "Hello Matrix!",
        room_id: str = MATRIX_ROOM_ID,
        attachments: Optional[list[MediaAttachment]] = None,
        reply_to: Optional[str] = None,
    ) -> ChannelMessage:
        return ChannelMessage(
            channel=ChannelType.MATRIX,
            kind=kind,
            text=text,
            sender=PlatformIdentity(
                channel=ChannelType.MATRIX,
                platform_id=CHEF_MXID,
                platform_name="chef",
                room_id=room_id,
            ),
            room_id=room_id,
            attachments=attachments or [],
            reply_to_platform_id=reply_to,
        )

    @pytest.mark.asyncio
    async def test_send_text_calls_send_message(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = self._outbound_msg(text="Hello Matrix!")
        event_id = await adapter.send(msg)
        assert event_id == "$EVENTID_1"
        assert len(client.sent_messages) == 1
        sent = client.sent_messages[0]
        assert sent["room_id"] == MATRIX_ROOM_ID
        assert sent["content"]["msgtype"] == "m.text"
        assert sent["content"]["body"] == "Hello Matrix!"

    @pytest.mark.asyncio
    async def test_send_returns_event_id(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = self._outbound_msg(text="id test")
        eid = await adapter.send(msg)
        assert eid.startswith("$EVENTID_")

    @pytest.mark.asyncio
    async def test_send_image_with_mxc_url_builds_m_image_content(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        att = MediaAttachment(
            filename="photo.jpg",
            mime_type="image/jpeg",
            size_bytes=80000,
            url="mxc://skworld.io/img123",
        )
        msg = self._outbound_msg(
            kind=MessageKind.IMAGE,
            text="check this out",
            attachments=[att],
        )
        await adapter.send(msg)
        sent_content = client.sent_messages[0]["content"]
        assert sent_content["msgtype"] == "m.image"
        assert sent_content["body"] == "photo.jpg"
        assert sent_content["url"] == "mxc://skworld.io/img123"
        assert sent_content["info"]["mimetype"] == "image/jpeg"

    @pytest.mark.asyncio
    async def test_send_file_with_mxc_url_builds_m_file_content(self):
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        att = MediaAttachment(
            filename="doc.pdf",
            mime_type="application/pdf",
            size_bytes=204800,
            url="mxc://skworld.io/pdf999",
        )
        msg = self._outbound_msg(
            kind=MessageKind.FILE,
            text="",
            attachments=[att],
        )
        await adapter.send(msg)
        sent_content = client.sent_messages[0]["content"]
        assert sent_content["msgtype"] == "m.file"
        assert sent_content["body"] == "doc.pdf"
        assert sent_content["url"] == "mxc://skworld.io/pdf999"

    @pytest.mark.asyncio
    async def test_send_image_without_mxc_url_falls_back_to_text(self):
        """IMAGE with no mxc URL (raw bytes only) → m.text fallback."""
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        att = MediaAttachment(
            filename="image.png",
            mime_type="image/png",
            size_bytes=1024,
            url=None,  # no mxc URL
            data=b"\x89PNG fake",
        )
        msg = self._outbound_msg(kind=MessageKind.IMAGE, text="image", attachments=[att])
        await adapter.send(msg)
        sent_content = client.sent_messages[0]["content"]
        assert sent_content["msgtype"] == "m.text"

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_when_response_missing_event_id(self):
        """send_message returning a dict without 'event_id' → AdapterSendError."""

        class BadClient(FakeMatrixClient):
            async def send_message(self, room_id, content, *, txn_id):
                return {"room_id": room_id}  # missing "event_id"

        client = BadClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = self._outbound_msg(text="will fail")
        with pytest.raises(AdapterSendError, match="event_id"):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_on_client_exception(self):
        client = FakeMatrixClient(raise_on_send=True)
        adapter = _make_adapter(client=client)
        await adapter.connect()

        msg = self._outbound_msg(text="exception path")
        with pytest.raises(AdapterSendError):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_raises_adapter_send_error_with_no_client(self):
        """No client → AdapterSendError without network call."""
        adapter = MatrixAdapter(
            config={"poll_interval_s": 0},
            matrix_client=None,
            bindings_store={},
        )
        msg = ChannelMessage(
            channel=ChannelType.MATRIX,
            kind=MessageKind.TEXT,
            text="orphan",
            sender=PlatformIdentity(
                channel=ChannelType.MATRIX,
                platform_id=CHEF_MXID,
                platform_name="chef",
                room_id=MATRIX_ROOM_ID,
            ),
            room_id=MATRIX_ROOM_ID,
        )
        with pytest.raises(AdapterSendError):
            await adapter.send(msg)

    @pytest.mark.asyncio
    async def test_send_txn_id_increments_across_sends(self):
        """Each send uses a unique txn_id."""
        client = FakeMatrixClient()
        adapter = _make_adapter(client=client)
        await adapter.connect()

        for i in range(3):
            await adapter.send(self._outbound_msg(text=f"msg {i}"))

        txn_ids = [m["txn_id"] for m in client.sent_messages]
        assert len(set(txn_ids)) == 3  # all unique


# ---------------------------------------------------------------------------
# G. Identity binding tests
# ---------------------------------------------------------------------------


class TestIdentityBinding:
    @pytest.mark.asyncio
    async def test_resolve_unknown_returns_none(self):
        adapter = _make_adapter()
        pid = PlatformIdentity(
            channel=ChannelType.MATRIX,
            platform_id=CHEF_MXID,
            platform_name="chef",
            room_id=MATRIX_ROOM_ID,
        )
        assert await adapter.resolve_fqid(pid) is None

    @pytest.mark.asyncio
    async def test_bind_and_resolve(self):
        adapter = _make_adapter()
        pid = PlatformIdentity(
            channel=ChannelType.MATRIX,
            platform_id=CHEF_MXID,
            platform_name="chef",
            room_id=MATRIX_ROOM_ID,
        )
        await adapter.bind_fqid(pid, "chef@skworld.io", "verified")
        assert await adapter.resolve_fqid(pid) == "chef@skworld.io"

    @pytest.mark.asyncio
    async def test_preloaded_bindings_resolve(self):
        pid = PlatformIdentity(
            channel=ChannelType.MATRIX,
            platform_id=AGENT_MXID,
            platform_name="lumina",
            room_id=MATRIX_ROOM_ID,
        )
        bindings = {pid.canonical_key: "lumina@skworld.io"}
        adapter = _make_adapter(bindings=bindings)
        assert await adapter.resolve_fqid(pid) == "lumina@skworld.io"

    @pytest.mark.asyncio
    async def test_bind_overrides_existing(self):
        pid = PlatformIdentity(
            channel=ChannelType.MATRIX,
            platform_id=CHEF_MXID,
            platform_name="chef",
            room_id=MATRIX_ROOM_ID,
        )
        bindings = {pid.canonical_key: "old@example.com"}
        adapter = _make_adapter(bindings=bindings)
        await adapter.bind_fqid(pid, "new@example.com", "trusted")
        assert await adapter.resolve_fqid(pid) == "new@example.com"

    def test_canonical_key_format_for_mxid(self):
        """canonical_key for a Matrix MXID uses the expected format."""
        pid = PlatformIdentity(
            channel=ChannelType.MATRIX,
            platform_id="@chef:skworld.io",
            platform_name="chef",
            room_id=MATRIX_ROOM_ID,
        )
        assert pid.canonical_key == "matrix:user:@chef:skworld.io"

    @pytest.mark.asyncio
    async def test_lumina_chef_binding_round_trip(self):
        """
        Demonstrates the full MXID ↔ FQID binding flow for the primary agents.
        """
        chef_pid = PlatformIdentity(
            channel=ChannelType.MATRIX,
            platform_id="@chef:skworld.io",
            platform_name="chef",
            room_id=MATRIX_ROOM_ID,
            room_name="skworld_general",
        )
        adapter = _make_adapter()
        # Initially unbound
        assert await adapter.resolve_fqid(chef_pid) is None
        # After /bind flow
        await adapter.bind_fqid(chef_pid, "chef@skworld.io", "sovereign")
        assert await adapter.resolve_fqid(chef_pid) == "chef@skworld.io"
        assert chef_pid.canonical_key == "matrix:user:@chef:skworld.io"


# ---------------------------------------------------------------------------
# H. _mxid_display_name helper tests
# ---------------------------------------------------------------------------


class TestMxidDisplayName:
    def test_well_formed_mxid_extracts_localpart(self):
        assert _mxid_display_name("@lumina:skworld.io") == "lumina"
        assert _mxid_display_name("@chef:skworld.io") == "chef"
        assert _mxid_display_name("@jarvis:matrix.org") == "jarvis"

    def test_malformed_mxid_returns_raw_string(self):
        assert _mxid_display_name("not-an-mxid") == "not-an-mxid"
        assert _mxid_display_name("") == ""

    def test_mxid_without_at_returns_raw_string(self):
        assert _mxid_display_name("chef:skworld.io") == "chef:skworld.io"


# ---------------------------------------------------------------------------
# I. Capabilities
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_matrix_capabilities(self):
        adapter = _make_adapter()
        caps = adapter.capabilities()
        assert caps.text is True
        assert caps.files is True
        assert caps.images is True
        assert caps.voice_notes is True
        assert caps.video is True
        assert caps.reactions is True
        assert caps.threads is False     # MSC3440 not universally deployed yet
        assert caps.read_receipts is True
        assert caps.typing_hint is True
        assert caps.max_text_bytes == 65536


# ---------------------------------------------------------------------------
# J. set_presence stub
# ---------------------------------------------------------------------------


class TestSetPresence:
    @pytest.mark.asyncio
    async def test_set_presence_does_not_raise(self):
        adapter = _make_adapter()
        await adapter.set_presence("lumina@skworld.io", "typing")


# ---------------------------------------------------------------------------
# K. ChannelType.MATRIX exists
# ---------------------------------------------------------------------------


def test_channel_type_matrix_exists():
    """ChannelType.MATRIX must be present in the enum."""
    assert ChannelType.MATRIX == "matrix"


def test_matrix_adapter_channel_type():
    """MatrixAdapter.channel_type must be ChannelType.MATRIX."""
    adapter = _make_adapter()
    assert adapter.channel_type == ChannelType.MATRIX
    assert adapter.adapter_name == "matrix"
