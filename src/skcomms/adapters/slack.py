"""
SlackAdapter — Slack Events API / Socket Mode channel adapter (Batch C3).

Receives events from a Slack workspace via Socket Mode (real-time WebSocket,
preferred) or the Events API (webhook), normalises them into
:class:`~skcomms.adapters.models.ChannelMessage`, and delivers outbound
messages via the Slack Web API (``chat.postMessage``).

The Slack client is **injectable** (pass ``slack_client`` to the constructor)
so the adapter is fully unit-testable without any live credentials.  The
production path would use `slack_sdk`; the injectable protocol covers only the
calls this adapter actually makes.

Config block in ``~/.skcomm/config.yml``::

    adapters:
      slack:
        enabled: true
        bot_token: "${SLACK_BOT_TOKEN}"       # xoxb-…  (required for send + REST health)
        app_token: "${SLACK_APP_TOKEN}"       # xapp-…  (required for Socket Mode)
        poll_interval_s: 1
        channels:
          sktechops:
            channel_id: "C0123456789"
            agent_fqid: "lumina@skworld.io"
        identity_store: "~/.skcomm/adapters/slack-ids.yaml"

Scopes required (Bot Token)
---------------------------
  chat:write, channels:history, groups:history, im:history, mpim:history,
  channels:read, groups:read, im:read, mpim:read,
  users:read, reactions:read, files:read

Socket Mode app-level token scopes
-----------------------------------
  connections:write

Implementation notes
--------------------
* The adapter accepts an optional ``slack_client`` satisfying
  :class:`SlackClientProtocol`.  Tests pass :class:`FakeSlackClient`;
  production builds pass a real ``slack_sdk.WebClient``-based wrapper.
* ``bindings_store``: inject an in-memory dict to skip YAML I/O in tests.
* No live connections are made at import time or before ``connect()``.

TODO (post-C3, live wiring):
  - Wire real ``slack_sdk.SocketModeClient`` in ``_build_slack_client``.
  - Implement reaction events (``reaction_added`` / ``reaction_removed``).
  - Add file download via ``files.info`` + ``url_private_download``.
  - Handle threaded replies (``thread_ts`` correlation).
  - Implement ``set_presence`` (``chat.postMessage`` typing indicator).

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §7
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from queue import Empty, Queue
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

logger = logging.getLogger("skcomms.adapters.slack")

# ---------------------------------------------------------------------------
# Injectable client protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SlackClientProtocol(Protocol):
    """
    Structural protocol for the injectable Slack client.

    Both the real ``slack_sdk``-based wrapper and :class:`FakeSlackClient`
    satisfy this interface.
    """

    def is_connected(self) -> bool: ...

    async def auth_test(self) -> dict: ...

    async def post_message(
        self,
        channel: str,
        text: str,
        *,
        thread_ts: Optional[str] = None,
        blocks: Optional[list] = None,
    ) -> dict: ...

    async def upload_file(
        self,
        channel: str,
        content: bytes,
        filename: str,
        *,
        initial_comment: str = "",
    ) -> dict: ...

    def drain_events(self) -> list[dict]: ...

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...


# ---------------------------------------------------------------------------
# SlackAdapter
# ---------------------------------------------------------------------------


class SlackAdapter(ChannelAdapter):
    """
    Slack adapter using Socket Mode + Web API (Batch C3).

    Args:
        config: Adapter config dict (see module docstring for shape).
        slack_client: Optional injectable client satisfying
            :class:`SlackClientProtocol`.  Tests pass a
            :class:`~tests.test_slack_adapter.FakeSlackClient`;
            production omits this arg and the adapter builds a real
            client from config.
        bindings_store: Optional dict used as the in-memory identity map
            instead of the YAML file on disk (useful for unit testing).
    """

    channel_type = ChannelType.SLACK
    adapter_name = "slack"

    def __init__(
        self,
        config: dict,
        slack_client: Optional[SlackClientProtocol] = None,
        bindings_store: Optional[dict[str, str]] = None,
    ) -> None:
        # --- Core config ---
        self._bot_token: str = config.get("bot_token", "")
        self._app_token: str = config.get("app_token", "")
        self._poll_s: float = config.get("poll_interval_s", 1)
        self._channels: dict[str, dict] = config.get("channels", {})
        self._id_store_path: str = config.get(
            "identity_store", "~/.skcomm/adapters/slack-ids.yaml"
        )

        # --- State ---
        self._running = False
        self._bot_user_id: Optional[str] = None
        self._workspace_name: Optional[str] = None

        # --- Identity bindings ---
        self._bindings: dict[str, str] = (
            bindings_store if bindings_store is not None else {}
        )
        self._external_bindings = bindings_store is not None

        # --- Injectable client ---
        self._client: Optional[SlackClientProtocol] = slack_client

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Authenticate with Slack and start the event socket.

        When a real (or fake injectable) client is provided it calls
        ``auth_test()`` to verify the token.  In stub mode (no client, no
        token), raises :class:`AdapterAuthError`.
        """
        if self._client is None:
            self._client = self._build_slack_client()

        if self._client is not None:
            await self._client.connect()
            try:
                info = await self._client.auth_test()
            except Exception as exc:
                raise AdapterConnectError(
                    f"Slack auth_test failed: {exc}"
                ) from exc

            if not info.get("ok", False):
                raise AdapterAuthError(
                    f"Slack auth_test returned ok=false: {info.get('error', 'unknown')}"
                )

            self._bot_user_id = info.get("user_id")
            self._workspace_name = info.get("team")
            logger.info(
                "slack adapter connected as %s (workspace=%s)",
                self._bot_user_id,
                self._workspace_name,
            )
        else:
            raise AdapterAuthError(
                "SlackAdapter requires a bot_token (xoxb-…) and optionally an "
                "app_token (xapp-…) for Socket Mode."
            )

        if not self._external_bindings:
            self._load_bindings()

        self._running = True
        logger.info("slack adapter ready")

    async def disconnect(self) -> None:
        """Stop the inbound loop and close the socket."""
        self._running = False
        if self._client is not None and self._client.is_connected():
            await self._client.disconnect()
        logger.info("slack adapter disconnected")

    async def health(self) -> AdapterHealth:
        """Return a point-in-time health snapshot via auth_test."""
        import time

        if self._client is not None:
            connected = self._client.is_connected()
            t0 = time.monotonic()
            try:
                info = await self._client.auth_test()
                latency_ms = (time.monotonic() - t0) * 1000
                ok = info.get("ok", False)
                return AdapterHealth(
                    adapter_name=self.adapter_name,
                    connected=connected and ok,
                    latency_ms=latency_ms,
                    error=None if ok else info.get("error"),
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
        """Slack capabilities."""
        return AdapterCapabilities(
            text=True,
            files=True,
            images=True,
            voice_notes=False,   # Slack has audio clips but no classic voice notes
            video=False,
            reactions=True,
            threads=True,        # Slack threaded replies
            read_receipts=False,
            typing_hint=False,   # chat.postMessage typing = not standard
            max_text_bytes=40000,  # Slack message text limit ~40 KB
        )

    # -----------------------------------------------------------------------
    # Inbound (platform → skcomms)
    # -----------------------------------------------------------------------

    async def inbound(self) -> AsyncIterator[ChannelMessage]:
        """
        Drain events pushed by the Socket Mode client and yield one
        :class:`ChannelMessage` per event.

        The injectable client exposes :meth:`drain_events` which returns
        a list of raw Slack event payloads (dicts).  In production, the
        real Socket Mode client enqueues events into an asyncio queue that
        ``drain_events`` flushes; tests push events directly into the fake
        client's queue.
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
        Translate a raw Slack event payload into a :class:`ChannelMessage`.

        Handles:
        * ``message`` subtype (new + edited messages)
        * ``file_share`` subtype → FILE / IMAGE
        * Reactions are NOT normalised here (separate event type, TODO).

        Slack event shape expected::

            {
              "type": "message",
              "channel": "C0123456789",
              "user": "U111",
              "text": "Hello",
              "ts": "1234567890.123456",
              "thread_ts": "...",   # optional
              "files": [...],       # optional
            }

        Unknown / bot messages and subtypes that indicate edits are
        dropped with a debug log to keep the inbound stream clean.
        """
        etype = event.get("type")
        if etype not in ("message", "app_mention"):
            logger.debug("slack: dropping event type=%s", etype)
            return None

        # Drop bot messages (subtype=bot_message) to avoid self-echo
        subtype = event.get("subtype")
        if subtype in ("bot_message", "message_changed", "message_deleted"):
            logger.debug("slack: dropping subtype=%s", subtype)
            return None

        user_id = event.get("user") or event.get("bot_id") or "unknown"
        username = event.get("username") or user_id
        channel_id = event.get("channel", "unknown")
        ts = event.get("ts", "")
        thread_ts = event.get("thread_ts")

        # Resolve room name from configured channels if possible
        room_name: Optional[str] = None
        for ch_cfg in self._channels.values():
            if ch_cfg.get("channel_id") == channel_id:
                room_name = ch_cfg.get("channel_id")
                break

        sender = PlatformIdentity(
            channel=ChannelType.SLACK,
            platform_id=user_id,
            platform_name=username,
            room_id=channel_id,
            room_name=room_name,
        )

        # Determine kind + attachments
        kind = MessageKind.TEXT
        text: str = event.get("text") or ""
        attachments: list[MediaAttachment] = []

        files = event.get("files", [])
        if files:
            f = files[0]
            mime = f.get("mimetype", "application/octet-stream")
            size = f.get("size", 0)
            name = f.get("name") or f.get("title") or "file"
            url = f.get("url_private")
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

        return ChannelMessage(
            channel=ChannelType.SLACK,
            kind=kind,
            text=text,
            sender=sender,
            room_id=channel_id,
            platform_msg_id=ts,
            reply_to_platform_id=thread_ts if thread_ts and thread_ts != ts else None,
            attachments=attachments,
            raw_payload=event,
        )

    # -----------------------------------------------------------------------
    # Outbound (skcomms → platform)
    # -----------------------------------------------------------------------

    async def send(self, message: ChannelMessage) -> str:
        """
        Deliver a :class:`ChannelMessage` to Slack via ``chat.postMessage``.

        Returns the Slack ``ts`` (timestamp) of the delivered message.

        Raises:
            AdapterSendError: On unrecoverable failure or missing client.
        """
        if self._client is None:
            raise AdapterSendError(
                "SlackAdapter.send() requires a connected client. "
                "Call connect() first."
            )

        channel = message.room_id
        thread_ts: Optional[str] = message.reply_to_platform_id

        try:
            if message.kind in (
                MessageKind.FILE,
                MessageKind.IMAGE,
                MessageKind.VOICE,
            ) and message.attachments and message.attachments[0].data is not None:
                att = message.attachments[0]
                result = await self._client.upload_file(
                    channel,
                    att.data,
                    att.filename,
                    initial_comment=message.text or "",
                )
            else:
                result = await self._client.post_message(
                    channel,
                    message.text,
                    thread_ts=thread_ts,
                )

            if not result.get("ok", False):
                raise AdapterSendError(
                    f"Slack API error: {result.get('error', 'unknown')}"
                )
            return str(result.get("ts", ""))
        except AdapterSendError:
            raise
        except Exception as exc:
            raise AdapterSendError(
                f"Slack send failed for channel {channel}: {exc}"
            ) from exc

    # -----------------------------------------------------------------------
    # Identity mapping
    # -----------------------------------------------------------------------

    async def resolve_fqid(self, platform_id: PlatformIdentity) -> Optional[str]:
        """Return the FQID bound to this Slack user, or None."""
        return self._bindings.get(platform_id.canonical_key)

    async def bind_fqid(
        self,
        platform_id: PlatformIdentity,
        fqid: str,
        trust_level: str,
    ) -> None:
        """
        Persist a verified FQID ↔ Slack-user binding.

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
        Stub presence setter — Slack typing indicator is channel-scoped.

        TODO: Implement via ``conversations.setTyping`` (Socket Mode) or a
              visible ``chat.postEphemeral`` typing message as a workaround.
        """
        logger.debug("slack set_presence stub: agent=%s status=%s", agent_fqid, status)

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _build_slack_client(self) -> Optional[SlackClientProtocol]:
        """
        Attempt to construct a real Slack client from config.

        Returns None if ``slack_sdk`` is not installed or config is incomplete.
        Production wiring point: replace this stub with the real
        ``slack_sdk.SocketModeClient`` + ``slack_sdk.WebClient`` wrapper.
        """
        if not self._bot_token:
            return None
        try:
            # Real wiring (production) — guarded by try/import so tests never
            # need slack_sdk installed.
            # from slack_sdk import WebClient
            # from slack_sdk.socket_mode.aiohttp import SocketModeClient
            # ...
            logger.warning(
                "SlackAdapter: real slack_sdk client not yet wired. "
                "Pass slack_client= for now, or install slack_sdk and complete "
                "_build_slack_client()."
            )
            return None
        except ImportError:
            logger.warning("slack_sdk not installed — pass slack_client= explicitly")
            return None

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
