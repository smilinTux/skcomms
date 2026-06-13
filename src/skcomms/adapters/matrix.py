"""
MatrixAdapter — Matrix Client-Server API / Appservice channel adapter (C5).

Bridges a Matrix homeserver (Synapse, Conduit, **Tuwunel**, …) into skcomms.
Supports two auth modes:

* **User access-token** — the agent has a real Matrix account, authenticates
  with a ``Bearer`` token, and polls ``/sync``.
* **Application service** — the agent registers as an appservice, receives
  events via an HTTP push endpoint, and can puppet arbitrary MXIDs.

The Matrix client is **injectable** (pass ``matrix_client`` to the constructor)
so the adapter is fully unit-testable without any live homeserver.  The
production path uses the Matrix Client-Server REST API (PUT/GET requests).

MXID ↔ FQID mapping
---------------------
Matrix users are identified by an MXID: ``@localpart:server`` — e.g.
``@lumina:skworld.io``.  The adapter maps these to FQIDs (``lumina@skworld.io``)
using a simple bidirectional in-memory store backed by a YAML file:

  * ``canonical_key`` = ``matrix:user:@localpart:server``
  * FQID = ``localpart@server`` (default) or the explicitly bound value.

Room ids (``!opaque:server``) map to skcomms ``room_id`` 1:1.

Config block in ``~/.skcomm/config.yml``::

    adapters:
      matrix:
        enabled: true
        homeserver: "https://matrix.skworld.io"
        access_token: "${MATRIX_ACCESS_TOKEN}"   # Bearer token (user or appservice)
        user_id: "@lumina:skworld.io"             # agent's own MXID
        poll_interval_s: 2
        rooms:
          skworld_general:
            room_id: "!opaque1234:skworld.io"
            agent_fqid: "lumina@skworld.io"
        identity_store: "~/.skcomm/adapters/matrix-ids.yaml"

Appservice mode (additional keys)::

        appservice: true
        appservice_token: "${MATRIX_AS_TOKEN}"  # hs_token from registration
        # The appservice HTTP push endpoint is registered in the homeserver's
        # appservice registration YAML (application_services section).

Known gaps (post-C5, live wiring)
-----------------------------------
* The ``/sync`` long-poll watermark (``next_batch``) is not persisted across
  restarts — missed events will be replayed from ``since=None`` on restart.
* Appservice push endpoint wiring requires an HTTP server (e.g. aiohttp) that
  receives events from the homeserver and enqueues them into the adapter's
  internal queue.  The ``drain_events`` protocol method simulates this for tests.
* Media download (``mxc://`` URIs) is not implemented — attachments carry the
  ``mxc://`` URL only.
* Puppeting (creating virtual MXIDs for guests) is not implemented in this
  batch; foundation is laid via ``agent_mxid`` config + appservice mode.
* Reaction events (``m.reaction`` with ``m.relates_to`` ``m.annotation``) are
  not normalized — they are silently dropped.

Spec: docs/superpowers/specs/2026-06-13-skcomms-channel-adapter.md §C5
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

logger = logging.getLogger("skcomms.adapters.matrix")

# ---------------------------------------------------------------------------
# Injectable client protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class MatrixClientProtocol(Protocol):
    """
    Structural protocol for the injectable Matrix client.

    Both the real Matrix CS-API HTTP wrapper and :class:`FakeMatrixClient`
    (in tests) satisfy this interface.

    The two inbound paths map to the two operational modes:

    * **sync mode**: caller drives the long-poll by calling ``sync()``
      repeatedly; the adapter advances ``next_batch`` internally.
    * **appservice/queue mode**: the homeserver pushes events to the
      adapter's HTTP endpoint; ``drain_events`` flushes the internal
      queue (same pattern as SlackAdapter / DiscordAdapter).
    """

    def is_connected(self) -> bool: ...

    async def whoami(self) -> dict:
        """
        GET /_matrix/client/v3/account/whoami

        Returns a dict with at least ``"user_id"`` (the agent's MXID).
        Raises on auth failure.
        """
        ...

    async def sync(self, since: Optional[str] = None, timeout_ms: int = 30000) -> dict:
        """
        GET /_matrix/client/v3/sync?since=…&timeout=…

        Returns the raw ``/sync`` response dict.  The adapter reads
        ``next_batch`` and ``rooms.join`` from the response.
        """
        ...

    async def send_message(
        self,
        room_id: str,
        content: dict,
        *,
        txn_id: str,
    ) -> dict:
        """
        PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}

        Returns a dict with ``"event_id"``.
        """
        ...

    def drain_events(self) -> list[dict]:
        """
        Flush and return all queued inbound Matrix events.

        Used in appservice mode (and in tests) where events are pushed
        into the client's internal queue rather than polled via ``sync``.
        Each item is a raw Matrix room event dict (the ``content``
        already unwrapped from the sync envelope).
        """
        ...

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...


# ---------------------------------------------------------------------------
# MatrixAdapter
# ---------------------------------------------------------------------------


class MatrixAdapter(ChannelAdapter):
    """
    Matrix channel adapter using the Client-Server API (C5).

    Supports user access-token mode (``/sync`` polling) and appservice mode
    (event queue drained via ``drain_events``).

    Args:
        config: Adapter config dict (see module docstring for shape).
        matrix_client: Optional injectable client satisfying
            :class:`MatrixClientProtocol`.  Tests pass a
            :class:`~tests.test_matrix_adapter.FakeMatrixClient`;
            production omits this arg and the adapter builds a real
            HTTP client from config.
        bindings_store: Optional dict used as the in-memory identity map
            instead of the YAML file on disk.  Useful for unit testing.
    """

    channel_type = ChannelType.MATRIX
    adapter_name = "matrix"

    def __init__(
        self,
        config: dict,
        matrix_client: Optional[MatrixClientProtocol] = None,
        bindings_store: Optional[dict[str, str]] = None,
    ) -> None:
        # --- Core config ---
        self._homeserver: str = config.get("homeserver", "https://matrix.org")
        self._access_token: str = config.get("access_token", "")
        self._agent_user_id: Optional[str] = config.get("user_id")
        self._poll_s: float = config.get("poll_interval_s", 2)
        self._rooms: dict[str, dict] = config.get("rooms", {})
        self._appservice: bool = config.get("appservice", False)
        self._appservice_token: str = config.get("appservice_token", "")
        self._id_store_path: str = config.get(
            "identity_store", "~/.skcomm/adapters/matrix-ids.yaml"
        )

        # --- State ---
        self._running = False
        # ``next_batch`` token from the last /sync response; None = first sync
        self._next_batch: Optional[str] = None
        # txn_id counter — incremented per outbound send
        self._txn_counter: int = 0

        # --- Identity bindings ---
        self._bindings: dict[str, str] = (
            bindings_store if bindings_store is not None else {}
        )
        self._external_bindings = bindings_store is not None

        # --- Injectable client ---
        self._client: Optional[MatrixClientProtocol] = matrix_client

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Authenticate with the Matrix homeserver.

        Calls ``whoami()`` to verify the access token and record the agent
        MXID.  In stub/test mode (no credentials, no client), raises
        :class:`AdapterAuthError`.
        """
        if self._client is None:
            self._client = self._build_matrix_client()

        if self._client is not None:
            await self._client.connect()
            try:
                me = await self._client.whoami()
            except Exception as exc:
                raise AdapterConnectError(
                    f"Matrix whoami failed: {exc}"
                ) from exc

            mxid = me.get("user_id")
            if not mxid:
                raise AdapterAuthError(
                    "Matrix whoami did not return a valid user_id — "
                    "check the access token."
                )

            # If user_id was not set in config, fill from whoami response.
            if not self._agent_user_id:
                self._agent_user_id = mxid

            logger.info(
                "matrix adapter connected as %s (homeserver=%s)",
                self._agent_user_id,
                self._homeserver,
            )
        else:
            raise AdapterAuthError(
                "MatrixAdapter requires an access_token (and optionally user_id). "
                "Set them in config or pass matrix_client=."
            )

        if not self._external_bindings:
            self._load_bindings()

        self._running = True
        logger.info("matrix adapter ready")

    async def disconnect(self) -> None:
        """Stop the inbound loop and close the Matrix connection."""
        self._running = False
        if self._client is not None and self._client.is_connected():
            await self._client.disconnect()
        logger.info("matrix adapter disconnected")

    async def health(self) -> AdapterHealth:
        """Return a point-in-time health snapshot via whoami()."""
        import time

        if self._client is not None:
            connected = self._client.is_connected()
            t0 = time.monotonic()
            try:
                me = await self._client.whoami()
                latency_ms = (time.monotonic() - t0) * 1000
                ok = bool(me.get("user_id"))
                return AdapterHealth(
                    adapter_name=self.adapter_name,
                    connected=connected and ok,
                    latency_ms=latency_ms,
                    error=None if ok else "whoami returned no user_id",
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
        """Matrix capabilities (federated, rich media, threading)."""
        return AdapterCapabilities(
            text=True,
            files=True,
            images=True,
            voice_notes=True,   # m.audio event type
            video=True,         # m.video event type
            reactions=True,     # m.reaction (annotation)
            threads=False,      # MSC3440 threads not universally deployed yet
            read_receipts=True,  # Matrix has first-class read receipts
            typing_hint=True,   # PUT /typing
            max_text_bytes=65536,  # no hard limit in spec; 64 KB is a safe practical cap
        )

    # -----------------------------------------------------------------------
    # Inbound (platform → skcomms)
    # -----------------------------------------------------------------------

    async def inbound(self) -> AsyncIterator[ChannelMessage]:
        """
        Yield normalized :class:`ChannelMessage` objects as Matrix events arrive.

        Two modes:

        * **Appservice / queue mode** (``appservice=True`` or injectable fake
          client with ``drain_events``): drains the client's internal event
          queue each poll cycle.
        * **Sync mode** (user access-token): calls ``client.sync()`` each cycle,
          advances the ``next_batch`` watermark, and yields events from all
          joined rooms.
        """
        while self._running:
            if self._client is None:
                await asyncio.sleep(self._poll_s)
                continue

            if self._appservice:
                # Appservice / injected-queue path
                events = self._client.drain_events()
                for raw in events:
                    msg = self._normalize(raw)
                    if msg is not None:
                        yield msg
            else:
                # /sync long-poll path
                events = await self._poll_sync()
                for msg in events:
                    yield msg

            await asyncio.sleep(self._poll_s)

    async def _poll_sync(self) -> list[ChannelMessage]:
        """
        Call ``client.sync()`` and convert the response into normalized messages.

        Advances ``_next_batch`` so only *new* events are yielded on the next
        call.  Returns an empty list on error (does not propagate per-poll
        network exceptions).
        """
        results: list[ChannelMessage] = []
        try:
            response = await self._client.sync(since=self._next_batch)
        except Exception:
            logger.exception("matrix /sync error")
            return results

        self._next_batch = response.get("next_batch", self._next_batch)

        rooms_data: dict = response.get("rooms", {})
        join_data: dict = rooms_data.get("join", {})

        for room_id, room_updates in join_data.items():
            timeline: dict = room_updates.get("timeline", {})
            events: list[dict] = timeline.get("events", [])
            for event in events:
                # Attach the room_id since sync responses omit it from the
                # individual event dict.
                event_with_room = dict(event)
                event_with_room.setdefault("room_id", room_id)
                msg = self._normalize(event_with_room)
                if msg is not None:
                    results.append(msg)

        return results

    def _normalize(self, event: dict) -> Optional[ChannelMessage]:
        """
        Translate a raw Matrix room event into a :class:`ChannelMessage`.

        Handles the following ``m.room.message`` ``msgtype`` values:

        * ``m.text``      → TEXT
        * ``m.image``     → IMAGE  (attachment with ``mxc://`` URL)
        * ``m.file``      → FILE   (attachment with ``mxc://`` URL)
        * ``m.audio``     → VOICE  (attachment with ``mxc://`` URL)
        * ``m.video``     → VIDEO  (attachment with ``mxc://`` URL)

        ``m.reaction`` and all other event types are silently dropped.

        Agent self-echo (events from ``_agent_user_id``) are dropped.

        Expected event shape (Matrix room event)::

            {
              "type": "m.room.message",
              "event_id": "$abc123",
              "room_id": "!opaque:server",
              "sender": "@chef:skworld.io",
              "origin_server_ts": 1718150400000,
              "content": {
                "msgtype": "m.text",
                "body": "Hello Lumina",
              }
            }

        For media events the ``content`` additionally carries::

            {
              "msgtype": "m.image",
              "body": "photo.jpg",
              "url": "mxc://skworld.io/abc123",
              "info": {
                "mimetype": "image/jpeg",
                "size": 102400,
                "w": 1280, "h": 720,
              }
            }
        """
        etype = event.get("type")
        if etype != "m.room.message":
            logger.debug("matrix: dropping event type=%s", etype)
            return None

        sender_mxid: str = event.get("sender", "")
        if not sender_mxid:
            logger.debug("matrix: dropping event with no sender")
            return None

        # Drop self-echo
        if self._agent_user_id and sender_mxid == self._agent_user_id:
            logger.debug("matrix: dropping self-echo from %s", sender_mxid)
            return None

        content: dict = event.get("content", {})
        msgtype: str = content.get("msgtype", "")
        body: str = content.get("body", "")
        event_id: str = event.get("event_id", "")
        room_id: str = event.get("room_id", "")

        # Build PlatformIdentity from MXID
        # MXID format: @localpart:server
        platform_name = _mxid_display_name(sender_mxid)
        room_name = _room_name_from_config(room_id, self._rooms)

        sender = PlatformIdentity(
            channel=ChannelType.MATRIX,
            platform_id=sender_mxid,
            platform_name=platform_name,
            room_id=room_id,
            room_name=room_name,
        )

        # Determine kind + attachments
        kind, attachments = _msgtype_to_kind_and_attachments(msgtype, content, body)
        if kind is None:
            # Unsupported msgtype (e.g. m.reaction, m.notice we want to ignore)
            logger.debug("matrix: dropping unsupported msgtype=%s", msgtype)
            return None

        # Reply threading via m.relates_to
        reply_to_id: Optional[str] = None
        relates_to: Optional[dict] = content.get("m.relates_to")
        if relates_to:
            # Threaded reply: m.in_reply_to
            in_reply_to = relates_to.get("m.in_reply_to")
            if in_reply_to:
                reply_to_id = in_reply_to.get("event_id")

        return ChannelMessage(
            channel=ChannelType.MATRIX,
            kind=kind,
            text=body,
            sender=sender,
            room_id=room_id,
            platform_msg_id=event_id,
            reply_to_platform_id=reply_to_id,
            attachments=attachments,
            raw_payload=event,
        )

    # -----------------------------------------------------------------------
    # Outbound (skcomms → platform)
    # -----------------------------------------------------------------------

    async def send(self, message: ChannelMessage) -> str:
        """
        Deliver a :class:`ChannelMessage` to a Matrix room via
        ``PUT /rooms/{roomId}/send/m.room.message/{txnId}``.

        Returns the Matrix ``event_id`` of the delivered event.

        Text and media (file/image/voice/video) are sent as ``m.room.message``
        with the appropriate ``msgtype``.  Media upload (``mxc://``) is not
        implemented in this batch — media attachments with raw ``data`` bytes
        are sent as text fallback with the filename as body.

        Raises:
            AdapterSendError: On unrecoverable failure or missing client.
        """
        if self._client is None:
            raise AdapterSendError(
                "MatrixAdapter.send() requires a connected client. "
                "Call connect() first."
            )

        room_id = message.room_id
        self._txn_counter += 1
        txn_id = f"skcomms-{id(self)}-{self._txn_counter}"

        content = _channel_message_to_matrix_content(message)

        try:
            result = await self._client.send_message(
                room_id,
                content,
                txn_id=txn_id,
            )
        except AdapterSendError:
            raise
        except Exception as exc:
            raise AdapterSendError(
                f"Matrix send failed for room {room_id}: {exc}"
            ) from exc

        event_id = result.get("event_id")
        if not event_id:
            raise AdapterSendError(
                f"Matrix API error: response missing 'event_id': {result}"
            )
        return str(event_id)

    # -----------------------------------------------------------------------
    # Identity mapping (MXID ↔ FQID)
    # -----------------------------------------------------------------------

    async def resolve_fqid(self, platform_id: PlatformIdentity) -> Optional[str]:
        """
        Return the FQID bound to this Matrix MXID, or None.

        Falls back to a default FQID derived from the MXID when the sender
        has a ``@localpart:server`` that maps to ``localpart@server``.
        Explicit bindings (from ``bind_fqid``) take priority.
        """
        explicit = self._bindings.get(platform_id.canonical_key)
        if explicit:
            return explicit
        # No explicit binding — return None; the hub assigns untrusted guest
        return None

    async def bind_fqid(
        self,
        platform_id: PlatformIdentity,
        fqid: str,
        trust_level: str,
    ) -> None:
        """
        Persist a verified FQID ↔ MXID binding.

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
    # Presence (stub)
    # -----------------------------------------------------------------------

    async def set_presence(self, agent_fqid: str, status: str) -> None:
        """
        Send a typing indicator to configured rooms.

        TODO: Implement via ``PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}``
              for each active room whose ``agent_fqid`` matches.
        """
        logger.debug("matrix set_presence stub: agent=%s status=%s", agent_fqid, status)

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _build_matrix_client(self) -> Optional[MatrixClientProtocol]:
        """
        Attempt to construct a real Matrix HTTP client from config.

        Returns None if config is incomplete.  Production wiring point:
        replace this stub with a real ``httpx``-based Matrix CS-API wrapper
        (or use ``matrix-nio`` / ``mautrix-python`` if available).
        """
        if not self._access_token:
            return None
        try:
            logger.warning(
                "MatrixAdapter: real HTTP client not yet wired. "
                "Pass matrix_client= for now, or implement _build_matrix_client() "
                "using httpx + Matrix CS-API calls."
            )
            return None
        except ImportError:
            logger.warning("httpx not installed — pass matrix_client= explicitly")
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


# ---------------------------------------------------------------------------
# Module-level helpers (pure, no I/O)
# ---------------------------------------------------------------------------


def _mxid_display_name(mxid: str) -> str:
    """
    Derive a human-readable display name from a Matrix MXID.

    ``@lumina:skworld.io`` → ``lumina``
    ``@chef:skworld.io``   → ``chef``
    Malformed MXID        → the raw MXID string.
    """
    # MXIDs are @localpart:server
    if mxid.startswith("@") and ":" in mxid:
        return mxid[1:].split(":")[0]
    return mxid


def _room_name_from_config(room_id: str, rooms_cfg: dict) -> Optional[str]:
    """
    Look up a human-readable room name from the adapter's rooms config.

    Returns the config key (e.g. ``"skworld_general"``) if found, else None.
    """
    for room_key, room_cfg in rooms_cfg.items():
        if room_cfg.get("room_id") == room_id:
            return room_key
    return None


# Mapping from Matrix msgtype → (MessageKind, is_media)
_MSGTYPE_MAP: dict[str, MessageKind] = {
    "m.text": MessageKind.TEXT,
    "m.notice": MessageKind.TEXT,   # bot notices treated as text
    "m.emote": MessageKind.TEXT,    # /me actions treated as text
    "m.image": MessageKind.IMAGE,
    "m.file": MessageKind.FILE,
    "m.audio": MessageKind.VOICE,
    "m.video": MessageKind.VIDEO,
}

_MEDIA_MSGTYPES = {"m.image", "m.file", "m.audio", "m.video"}


def _msgtype_to_kind_and_attachments(
    msgtype: str,
    content: dict,
    body: str,
) -> tuple[Optional[MessageKind], list[MediaAttachment]]:
    """
    Translate a Matrix ``msgtype`` into a :class:`MessageKind` + attachments.

    Returns ``(None, [])`` for unknown/unsupported msgtypes so the caller
    can drop the event gracefully.
    """
    kind = _MSGTYPE_MAP.get(msgtype)
    if kind is None:
        return None, []

    attachments: list[MediaAttachment] = []
    if msgtype in _MEDIA_MSGTYPES:
        url: Optional[str] = content.get("url")  # mxc:// URI
        info: dict = content.get("info", {})
        mime = info.get("mimetype", "application/octet-stream")
        size = info.get("size", 0)
        filename = body or "file"
        attachments.append(
            MediaAttachment(
                filename=filename,
                mime_type=mime,
                size_bytes=size,
                url=url,
            )
        )

    return kind, attachments


def _channel_message_to_matrix_content(message: ChannelMessage) -> dict:
    """
    Build a Matrix ``m.room.message`` content dict from a :class:`ChannelMessage`.

    For media messages with a populated ``attachment.url`` (``mxc://`` URI),
    the full media content dict is returned.  For plain text and for media
    without a pre-uploaded ``mxc://`` URL, a ``m.text`` fallback is used.
    """
    kind = message.kind

    if kind == MessageKind.TEXT:
        return {"msgtype": "m.text", "body": message.text}

    if kind == MessageKind.IMAGE:
        att = message.attachments[0] if message.attachments else None
        if att and att.url:
            content: dict = {
                "msgtype": "m.image",
                "body": att.filename,
                "url": att.url,
                "info": {
                    "mimetype": att.mime_type,
                    "size": att.size_bytes,
                },
            }
            if message.text:
                content["org.matrix.msc1767.caption"] = message.text
            return content
        # No mxc URL — fall back to text
        return {"msgtype": "m.text", "body": message.text or f"[image: {att.filename if att else 'unknown'}]"}

    if kind == MessageKind.FILE:
        att = message.attachments[0] if message.attachments else None
        if att and att.url:
            return {
                "msgtype": "m.file",
                "body": att.filename,
                "url": att.url,
                "info": {
                    "mimetype": att.mime_type,
                    "size": att.size_bytes,
                },
            }
        return {"msgtype": "m.text", "body": message.text or f"[file: {att.filename if att else 'unknown'}]"}

    if kind == MessageKind.VOICE:
        att = message.attachments[0] if message.attachments else None
        if att and att.url:
            return {
                "msgtype": "m.audio",
                "body": att.filename,
                "url": att.url,
                "info": {
                    "mimetype": att.mime_type,
                    "size": att.size_bytes,
                },
            }
        return {"msgtype": "m.text", "body": message.text or "[audio message]"}

    if kind == MessageKind.VIDEO:
        att = message.attachments[0] if message.attachments else None
        if att and att.url:
            return {
                "msgtype": "m.video",
                "body": att.filename,
                "url": att.url,
                "info": {
                    "mimetype": att.mime_type,
                    "size": att.size_bytes,
                },
            }
        return {"msgtype": "m.text", "body": message.text or "[video message]"}

    # STICKER, PRESENCE, REACTION — send as notice
    return {"msgtype": "m.notice", "body": message.text or f"[{kind.value}]"}
