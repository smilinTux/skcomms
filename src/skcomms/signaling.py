"""WebRTC signaling broker for SKComms.

Implements a WebSocket-based SDP/ICE relay broker compatible with the
weblink signaling protocol. All connections are authenticated via CapAuth
PGP bearer tokens. Room IDs are derived from CapAuth PGP fingerprints:

    room = "skcomms-" + fingerprint[:16]

Signal wire protocol (relay only — no media ever passes through):

    Client → Server:  WS connect to /webrtc/ws?room=<room>&peer=<fingerprint>
    Server → Client:  {"type": "welcome",    "peers": ["<fp>", ...]}
    Client → Server:  {"type": "signal",     "to": "<fp>", "data": {"sdp": ...}}
    Server → Client:  {"type": "signal",     "from": "<fp>", "data": {...}}
    Server → Client:  {"type": "peer_joined","peer": "<fp>"}
    Server → Client:  {"type": "peer_left",  "peer": "<fp>"}
    Server → Client:  {"type": "cancel_ice", "peer": "<fp>"}  -- ICE cancelled (peer disconnected mid-negotiation)

Security:
    The broker validates that the authenticated fingerprint (from the
    CapAuth token) matches the ``peer`` query param. This prevents an
    authenticated agent from impersonating another by using a different
    fingerprint in the URL.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

from .capauth_validator import CapAuthValidator

if TYPE_CHECKING:
    from fastapi import WebSocket

logger = logging.getLogger("skcomms.signaling")

# Rate limiting defaults
MAX_MESSAGES_PER_MINUTE = 60  # Per-peer message rate limit
MAX_PEERS_PER_ROOM = 50  # Maximum concurrent connections per room
RATE_WINDOW_SECONDS = 60.0  # Sliding window for rate counting


class WebRTCRoom:
    """Manages connected peers in a single WebRTC signaling room.

    A room is a named namespace where peers exchange SDP offers/answers
    and ICE candidates. The broker relays messages between peers without
    inspecting or modifying the cryptographic content.

    Args:
        room_id: Unique room identifier (e.g. ``skcomms-CCBE9306410CF8CD``).
    """

    def __init__(self, room_id: str) -> None:
        self.room_id = room_id
        self._peers: dict[str, "WebSocket"] = {}
        # Per-peer rate limiting: fingerprint -> list of message timestamps
        self._message_timestamps: dict[str, list[float]] = defaultdict(list)
        # Active ICE negotiations: fingerprint -> set of partner fingerprints
        # Used to send cancel_ice when a peer disconnects mid-negotiation.
        self._ice_sessions: dict[str, set[str]] = defaultdict(set)

    @property
    def peer_ids(self) -> list[str]:
        """List of currently connected peer fingerprints."""
        return list(self._peers.keys())

    @property
    def peer_count(self) -> int:
        """Number of currently connected peers."""
        return len(self._peers)

    @property
    def is_empty(self) -> bool:
        """True if no peers are currently connected."""
        return len(self._peers) == 0

    @property
    def is_full(self) -> bool:
        """True if the room has reached the maximum number of peers."""
        return len(self._peers) >= MAX_PEERS_PER_ROOM

    def is_rate_limited(self, fingerprint: str) -> bool:
        """Check if a peer has exceeded the per-minute message rate limit.

        Prunes timestamps older than the rate window before checking.

        Args:
            fingerprint: PGP fingerprint of the peer to check.

        Returns:
            True if the peer should be rate-limited.
        """
        now = time.monotonic()
        cutoff = now - RATE_WINDOW_SECONDS
        timestamps = self._message_timestamps[fingerprint]
        # Prune old timestamps outside the window
        self._message_timestamps[fingerprint] = [ts for ts in timestamps if ts > cutoff]
        return len(self._message_timestamps[fingerprint]) >= MAX_MESSAGES_PER_MINUTE

    def record_message(self, fingerprint: str) -> None:
        """Record a message timestamp for rate-limiting purposes.

        Args:
            fingerprint: PGP fingerprint of the sending peer.
        """
        self._message_timestamps[fingerprint].append(time.monotonic())

    async def add_peer(self, fingerprint: str, ws: "WebSocket") -> None:
        """Register a new peer and notify existing peers.

        Sends a ``welcome`` message with the list of existing peer IDs,
        then broadcasts ``peer_joined`` to all other connected peers.

        Args:
            fingerprint: PGP fingerprint of the joining peer.
            ws: The peer's accepted WebSocket connection.
        """
        existing = [p for p in self._peers if p != fingerprint]
        self._peers[fingerprint] = ws

        # Notify existing peers about the new arrival
        await self._notify_others(
            sender=fingerprint,
            message={"type": "peer_joined", "peer": fingerprint},
        )

        # Send welcome with the list of peers that were already here
        await self._send(ws, {"type": "welcome", "peers": existing})

        logger.info(
            "Peer %s joined room %s (%d total)",
            fingerprint[:8],
            self.room_id,
            len(self._peers),
        )

    async def remove_peer(self, fingerprint: str) -> None:
        """Deregister a peer and notify remaining peers.

        Sends ``cancel_ice`` to any peers that were mid-negotiation with
        this peer, then removes the peer and broadcasts ``peer_left``.

        Args:
            fingerprint: PGP fingerprint of the leaving peer.
        """
        # Cancel active ICE sessions before removing (partners still in _peers)
        await self._cancel_ice_sessions(fingerprint)
        self._peers.pop(fingerprint, None)
        self._message_timestamps.pop(fingerprint, None)
        await self._notify_others(
            sender=fingerprint,
            message={"type": "peer_left", "peer": fingerprint},
        )
        logger.info(
            "Peer %s left room %s (%d remain)",
            fingerprint[:8],
            self.room_id,
            len(self._peers),
        )

    async def _cancel_ice_sessions(self, fingerprint: str) -> None:
        """Send ``cancel_ice`` to all peers that were in an active ICE
        negotiation with ``fingerprint`` and clean up session state.

        Called during peer removal so that partners can abort their
        RTCPeerConnection before receiving the generic ``peer_left``.

        Args:
            fingerprint: PGP fingerprint of the departing peer.
        """
        partners = self._ice_sessions.pop(fingerprint, set())
        for partner_fp in partners:
            # Remove the reverse reference to avoid stale state
            self._ice_sessions.get(partner_fp, set()).discard(fingerprint)
            partner_ws = self._peers.get(partner_fp)
            if partner_ws is None:
                continue
            try:
                await self._send(partner_ws, {"type": "cancel_ice", "peer": fingerprint})
            except Exception as exc:
                logger.debug("Failed to send cancel_ice to %s: %s", partner_fp[:8], exc)
        if partners:
            logger.info(
                "Cancelled %d ICE session(s) for departing peer %s",
                len(partners),
                fingerprint[:8],
            )

    async def relay(self, sender: str, to: str, data: dict) -> bool:
        """Relay a signal message from one peer to another.

        The sender fingerprint in the relayed message is always the
        authenticated sender, not whatever ``from`` the client claimed.
        This prevents spoofing within an authenticated session.

        Args:
            sender: Authenticated fingerprint of the sending peer.
            to: Fingerprint of the intended recipient peer.
            data: SDP offer/answer or ICE candidate payload to relay.

        Returns:
            True if the message was relayed, False if target not in room.
        """
        target_ws = self._peers.get(to)
        if target_ws is None:
            logger.debug(
                "Relay target %s not in room %s (sender=%s)",
                to[:8] if len(to) >= 8 else to,
                self.room_id,
                sender[:8],
            )
            return False

        # Track ICE negotiation sessions so we can send cancel_ice on disconnect.
        # ICE candidate messages contain a "candidate" key in the data dict.
        if isinstance(data, dict) and "candidate" in data:
            self._ice_sessions[sender].add(to)
            self._ice_sessions[to].add(sender)

        message = {"type": "signal", "from": sender, "data": data}
        try:
            await self._send(target_ws, message)
        except Exception as exc:
            logger.warning("Relay to %s failed: %s", to[:8], exc)
            return False
        return True

    async def _notify_others(self, sender: str, message: dict) -> None:
        """Broadcast a message to all peers except the sender.

        Args:
            sender: Fingerprint to exclude from notification.
            message: Message payload to broadcast.
        """
        for fp, ws in list(self._peers.items()):
            if fp != sender:
                try:
                    await self._send(ws, message)
                except Exception as exc:
                    logger.debug("Failed to notify peer %s: %s", fp[:8], exc)

    @staticmethod
    async def _send(ws: "WebSocket", message: dict) -> None:
        """Send a JSON-serialised message over a WebSocket.

        Args:
            ws: Target WebSocket connection.
            message: Dict payload to serialize and send.
        """
        await ws.send_text(json.dumps(message))


class SignalingBroker:
    """Manages all WebRTC signaling rooms and peer authentication.

    The broker is the single source of truth for all active signaling
    sessions. It validates CapAuth tokens on WebSocket upgrade, routes
    signal messages between peers, and auto-cleans empty rooms.

    Args:
        validator: CapAuthValidator instance. Defaults to a strict validator
            (require_auth=True). SECURITY (fail-closed): the broker used to
            default to a permissive validator; anyone constructing a broker
            without arguments got unauthenticated signaling. Pass
            ``require_auth=False`` explicitly for development setups.
        capauth_url: If provided, creates a remote-validating CapAuthValidator.
        require_auth: Passed to the default CapAuthValidator if ``validator``
            is not provided. Defaults to True.
    """

    def __init__(
        self,
        validator: Optional[CapAuthValidator] = None,
        capauth_url: Optional[str] = None,
        require_auth: bool = True,
    ) -> None:
        self._rooms: dict[str, WebRTCRoom] = {}
        self._validator = validator or CapAuthValidator(
            capauth_url=capauth_url,
            require_auth=require_auth,
        )

    def get_or_create_room(self, room_id: str) -> WebRTCRoom:
        """Get an existing room or create a new one.

        Args:
            room_id: Room identifier string.

        Returns:
            WebRTCRoom instance (newly created or existing).
        """
        if room_id not in self._rooms:
            self._rooms[room_id] = WebRTCRoom(room_id)
            logger.info("Created signaling room '%s'", room_id)
        return self._rooms[room_id]

    def cleanup_room(self, room_id: str) -> None:
        """Remove a room if it has no connected peers.

        Args:
            room_id: Room to potentially clean up.
        """
        room = self._rooms.get(room_id)
        if room and room.is_empty:
            del self._rooms[room_id]
            logger.info("Destroyed empty room '%s'", room_id)

    def active_rooms(self) -> dict[str, list[str]]:
        """Return a snapshot of all active rooms and their peer lists.

        Returns:
            Mapping of room_id → list of connected peer fingerprints.
        """
        return {rid: list(room.peer_ids) for rid, room in self._rooms.items()}

    def authenticate(self, authorization: Optional[str]) -> Optional[str]:
        """Extract and validate a CapAuth bearer token from a header.

        Args:
            authorization: Raw ``Authorization`` header value
                (e.g. ``"Bearer CCBE9306..."``) or None.

        Returns:
            PGP fingerprint string if valid, None otherwise.
        """
        token: Optional[str] = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        return self._validator.validate(token)

    async def handle_connection(
        self,
        ws: "WebSocket",
        room_id: str,
        peer_id: str,
    ) -> None:
        """Handle the full lifecycle of a signaling WebSocket connection.

        Joins the peer to the room, receives signal messages and relays
        them, and cleans up on disconnect. The peer_id has already been
        authenticated by the route handler before this is called.

        Enforces:
            - Max peers per room (MAX_PEERS_PER_ROOM). Connection is
              rejected with WS close code 4429 if the room is full.
            - Per-peer message rate limit (MAX_MESSAGES_PER_MINUTE).
              Excess messages are dropped with a warning sent to the peer.

        Args:
            ws: The accepted WebSocket connection.
            room_id: Room to join (e.g. ``"skcomms-CCBE9306410CF8CD"``).
            peer_id: Authenticated PGP fingerprint of this peer.
        """
        room = self.get_or_create_room(room_id)

        # Enforce max connections per room
        if room.is_full:
            logger.warning(
                "Room %s full (%d/%d peers) — rejecting peer %s",
                room_id,
                room.peer_count,
                MAX_PEERS_PER_ROOM,
                peer_id[:8],
            )
            await ws.close(
                code=4429,
                reason=f"Room full ({MAX_PEERS_PER_ROOM} peers max)",
            )
            return

        await room.add_peer(peer_id, ws)

        try:
            while True:
                text = await ws.receive_text()
                try:
                    msg = json.loads(text)
                except json.JSONDecodeError:
                    logger.warning("Malformed JSON signal from peer %s", peer_id[:8])
                    continue

                # Enforce per-peer rate limit
                if room.is_rate_limited(peer_id):
                    logger.warning(
                        "Rate limit exceeded for peer %s in room %s "
                        "(%d msgs/min max) — dropping message",
                        peer_id[:8],
                        room_id,
                        MAX_MESSAGES_PER_MINUTE,
                    )
                    try:
                        await ws.send_text(
                            json.dumps(
                                {
                                    "type": "error",
                                    "code": "RATE_LIMITED",
                                    "message": (
                                        f"Rate limit exceeded: max {MAX_MESSAGES_PER_MINUTE} "
                                        f"messages per {int(RATE_WINDOW_SECONDS)}s"
                                    ),
                                }
                            )
                        )
                    except Exception as e:
                        logger.warning("signaling.py: %s", e)
                        pass
                    continue

                room.record_message(peer_id)
                msg_type = msg.get("type")

                if msg_type == "signal":
                    to = msg.get("to", "")
                    data = msg.get("data", {})
                    # The relay always uses the authenticated peer_id as sender
                    # (anti-spoofing: client cannot forge a different "from")
                    await room.relay(sender=peer_id, to=to, data=data)
                else:
                    logger.debug("Unhandled signal type '%s' from %s", msg_type, peer_id[:8])

        except Exception as exc:
            # Normal on disconnect (WebSocketDisconnect, CancelledError, etc.)
            logger.info("Peer %s disconnected from room %s: %s", peer_id[:8], room_id, exc)
        finally:
            await room.remove_peer(peer_id)
            self.cleanup_room(room_id)


async def signaling_ws_endpoint(
    ws: "WebSocket",
    room: str,
    peer: str,
    broker: SignalingBroker,
) -> None:
    """FastAPI WebSocket endpoint handler for WebRTC signaling.

    Authenticates the connection using the Authorization header, then
    delegates to the broker for full session management.

    Authentication failure closes the WebSocket with code 4401 after
    accepting (WebSocket protocol requires accept before close).

    Args:
        ws: Incoming WebSocket connection (not yet accepted).
        room: Room ID from the ``?room=`` query parameter.
        peer: Claimed peer fingerprint from the ``?peer=`` query parameter.
        broker: The global SignalingBroker instance.
    """
    auth_header = ws.headers.get("authorization")
    auth_fp = broker.authenticate(auth_header)

    await ws.accept()

    if auth_fp is None:
        await ws.close(code=4401, reason="Unauthorized: invalid or missing CapAuth token")
        logger.warning("Rejected unauthenticated WebRTC signaling connection")
        return

    # Use the authenticated fingerprint, not the client-claimed peer param
    # (prevents identity spoofing via URL manipulation)
    authenticated_peer = auth_fp if auth_fp != "anonymous" else peer

    await broker.handle_connection(ws=ws, room_id=room, peer_id=authenticated_peer)
