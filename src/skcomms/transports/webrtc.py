"""WebRTC transport — real-time P2P messaging via aiortc data channels.

Establishes direct peer-to-peer data channels using WebRTC. A background
asyncio loop (in its own daemon thread) manages peer connections and the
signaling WebSocket connection to the SKComms signaling broker.

Incoming messages are buffered in a thread-safe queue. Outgoing messages
are bridged from the synchronous Transport API into the async loop via
``asyncio.run_coroutine_threadsafe()``.

Send behaviour on first contact with a new peer:
  1. WebRTC offer is initiated via the signaling broker (async, background)
  2. ``send()`` returns ``success=False`` for that envelope → router falls back
  3. ICE negotiation completes in ~1-3s (LAN) or ~5s (WAN via TURN)
  4. Subsequent ``send()`` calls succeed transparently via the data channel

Security:
  SDP offers/answers carry a ``capauth`` wrapper with a PGP signature over
  the SDP text. The DTLS-SRTP fingerprint embedded in the SDP is bound to
  the signature, making MITM impossible even if the signaling relay is
  compromised (see plan sec. "Security by architecture").

Dependencies (optional extra):
    pip install 'skcomms[webrtc]'   →  aiortc>=1.9.0, websockets>=12.0
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ..transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

logger = logging.getLogger("skcomms.transports.webrtc")

DEFAULT_SIGNALING_URL = os.environ.get("SKCOMMS_SIGNALING_URL", "wss://localhost:9384/webrtc/ws")
CHANNEL_NAME = "skcomms"
ICE_GATHER_TIMEOUT = 30.0  # seconds to wait for ICE gathering
RECV_TIMEOUT = 1.0  # seconds for signaling recv poll
SEND_TIMEOUT = 5.0  # seconds for send future.result()
CONNECT_SETTLE = 0.3  # seconds to wait after starting the loop thread


def summarize_ice_candidate(candidate: str):
    """Summarize a single ICE candidate line for debug logging.

    Extracts only non-sensitive, network-level fields useful for
    connection debugging — candidate type (host/srflx/prflx/relay),
    transport protocol, and connection address/port. Session credentials
    such as the ICE ``ufrag`` are deliberately NOT parsed out so they can
    never leak into logs.

    Args:
        candidate: A candidate line with or without the ``candidate:``
            prefix (e.g. from an SDP ``a=candidate:`` attribute or a
            trickle-ICE payload).

    Returns:
        A dict with ``type``/``protocol``/``address``/``port``/``component``
        keys, or None if the line could not be parsed.
    """
    if not candidate:
        return None
    line = candidate.strip()
    if line.startswith("candidate:"):
        line = line[len("candidate:") :]
    parts = line.split()
    # RFC 5245: foundation component transport priority address port typ <type>
    if len(parts) < 8 or parts[6] != "typ":
        return None
    return {
        "type": parts[7],
        "protocol": parts[2].lower(),
        "address": parts[4],
        "port": parts[5],
        "component": parts[1],
    }


def iter_sdp_candidate_summaries(sdp: str):
    """Yield candidate summaries for every ``a=candidate:`` line in an SDP.

    Args:
        sdp: A full SDP offer/answer string.

    Yields:
        Non-None summaries from :func:`summarize_ice_candidate`.
    """
    if not sdp:
        return
    for raw in sdp.splitlines():
        raw = raw.strip()
        if raw.startswith("a=candidate:"):
            summary = summarize_ice_candidate(raw[len("a=") :])
            if summary:
                yield summary


@dataclass
class PeerConnection:
    """State for a single WebRTC peer connection.

    Attributes:
        peer_fingerprint: PGP fingerprint of the remote peer.
        pc: aiortc RTCPeerConnection instance.
        channel: The "skcomms" ordered reliable RTCDataChannel, or None.
        connected: True when the data channel is open and ready to send.
        negotiating: True while SDP/ICE negotiation is in progress.
        pending: Envelope bytes queued before the channel opened.
    """

    peer_fingerprint: str
    pc: object  # RTCPeerConnection
    channel: Optional[object] = None  # RTCDataChannel
    connected: bool = False
    negotiating: bool = False
    pending: list[bytes] = field(default_factory=list)


class WebRTCTransport(Transport):
    """P2P transport using WebRTC data channels via aiortc.

    Opens direct peer-to-peer data channels to other SKComms agents and
    browser clients. Uses the SKComms signaling broker (Phase 2) for SDP/ICE
    exchange. Falls back gracefully to lower-priority transports during the
    ~3s ICE negotiation window.

    Attributes:
        name: Always ``"webrtc"``.
        priority: Default 1 (highest — preferred over all other transports).
        category: ``REALTIME`` — selected by ``RoutingMode.SPEED``.
    """

    name: str = "webrtc"
    priority: int = 1
    category: TransportCategory = TransportCategory.REALTIME

    def __init__(
        self,
        signaling_url: Optional[str] = None,
        stun_servers: Optional[list[str]] = None,
        turn_server: Optional[str] = None,
        turn_username: Optional[str] = None,
        turn_credential: Optional[str] = None,
        turn_secret: Optional[str] = None,
        agent_fingerprint: Optional[str] = None,
        agent_name: Optional[str] = None,
        token: Optional[str] = None,
        auto_connect: bool = False,
        priority: int = 1,
        **kwargs,
    ):
        """Initialize the WebRTC transport.

        Args:
            signaling_url: WebSocket URL of the SKComms signaling broker.
                Defaults to ``wss://localhost:9384/webrtc/ws``.
                Override with the ``SKCOMMS_SIGNALING_URL`` environment variable.
            stun_servers: STUN server URLs (default: Google public STUN).
            turn_server: TURN relay URL (e.g. ``turn:turn.skworld.io:3478``).
            turn_username: Static TURN username (for static credentials).
            turn_credential: Static TURN password.
            turn_secret: HMAC-SHA1 secret for time-limited TURN credentials.
                Takes precedence over static username/credential.
            agent_fingerprint: Local CapAuth PGP fingerprint (used for room ID
                and signaling identity).
            agent_name: Local agent name (fallback if no fingerprint).
            token: CapAuth bearer token for signaling authentication.
            auto_connect: Start the background loop immediately on init.
            priority: Transport priority (lower = higher priority).
        """
        self._signaling_url = signaling_url or DEFAULT_SIGNALING_URL
        self._stun_servers = stun_servers or ["stun:stun.l.google.com:19302"]
        self._turn_server = turn_server
        self._turn_username = turn_username
        self._turn_credential = turn_credential
        self._turn_secret = turn_secret
        self._agent_fingerprint = agent_fingerprint
        self._agent_name = agent_name or "agent"
        self._token = token
        self.priority = priority

        # Async infrastructure
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._running = False

        # Signaling state
        self._signaling_ws = None
        self._signaling_connected = False
        self._signaling_error: Optional[str] = None
        # Log-once-per-state-change flag for signaling connect failures (RC4):
        # True while the broker is unreachable, so the reconnect loop WARNs once
        # on the way in and DEBUGs while it persists, instead of every attempt.
        self._signaling_failing = False

        # Peer connections: fingerprint → PeerConnection
        self._peers: dict[str, PeerConnection] = {}
        self._peers_lock = threading.Lock()

        # Unified inbox for all received envelopes from all peers
        self._inbox: queue.Queue[bytes] = queue.Queue(maxsize=10000)

        if auto_connect:
            self.start()

    # ──────────────────────────────────────────────────────────────────────
    # Transport ABC implementation
    # ──────────────────────────────────────────────────────────────────────

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys: ``signaling_url``, ``stun_servers``,
                ``turn_server``, ``turn_secret``, ``agent_fingerprint``,
                ``agent_name``, ``token``, ``priority``, ``auto_connect``.
        """
        was_running = self._running
        if was_running:
            self.stop()

        for key, attr in [
            ("signaling_url", "_signaling_url"),
            ("stun_servers", "_stun_servers"),
            ("turn_server", "_turn_server"),
            ("turn_secret", "_turn_secret"),
            ("agent_fingerprint", "_agent_fingerprint"),
            ("agent_name", "_agent_name"),
            ("token", "_token"),
        ]:
            if key in config:
                setattr(self, attr, config[key])

        if "priority" in config:
            self.priority = int(config["priority"])

        if was_running or config.get("auto_connect", False):
            self.start()

    def is_available(self) -> bool:
        """True if the background loop is running and signaling is connected.

        Returns:
            bool: Whether the transport can likely deliver right now.
        """
        return self._running and self._signaling_connected

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Send an envelope to a recipient via a WebRTC data channel.

        If a connected data channel exists for the recipient, sends
        immediately. Otherwise, initiates ICE negotiation in the background
        and returns failure so the router can fall back to another transport.
        The next send attempt (~3s later) will succeed transparently.

        Args:
            envelope_bytes: Serialised MessageEnvelope bytes.
            recipient: PGP fingerprint or agent name of the recipient.

        Returns:
            SendResult with success/failure and timing.
        """
        start = time.monotonic()
        envelope_id = self._extract_id(envelope_bytes)

        if not self._running:
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=(time.monotonic() - start) * 1000,
                error="WebRTC transport not started (call start())",
            )

        with self._peers_lock:
            peer = self._peers.get(recipient)
            # Snapshot connection state under lock to avoid races.
            # The offer-scheduling decision is also made here: pre-marking
            # negotiating=True (or inserting the stub) inside the lock ensures
            # that concurrent send() calls cannot both decide to schedule an
            # offer for the same recipient, preventing duplicate ICE offers.
            is_connected = peer.connected if peer else False
            channel = peer.channel if peer else None
            is_negotiating = peer.negotiating if peer else False
            should_offer = not is_connected and not is_negotiating
            if should_offer:
                if peer is None:
                    self._peers[recipient] = PeerConnection(
                        peer_fingerprint=recipient, pc=None, negotiating=True
                    )
                else:
                    peer.negotiating = True

        if is_connected and channel:
            # Happy path: data channel is open
            try:
                future = self._run_in_loop(
                    self._async_channel_send(channel, envelope_bytes),
                )
                future.result(timeout=SEND_TIMEOUT)
                elapsed = (time.monotonic() - start) * 1000
                logger.info(
                    "Sent %d bytes to %s via WebRTC (%.1fms)",
                    len(envelope_bytes),
                    recipient[:8] if len(recipient) >= 8 else recipient,
                    elapsed,
                )
                return SendResult(
                    success=True,
                    transport_name=self.name,
                    envelope_id=envelope_id,
                    latency_ms=elapsed,
                )
            except Exception as exc:
                elapsed = (time.monotonic() - start) * 1000
                logger.warning("WebRTC channel send failed to %s: %s", recipient[:8], exc)
                # Use identity comparison (``is peer``) rather than a key lookup +
                # index: between the two steps another thread could remove the peer
                # (via _cleanup_peer) or replace it with a fresh negotiating stub,
                # causing either a KeyError or wrongly marking the new stub as
                # disconnected.  ``peer`` was captured under the lock above, so
                # comparing by identity is safe and avoids re-indexing the dict.
                with self._peers_lock:
                    if self._peers.get(recipient) is peer:
                        peer.connected = False
                return SendResult(
                    success=False,
                    transport_name=self.name,
                    envelope_id=envelope_id,
                    latency_ms=elapsed,
                    error=str(exc),
                )

        # No open connection — schedule ICE negotiation, return failure.
        # The stub / negotiating=True flag was set inside the lock above, so
        # only one concurrent send() will ever reach should_offer=True.
        if should_offer and self._loop and self._running:
            try:
                self._run_in_loop(self._initiate_offer(recipient))
            except RuntimeError:
                logger.warning("WebRTC: cannot schedule offer — event loop not running")

        elapsed = (time.monotonic() - start) * 1000
        return SendResult(
            success=False,
            transport_name=self.name,
            envelope_id=envelope_id,
            latency_ms=elapsed,
            error="No WebRTC connection yet — ICE negotiation started, retry in ~3s",
        )

    def receive(self) -> list[bytes]:
        """Drain all buffered incoming envelopes.

        Returns:
            List of raw envelope bytes received since the last call.
        """
        messages: list[bytes] = []
        try:
            while True:
                messages.append(self._inbox.get_nowait())
        except queue.Empty:
            pass
        return messages

    def health_check(self) -> HealthStatus:
        """Detailed health report for the WebRTC transport.

        Returns:
            HealthStatus with signaling state, active peer count, and details.
        """
        if not self._running:
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.UNAVAILABLE,
                error="Transport not started — call start()",
                details={"signaling_url": self._signaling_url},
            )

        with self._peers_lock:
            connected = [fp for fp, p in self._peers.items() if p.connected]
            negotiating = [fp for fp, p in self._peers.items() if p.negotiating]

        if not self._signaling_connected:
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.DEGRADED,
                error=self._signaling_error or "Signaling broker disconnected",
                details={
                    "signaling_url": self._signaling_url,
                    "signaling_connected": False,
                    "active_peers": len(connected),
                },
            )

        return HealthStatus(
            transport_name=self.name,
            status=TransportStatus.AVAILABLE,
            details={
                "signaling_url": self._signaling_url,
                "signaling_connected": True,
                "active_peers": len(connected),
                "negotiating_peers": len(negotiating),
                "peer_fingerprints": [fp[:8] for fp in connected],
                "inbox_pending": self._inbox.qsize(),
            },
        )

    # ──────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start the background asyncio loop and connect to the signaling broker.

        Returns:
            True when the background thread has been started.
        """
        if self._running:
            return True

        self._loop = asyncio.new_event_loop()
        self._running = True
        self._loop_thread = threading.Thread(
            target=self._run_loop,
            name="skcomms-webrtc",
            daemon=True,
        )
        self._loop_thread.start()
        time.sleep(CONNECT_SETTLE)  # Allow loop + signaling connect attempt
        return True

    def stop(self) -> None:
        """Stop the background loop and close all peer connections."""
        self._running = False

        if self._loop and not self._loop.is_closed():
            try:
                future = self._run_in_loop(self._async_stop())
                future.result(timeout=5.0)
            except RuntimeError:
                # Loop already stopped — skip async cleanup
                pass
            except Exception as e:
                logger.warning("webrtc.py: %s", e)
                pass
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass

        if self._loop_thread and self._loop_thread.is_alive():
            self._loop_thread.join(timeout=5.0)

        # Defensive close after join: _run_loop's finally block normally handles
        # this, but if the thread never started or exited before run_until_complete
        # was entered, the loop may still be open.
        if self._loop and not self._loop.is_closed():
            try:
                self._loop.close()
            except Exception as e:
                logger.warning("webrtc.py: %s", e)
                pass

        self._signaling_connected = False

    # ──────────────────────────────────────────────────────────────────────
    # Background asyncio loop
    # ──────────────────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Background thread: own and drive the asyncio event loop."""
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main_loop())
        finally:
            self._loop.close()

    def _log_signaling_failure(self, exc: Exception, reconnect_delay: float) -> int:
        """Log a signaling connect failure once per state change (RC4).

        WARN on the transition INTO the failing state (first failure), DEBUG
        while the broker stays unreachable. The startup health-gate (B5) is the
        real fix when the broker is simply absent; this only bounds the noise.

        Args:
            exc: The connect exception.
            reconnect_delay: The delay before the next reconnect attempt.

        Returns:
            The ``logging`` level that was emitted (WARNING or DEBUG).
        """
        msg = "Signaling connection error: %s — reconnect in %.0fs"
        if not self._signaling_failing:
            self._signaling_failing = True
            logger.warning(msg, exc, reconnect_delay)
            return logging.WARNING
        logger.debug(msg, exc, reconnect_delay)
        return logging.DEBUG

    def _note_signaling_recovered(self) -> None:
        """Emit one recovery line iff signaling was previously failing (RC4)."""
        if self._signaling_failing:
            self._signaling_failing = False
            logger.info("WebRTC: signaling connection recovered")

    async def _main_loop(self) -> None:
        """Async main: connect to signaling broker with exponential backoff."""
        reconnect_delay = 2.0
        while self._running:
            try:
                await self._connect_signaling()
                reconnect_delay = 2.0
                # A clean connect/attempt clears the failing state (one INFO
                # line) so the next real failure WARNs again.
                self._note_signaling_recovered()
            except Exception as exc:
                self._signaling_connected = False
                self._signaling_error = str(exc)
                self._log_signaling_failure(exc, reconnect_delay)
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, 60.0)

    async def _connect_signaling(self) -> None:
        """Connect to the signaling broker and process messages until disconnect."""
        try:
            import websockets
        except ImportError:
            msg = "websockets not installed — pip install 'skcomms[webrtc]'"
            self._signaling_error = msg
            logger.error(msg)
            self._running = False
            return

        room = self._room_id()
        peer = self._agent_fingerprint or self._agent_name
        url = f"{self._signaling_url}?room={room}&peer={peer}"
        headers: dict = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        logger.info("WebRTC: connecting to signaling broker at %s", url)

        async with websockets.connect(url, additional_headers=headers) as ws:
            self._signaling_ws = ws
            self._signaling_connected = True
            self._signaling_error = None
            logger.info("WebRTC: signaling connected (room=%s)", room)

            try:
                while self._running:
                    try:
                        text = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT)
                    except asyncio.TimeoutError:
                        continue

                    try:
                        msg = json.loads(text)
                        await self._handle_signal(msg)
                    except json.JSONDecodeError:
                        logger.warning("WebRTC: malformed JSON from signaling broker")
            except Exception as exc:
                # Signaling disconnected unexpectedly — reset negotiating state
                # on all peers so that new offers can be initiated when signaling
                # reconnects, rather than leaving peers stuck in negotiating=True.
                logger.warning(
                    "WebRTC: signaling disconnected unexpectedly: %s — "
                    "resetting peer negotiation state so offers can be retried",
                    exc,
                )
                with self._peers_lock:
                    for peer in self._peers.values():
                        peer.negotiating = False
            finally:
                self._signaling_ws = None
                self._signaling_connected = False

    async def _handle_signal(self, msg: dict) -> None:
        """Dispatch incoming signaling messages from the broker.

        Args:
            msg: Parsed message dict from the signaling WebSocket.
        """
        msg_type = msg.get("type")

        if msg_type == "welcome":
            # Broker told us which peers are already in the room.
            # Insert the negotiating stub inside the lock so that the
            # check-and-act is atomic — prevents TOCTOU where two code paths
            # both see "not in peers" and fire duplicate offers.
            for peer_id in msg.get("peers", []):
                should_offer = False
                with self._peers_lock:
                    if peer_id not in self._peers:
                        self._peers[peer_id] = PeerConnection(
                            peer_fingerprint=peer_id, pc=None, negotiating=True
                        )
                        should_offer = True
                if should_offer:
                    await self._initiate_offer(peer_id)

        elif msg_type == "peer_joined":
            # A new peer arrived — they will (or we will) send an offer
            peer_id = msg.get("peer", "")
            if peer_id:
                logger.info("WebRTC: new peer in room: %s", peer_id[:8])

        elif msg_type == "peer_left":
            peer_id = msg.get("peer", "")
            if peer_id:
                await self._cleanup_peer(peer_id)

        elif msg_type == "signal":
            from_id = msg.get("from", "")
            data = msg.get("data", {})
            if from_id:
                await self._handle_incoming_signal(from_id, data)

    async def _initiate_offer(self, peer_id: str) -> None:
        """Create a WebRTC SDP offer and send it to a peer via signaling.

        Args:
            peer_id: PGP fingerprint of the peer to connect to.
        """
        try:
            from aiortc import RTCPeerConnection, RTCSessionDescription  # noqa: F401
        except ImportError:
            logger.error("aiortc not installed — pip install 'skcomms[webrtc]'")
            return

        peer: Optional[PeerConnection] = None
        try:
            peer = await self._create_peer_connection(peer_id)

            # We create the data channel (offerer side)
            channel = peer.pc.createDataChannel(CHANNEL_NAME, ordered=True)
            self._wire_channel(peer, channel)

            offer = await peer.pc.createOffer()
            await peer.pc.setLocalDescription(offer)
            await self._wait_for_ice_gathering(peer.pc)
            self._log_ice_candidates(
                peer.pc.localDescription.sdp if peer.pc.localDescription else "",
                peer_id,
                direction="local",
            )

            sdp_payload = {
                "sdp": {
                    "type": peer.pc.localDescription.type,
                    "sdp": peer.pc.localDescription.sdp,
                }
            }
            await self._send_signal(to=peer_id, data=sdp_payload)
            logger.info("WebRTC: sent SDP offer to %s", peer_id[:8])

        except Exception as exc:
            logger.error("WebRTC: failed to create offer for %s: %s", peer_id[:8], exc)
            with self._peers_lock:
                # Use identity comparison to avoid operating on a replacement
                # PeerConnection: if the peer was cleaned up and a new stub
                # inserted between the await above and this handler, we must
                # not reset the new stub's negotiating flag.  When peer is None
                # (failure before _create_peer_connection returned), fall back
                # to resetting whatever entry is present for peer_id.
                current = self._peers.get(peer_id)
                if peer is not None:
                    if current is peer:
                        peer.negotiating = False
                elif current is not None:
                    current.negotiating = False

    async def _handle_incoming_signal(self, from_id: str, data: dict) -> None:
        """Handle an incoming SDP offer, SDP answer, or ICE candidate.

        Args:
            from_id: PGP fingerprint of the signaling sender (authenticated).
            data: SDP or ICE payload from the broker.
        """
        try:
            from aiortc import RTCPeerConnection, RTCSessionDescription  # noqa: F401
        except ImportError:
            logger.error("aiortc not installed — pip install 'skcomms[webrtc]'")
            return

        try:
            # Verify CapAuth signature on SDP payloads.
            # The signaling broker authenticates the WebSocket connection, but
            # SDP payloads themselves should carry a PGP signature to prevent
            # MITM attacks at the signaling layer.  When a ``capauth`` wrapper
            # is present we verify it; when absent we log a warning and proceed
            # so that unsigned dev/test peers are not silently accepted as
            # fully authenticated.
            capauth_wrapper = data.get("capauth")
            if capauth_wrapper:
                try:
                    from ..capauth_validator import CapAuthValidator

                    validator = CapAuthValidator()
                    sig = capauth_wrapper.get("signature", "")
                    signed_payload = capauth_wrapper.get("signed_payload", "")
                    claimed_fp = capauth_wrapper.get("fingerprint", "")
                    if not validator.verify_detached(signed_payload, sig, claimed_fp):
                        logger.warning(
                            "WebRTC: SDP from %s has INVALID CapAuth signature — "
                            "dropping to prevent potential MITM",
                            from_id[:8],
                        )
                        return
                    if claimed_fp.upper() != from_id.upper():
                        logger.warning(
                            "WebRTC: SDP CapAuth fingerprint mismatch: "
                            "claimed=%s, authenticated=%s — dropping",
                            claimed_fp[:8],
                            from_id[:8],
                        )
                        return
                except ImportError:
                    logger.debug(
                        "WebRTC: CapAuth validator not available — "
                        "skipping SDP signature verification"
                    )
                except Exception as exc:
                    logger.warning(
                        "WebRTC: SDP signature verification failed for %s: %s — rejecting signal",
                        from_id[:8],
                        exc,
                    )
                    return
            else:
                logger.warning(
                    "WebRTC: SDP from %s has no CapAuth signature wrapper — "
                    "DTLS fingerprint binding is not verified. "
                    "Peer should send signed SDP for full MITM protection.",
                    from_id[:8],
                )

            sdp_data = data.get("sdp")
            if sdp_data:
                sdp_type = sdp_data.get("type")
                sdp_str = sdp_data.get("sdp", "")

                if sdp_type == "offer":
                    # We're the answerer
                    peer = await self._create_peer_connection(from_id)

                    # Wire the datachannel event before setting remote desc
                    @peer.pc.on("datachannel")
                    def _on_datachannel(channel):
                        if channel.label == CHANNEL_NAME:
                            self._wire_channel(peer, channel)

                    await peer.pc.setRemoteDescription(
                        RTCSessionDescription(sdp=sdp_str, type="offer")
                    )
                    self._log_ice_candidates(sdp_str, from_id, direction="remote")
                    answer = await peer.pc.createAnswer()
                    await peer.pc.setLocalDescription(answer)
                    await self._wait_for_ice_gathering(peer.pc)
                    self._log_ice_candidates(
                        peer.pc.localDescription.sdp if peer.pc.localDescription else "",
                        from_id,
                        direction="local",
                    )

                    sdp_payload = {
                        "sdp": {
                            "type": peer.pc.localDescription.type,
                            "sdp": peer.pc.localDescription.sdp,
                        }
                    }
                    await self._send_signal(to=from_id, data=sdp_payload)
                    logger.info("WebRTC: sent SDP answer to %s", from_id[:8])

                elif sdp_type == "answer":
                    # We're the offerer receiving the answer
                    with self._peers_lock:
                        peer = self._peers.get(from_id)
                    if peer:
                        await peer.pc.setRemoteDescription(
                            RTCSessionDescription(sdp=sdp_str, type="answer")
                        )
                        self._log_ice_candidates(sdp_str, from_id, direction="remote")
                        logger.info("WebRTC: applied SDP answer from %s", from_id[:8])

            ice_data = data.get("ice")
            if ice_data:
                # Trickle ICE: remote peer sent a candidate after SDP exchange.
                # Apply it to the existing peer connection so ICE can complete
                # even when the local _wait_for_ice_gathering already returned.
                candidate_str = ice_data.get("candidate", "")
                if candidate_str:
                    with self._peers_lock:
                        peer = self._peers.get(from_id)
                    if peer and peer.pc:
                        try:
                            from aiortc.sdp import candidate_from_sdp

                            # Strip the "candidate:" prefix that browsers include
                            sdp_line = candidate_str
                            if sdp_line.startswith("candidate:"):
                                sdp_line = sdp_line[len("candidate:") :]

                            ice_candidate = candidate_from_sdp(sdp_line)
                            ice_candidate.sdpMid = ice_data.get("sdpMid")
                            ice_candidate.sdpMLineIndex = ice_data.get("sdpMLineIndex")
                            await peer.pc.addIceCandidate(ice_candidate)
                            _summary = summarize_ice_candidate(candidate_str)
                            if _summary:
                                logger.debug(
                                    "WebRTC: applied trickle ICE candidate from %s: "
                                    "type=%s proto=%s addr=%s:%s",
                                    from_id[:8],
                                    _summary["type"],
                                    _summary["protocol"],
                                    _summary["address"],
                                    _summary["port"],
                                )
                            else:
                                logger.debug(
                                    "WebRTC: applied trickle ICE candidate from %s", from_id[:8]
                                )
                        except Exception as exc:
                            logger.warning(
                                "WebRTC: failed to apply ICE candidate from %s: %s",
                                from_id[:8],
                                exc,
                            )

        except Exception as exc:
            logger.error("WebRTC: signal handler error (from=%s): %s", from_id[:8], exc)

    async def _create_peer_connection(self, peer_id: str) -> PeerConnection:
        """Create a new RTCPeerConnection for a peer and register it.

        Args:
            peer_id: PGP fingerprint of the remote peer.

        Returns:
            Initialized PeerConnection (negotiation not yet started).
        """
        from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection

        ice_servers = self._build_ice_servers(RTCIceServer)
        pc = RTCPeerConnection(configuration=RTCConfiguration(iceServers=ice_servers))

        peer = PeerConnection(peer_fingerprint=peer_id, pc=pc, negotiating=True)

        with self._peers_lock:
            self._peers[peer_id] = peer

        # Track previous ICE connection-state so transitions can be logged
        # for connection debugging (purely diagnostic — no behaviour change).
        prev_ice_state = {"value": None}

        @pc.on("iceconnectionstatechange")
        async def _on_ice_state_change():
            state = pc.iceConnectionState
            old = prev_ice_state["value"]
            prev_ice_state["value"] = state
            logger.info(
                "WebRTC: ICE connection-state %s -> %s with %s",
                old,
                state,
                peer_id[:8],
            )
            if state == "failed":
                peer.negotiating = False
                logger.warning("WebRTC: ICE failed with %s", peer_id[:8])
            elif state in ("connected", "completed"):
                peer.negotiating = False

        @pc.on("icegatheringstatechange")
        def _on_ice_gathering_state_change():
            gstate = pc.iceGatheringState
            logger.debug(
                "WebRTC: ICE gathering-state with %s: %s", peer_id[:8], gstate
            )
            if gstate == "complete":
                logger.info("WebRTC: ICE gathering complete for %s", peer_id[:8])

        return peer

    def _log_ice_candidates(self, sdp: str, peer_id: str, direction: str) -> None:
        """Log the ICE candidates embedded in an SDP for connection debugging.

        Purely diagnostic — emits one DEBUG line per candidate (type /
        protocol / address / port) plus a single INFO summary with the
        total count and the distinct candidate types. No behaviour change
        and no secrets (ufrag/pwd/tokens) are ever logged. Verbosity is
        governed entirely by the module logger's configuration.

        Args:
            sdp: SDP offer/answer whose candidates should be logged.
            peer_id: Fingerprint of the remote peer (truncated in logs).
            direction: ``"local"`` (gathered) or ``"remote"`` (received).
        """
        summaries = list(iter_sdp_candidate_summaries(sdp))
        if not summaries:
            return
        for cand in summaries:
            logger.debug(
                "WebRTC: %s ICE candidate for %s: type=%s proto=%s addr=%s:%s",
                direction,
                peer_id[:8],
                cand["type"],
                cand["protocol"],
                cand["address"],
                cand["port"],
            )
        types = ",".join(sorted({c["type"] for c in summaries}))
        logger.info(
            "WebRTC: %d %s ICE candidate(s) for %s (types=%s)",
            len(summaries),
            direction,
            peer_id[:8],
            types,
        )

    def _wire_channel(self, peer: PeerConnection, channel) -> None:
        """Register event handlers on an RTCDataChannel.

        Args:
            peer: The owning PeerConnection.
            channel: An aiortc RTCDataChannel instance.
        """
        peer.channel = channel

        @channel.on("open")
        async def _on_open():
            peer.connected = True
            peer.negotiating = False
            logger.info("WebRTC: data channel open with %s", peer.peer_fingerprint[:8])
            # Flush any messages queued before the channel opened
            if peer.pending:
                for pending_bytes in list(peer.pending):
                    try:
                        await self._async_channel_send(channel, pending_bytes)
                    except Exception as exc:
                        logger.warning(
                            "WebRTC: pending flush failed to %s: %s",
                            peer.peer_fingerprint[:8],
                            exc,
                        )
                peer.pending.clear()

        @channel.on("message")
        def _on_message(message):
            if isinstance(message, str):
                message = message.encode()
            try:
                self._inbox.put_nowait(message)
            except queue.Full:
                logger.warning(
                    "WebRTC: inbox full (maxsize=%d), dropping %d-byte message from %s",
                    self._inbox.maxsize,
                    len(message),
                    peer.peer_fingerprint[:8],
                )
                return
            logger.debug(
                "WebRTC: received %d bytes from %s", len(message), peer.peer_fingerprint[:8]
            )

        @channel.on("close")
        def _on_close():
            peer.connected = False
            logger.info("WebRTC: data channel closed with %s", peer.peer_fingerprint[:8])

    async def _wait_for_ice_gathering(self, pc, timeout: float = ICE_GATHER_TIMEOUT) -> None:
        """Wait for ICE gathering to complete (iceGatheringState == "complete").

        Args:
            pc: RTCPeerConnection to monitor.
            timeout: Maximum seconds to wait before proceeding.
        """
        if pc.iceGatheringState == "complete":
            return

        ice_done = asyncio.Event()

        @pc.on("icegatheringcomplete")
        def _on_ice_done():
            ice_done.set()

        try:
            await asyncio.wait_for(ice_done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("WebRTC: ICE gathering timed out after %.0fs", timeout)

    async def _send_signal(self, to: str, data: dict) -> None:
        """Send a signal message to a peer via the signaling WebSocket.

        Args:
            to: Fingerprint of the target peer.
            data: SDP or ICE payload.
        """
        if not self._signaling_ws:
            logger.warning("WebRTC: cannot signal — not connected to broker")
            return
        message = json.dumps({"type": "signal", "to": to, "data": data})
        await self._signaling_ws.send(message)

    @staticmethod
    async def _async_channel_send(channel, data: bytes) -> None:
        """Send bytes through a WebRTC data channel.

        Args:
            channel: Open RTCDataChannel instance.
            data: Raw bytes to send.
        """
        channel.send(data)

    async def _cleanup_peer(self, peer_id: str) -> None:
        """Remove a single peer connection and close its RTCPeerConnection.

        Acquires ``_peers_lock`` to safely remove the peer from the dict,
        preventing modification while another thread may be iterating.

        Args:
            peer_id: PGP fingerprint of the peer to clean up.
        """
        with self._peers_lock:
            peer = self._peers.pop(peer_id, None)

        if peer:
            try:
                await peer.pc.close()
            except Exception as e:
                logger.warning("webrtc.py: %s", e)
                pass
            logger.info("WebRTC: peer %s cleaned up", peer_id[:8])

    async def _async_stop(self) -> None:
        """Async cleanup: close all peer connections and signaling WS.

        Copies peer keys under lock before iterating, so that concurrent
        ``_cleanup_peer`` or ``_on_datachannel`` calls do not cause a
        ``RuntimeError: dictionary changed size during iteration``.
        """
        with self._peers_lock:
            peer_ids = list(self._peers.keys())

        for pid in peer_ids:
            await self._cleanup_peer(pid)

        if self._signaling_ws:
            try:
                await self._signaling_ws.close()
            except Exception as e:
                logger.warning("webrtc.py: %s", e)
                pass

    # ──────────────────────────────────────────────────────────────────────
    # Threading bridge
    # ──────────────────────────────────────────────────────────────────────

    def _run_in_loop(self, coro) -> "asyncio.Future":
        """Submit a coroutine to the background asyncio loop from a sync thread.

        Guards against submitting work to a closed or stopped loop, which
        would otherwise silently drop the coroutine or raise an obscure error.

        Args:
            coro: Awaitable coroutine to schedule on the event loop.

        Returns:
            A concurrent.futures.Future representing the result.

        Raises:
            RuntimeError: If the background event loop is not running (stopped
                or closed), so callers get a clear error instead of a hang.
        """
        loop = self._loop
        if loop is None or loop.is_closed() or not loop.is_running():
            # Close the coroutine to avoid "coroutine was never awaited" warning
            coro.close()
            raise RuntimeError(
                "WebRTC background event loop is not running — "
                "cannot submit async work (loop closed or stopped)"
            )
        return asyncio.run_coroutine_threadsafe(coro, loop)

    def _schedule_offer(self, peer_id: str) -> None:
        """Schedule a WebRTC offer to a peer from the synchronous side.

        Sets ``negotiating=True`` on a stub PeerConnection *before* dispatching
        to the async loop so that concurrent ``send()`` calls do not enqueue a
        second offer for the same peer while the first is being set up.
        ``_create_peer_connection`` will replace the stub with the real one.

        Args:
            peer_id: Target peer fingerprint.
        """
        if not self._loop or not self._running:
            return
        with self._peers_lock:
            if peer_id not in self._peers:
                # Install a stub so send() sees negotiating=True immediately.
                # _create_peer_connection will overwrite this with the real PC.
                self._peers[peer_id] = PeerConnection(
                    peer_fingerprint=peer_id, pc=None, negotiating=True
                )
        try:
            self._run_in_loop(self._initiate_offer(peer_id))
        except RuntimeError:
            logger.warning("WebRTC: cannot schedule offer — event loop not running")

    # ──────────────────────────────────────────────────────────────────────
    # ICE server configuration
    # ──────────────────────────────────────────────────────────────────────

    def _build_ice_servers(self, RTCIceServer) -> list:
        """Build the ICE server list from transport configuration.

        Args:
            RTCIceServer: The aiortc RTCIceServer class.

        Returns:
            List of configured RTCIceServer instances.
        """
        servers = [RTCIceServer(urls=url) for url in self._stun_servers]

        if self._turn_server:
            if self._turn_secret:
                username, credential = self._derive_turn_credentials()
                servers.append(
                    RTCIceServer(
                        urls=self._turn_server,
                        username=username,
                        credential=credential,
                    )
                )
            elif self._turn_username and self._turn_credential:
                servers.append(
                    RTCIceServer(
                        urls=self._turn_server,
                        username=self._turn_username,
                        credential=self._turn_credential,
                    )
                )
            else:
                logger.warning(
                    "WebRTC: TURN server %s configured but no credentials "
                    "provided (set turn_secret or turn_username+turn_credential). "
                    "TURN relay will likely fail authentication and NAT traversal "
                    "may fall back to STUN-only.",
                    self._turn_server,
                )
                servers.append(RTCIceServer(urls=self._turn_server))

        return servers

    def _derive_turn_credentials(self) -> tuple[str, str]:
        """Derive time-limited HMAC-SHA1 TURN credentials (RFC 5389 §10.2).

        Returns:
            Tuple of (username, credential) for ``RTCIceServer``.
        """
        import base64
        import hashlib
        import hmac

        ttl = 86400  # 24-hour validity window
        timestamp = int(time.time()) + ttl
        username = f"{timestamp}:{self._agent_name}"
        credential = base64.b64encode(
            hmac.new(
                key=self._turn_secret.encode(),
                msg=username.encode(),
                digestmod=hashlib.sha1,
            ).digest()
        ).decode()
        return username, credential

    # ──────────────────────────────────────────────────────────────────────
    # Room ID
    # ──────────────────────────────────────────────────────────────────────

    def _room_id(self) -> str:
        """Generate the signaling room ID for this agent.

        Returns:
            Room ID string: ``"skcomms-"`` + first 16 chars of fingerprint.
        """
        if self._agent_fingerprint:
            return f"skcomms-{self._agent_fingerprint[:16]}"
        return f"skcomms-{self._agent_name}"

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_id(envelope_bytes: bytes) -> str:
        """Best-effort extraction of envelope_id from raw envelope bytes.

        Args:
            envelope_bytes: Raw JSON envelope.

        Returns:
            The envelope_id string, or a timestamp-based fallback.
        """
        try:
            parsed = json.loads(envelope_bytes)
            return parsed.get("envelope_id", f"unknown-{int(time.time())}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return f"unknown-{int(time.time())}"


def create_transport(
    signaling_url: Optional[str] = None,
    stun_servers: Optional[list[str]] = None,
    turn_server: Optional[str] = None,
    turn_secret: Optional[str] = None,
    agent_fingerprint: Optional[str] = None,
    agent_name: Optional[str] = None,
    token: Optional[str] = None,
    auto_connect: bool = False,
    priority: int = 1,
    **kwargs,
) -> WebRTCTransport:
    """Factory function called by the SKComms router transport loader.

    Args:
        signaling_url: WebSocket URL of the SKComms signaling broker.
        stun_servers: List of STUN server URLs.
        turn_server: TURN relay URL for fallback (e.g. ``turn:turn.skworld.io:3478``).
        turn_secret: HMAC-SHA1 secret for time-limited TURN credentials.
        agent_fingerprint: Local CapAuth PGP fingerprint.
        agent_name: Local agent name (fallback if fingerprint unavailable).
        token: CapAuth bearer token for signaling broker authentication.
        auto_connect: Start the background asyncio loop immediately.
        priority: Transport priority (lower = higher priority in routing).

    Returns:
        Configured WebRTCTransport instance.
    """
    return WebRTCTransport(
        signaling_url=signaling_url,
        stun_servers=stun_servers,
        turn_server=turn_server,
        turn_secret=turn_secret,
        agent_fingerprint=agent_fingerprint,
        agent_name=agent_name,
        token=token,
        auto_connect=auto_connect,
        priority=priority,
    )
