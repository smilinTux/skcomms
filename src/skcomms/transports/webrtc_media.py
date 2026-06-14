"""WebRTC media session for FaceTime avatar streaming.

Manages an RTCPeerConnection with video (MuseTalk avatar), audio (TTS),
and a data channel (control/captions). Uses the same signaling broker and
ICE infrastructure as the existing WebRTCTransport, but is a separate
class because it serves a fundamentally different purpose (media streaming
vs. reliable message delivery).

Architecture:
    This runs on the GPU server (192.168.0.100) alongside MuseTalk and TTS.
    The browser connects via the SKComms signaling broker (/webrtc/ws), and
    media flows directly via ICE (LAN direct or TURN relay).

    GPU Server                          Browser
    ┌─────────────────────┐            ┌──────────────────┐
    │ FaceTimeSession     │            │ RTCPeerConnection │
    │  ├─ VideoTrack ─────┼── ICE ────►│  ontrack(video)   │
    │  ├─ AudioTrack ─────┼── ICE ────►│  ontrack(audio)   │
    │  └─ DataChannel ────┼── ICE ────►│  ondatachannel    │
    └─────────────────────┘            └──────────────────┘
              ▲                                ▲
              │ SDP/ICE signals                │
              └──────── /webrtc/ws ────────────┘

Usage:
    session = FaceTimeSession(
        agent_name="lumina",
        portrait_path="~/.skcapstone/agents/lumina/avatar/portrait.png",
        signaling_url="wss://skchat.skworld.io/webrtc/ws",
        turn_server="turn:turn.skworld.io:3478",
        turn_secret="...",
    )
    await session.start()

    # Feed TTS audio (triggers MuseTalk + WebRTC delivery)
    await session.send_audio(tts_pcm_bytes)

    # Feed MuseTalk frames
    await session.send_video_frame(bgr_numpy_array)

    # Send caption text via data channel
    await session.send_caption("Hello from Lumina!")

    # Cleanup
    await session.stop()

Dependencies (optional extra):
    pip install 'skcomms[webrtc]'  →  aiortc>=1.9.0, av, websockets>=12.0
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import numpy as np

from .audio_track import TTSAudioTrack
from .video_track import MuseTalkVideoTrack

logger = logging.getLogger("skcomms.transports.webrtc_media")

# Defaults
DEFAULT_SIGNALING_URL = os.environ.get("SKCOMMS_SIGNALING_URL", "wss://localhost:9384/webrtc/ws")
DEFAULT_TURN_SERVER = os.environ.get("SKCOMMS_TURN_SERVER", "turn:turn.skworld.io:3478")
DEFAULT_STUN_SERVERS = ["stun:stun.l.google.com:19302"]

# Video settings
DEFAULT_FPS = 20
DEFAULT_WIDTH = 1280
DEFAULT_HEIGHT = 720

# Queue sizes
VIDEO_QUEUE_SIZE = 3  # Small: latest-wins, minimize latency
AUDIO_QUEUE_SIZE = 50  # Larger: audio gaps are more noticeable


class FaceTimeSession:
    """Manages a single FaceTime avatar streaming session over WebRTC.

    Creates an RTCPeerConnection with video, audio, and data channel tracks.
    Handles signaling via the SKComms WebSocket broker and ICE negotiation.

    The session can be in one of these states:
        - IDLE: Created but not started
        - SIGNALING: SDP offer created, waiting for browser answer
        - CONNECTED: ICE connected, media flowing
        - CLOSED: Session ended

    Attributes:
        agent_name: Name of the agent whose avatar is being streamed.
        state: Current session state string.
        peer_id: Browser's fingerprint (set after signaling).
    """

    def __init__(
        self,
        agent_name: str,
        portrait_path: Optional[str] = None,
        signaling_url: Optional[str] = None,
        stun_servers: Optional[list[str]] = None,
        turn_server: Optional[str] = None,
        turn_secret: Optional[str] = None,
        agent_fingerprint: Optional[str] = None,
        token: Optional[str] = None,
        fps: int = DEFAULT_FPS,
        width: int = DEFAULT_WIDTH,
        height: int = DEFAULT_HEIGHT,
        tts_sample_rate: int = 24000,
    ):
        """Initialize a FaceTime session.

        Args:
            agent_name: Agent name (e.g., "lumina").
            portrait_path: Path to the agent's portrait image for idle frame.
            signaling_url: SKComms signaling broker WebSocket URL.
            stun_servers: STUN server URLs.
            turn_server: TURN relay URL.
            turn_secret: HMAC-SHA1 secret for TURN credentials.
            agent_fingerprint: Local CapAuth PGP fingerprint.
            token: CapAuth bearer token for signaling.
            fps: Target video frame rate.
            width: Output video width.
            height: Output video height.
            tts_sample_rate: Sample rate of incoming TTS audio.
        """
        self.agent_name = agent_name
        self.state = "IDLE"
        self.peer_id: Optional[str] = None

        # Configuration
        self._signaling_url = signaling_url or DEFAULT_SIGNALING_URL
        self._stun_servers = stun_servers or DEFAULT_STUN_SERVERS
        self._turn_server = turn_server or DEFAULT_TURN_SERVER
        self._turn_secret = turn_secret or os.environ.get("SKCOMMS_TURN_SECRET")
        self._agent_fingerprint = agent_fingerprint
        self._token = token
        self._portrait_path = portrait_path

        # Media settings
        self._fps = fps
        self._width = width
        self._height = height
        self._tts_sample_rate = tts_sample_rate

        # Queues for feeding media to tracks
        self._video_queue: asyncio.Queue = asyncio.Queue(maxsize=VIDEO_QUEUE_SIZE)
        self._audio_queue: asyncio.Queue = asyncio.Queue(maxsize=AUDIO_QUEUE_SIZE)

        # Track instances (created in start())
        self._video_track: Optional[MuseTalkVideoTrack] = None
        self._audio_track: Optional[TTSAudioTrack] = None

        # WebRTC objects (created in start())
        self._pc = None  # RTCPeerConnection
        self._channel = None  # RTCDataChannel
        self._signaling_ws = None  # WebSocket to signaling broker

        # Event for connection established
        self._connected_event = asyncio.Event()

    async def start(self) -> None:
        """Start the FaceTime session.

        Creates the RTCPeerConnection, adds media tracks, connects to
        the signaling broker, and waits for a browser peer to join.
        """
        from aiortc import (
            RTCConfiguration,
            RTCIceServer,
            RTCPeerConnection,
        )

        logger.info("Starting FaceTime session for agent '%s'", self.agent_name)
        self.state = "SIGNALING"

        # Load idle portrait
        idle_frame = self._load_portrait()

        # Create media tracks
        self._video_track = MuseTalkVideoTrack(
            frame_queue=self._video_queue,
            fps=self._fps,
            width=self._width,
            height=self._height,
            idle_frame=idle_frame,
        )
        self._audio_track = TTSAudioTrack(
            audio_queue=self._audio_queue,
            input_sample_rate=self._tts_sample_rate,
        )

        # Build ICE configuration
        ice_servers = self._build_ice_servers(RTCIceServer)
        config = RTCConfiguration(iceServers=ice_servers)

        # Create peer connection
        self._pc = RTCPeerConnection(configuration=config)

        # Add tracks
        video_sender = self._pc.addTrack(self._video_track)
        audio_sender = self._pc.addTrack(self._audio_track)

        # Prefer H.264 for video
        self._prefer_h264(video_sender)

        # Set bandwidth limits
        await self._set_bandwidth(video_sender, max_bitrate=800_000)
        await self._set_bandwidth(audio_sender, max_bitrate=48_000)

        # Create data channel for captions and control
        self._channel = self._pc.createDataChannel("skcomms", ordered=True)
        self._channel.on("open", self._on_channel_open)
        self._channel.on("message", self._on_channel_message)

        # Monitor connection state
        self._pc.on("connectionstatechange", self._on_connection_state_change)
        self._pc.on("iceconnectionstatechange", self._on_ice_state_change)

        # Connect to signaling broker
        await self._connect_signaling()

        logger.info("FaceTime session started, waiting for browser peer")

    async def stop(self) -> None:
        """Stop the FaceTime session and clean up all resources."""
        logger.info("Stopping FaceTime session for agent '%s'", self.agent_name)
        self.state = "CLOSED"

        if self._pc:
            await self._pc.close()
            self._pc = None

        if self._signaling_ws:
            await self._signaling_ws.close()
            self._signaling_ws = None

        self._video_track = None
        self._audio_track = None
        self._channel = None

        logger.info("FaceTime session stopped")

    # ──────────────────────────────────────────────────────────────────
    # Public API: feeding media
    # ──────────────────────────────────────────────────────────────────

    async def send_video_frame(self, bgr_array: np.ndarray) -> bool:
        """Feed a video frame from MuseTalk to the WebRTC video track.

        If the queue is full (track not consuming fast enough), the frame
        is dropped. This implements latest-wins behavior to minimize latency.

        Args:
            bgr_array: BGR uint8 numpy array from MuseTalk.

        Returns:
            True if enqueued, False if dropped.
        """
        if self.state != "CONNECTED":
            return False
        try:
            # Drop oldest if full (latest-wins)
            if self._video_queue.full():
                try:
                    self._video_queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            self._video_queue.put_nowait(bgr_array)
            return True
        except asyncio.QueueFull:
            return False

    async def send_audio(self, pcm_bytes: bytes) -> bool:
        """Feed TTS audio to the WebRTC audio track.

        Args:
            pcm_bytes: Raw 16-bit signed PCM audio (mono) at the
                sample rate specified in the constructor.

        Returns:
            True if enqueued, False if queue is full.
        """
        if self.state != "CONNECTED":
            return False
        try:
            self._audio_queue.put_nowait(pcm_bytes)
            return True
        except asyncio.QueueFull:
            logger.warning("Audio queue full, dropping chunk")
            return False

    async def send_caption(self, text: str, role: str = "assistant") -> None:
        """Send a caption/transcript message via the data channel.

        Args:
            text: Caption text.
            role: "assistant" or "user".
        """
        if self._channel and self._channel.readyState == "open":
            self._channel.send(
                json.dumps(
                    {
                        "type": "transcript",
                        "role": role,
                        "text": text,
                    }
                )
            )

    async def send_emotion(self, emotion: str, intensity: float) -> None:
        """Send an emotion state update via the data channel.

        Args:
            emotion: Emotion label (e.g., "happy", "sad", "neutral").
            intensity: Emotion intensity 0.0 to 1.0.
        """
        if self._channel and self._channel.readyState == "open":
            self._channel.send(
                json.dumps(
                    {
                        "type": "emotion",
                        "emotion": emotion,
                        "intensity": intensity,
                    }
                )
            )

    def interrupt(self) -> None:
        """Interrupt current speech. Flushes audio buffer immediately."""
        if self._audio_track:
            self._audio_track.flush()
        # Clear video queue too
        while not self._video_queue.empty():
            try:
                self._video_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    # ──────────────────────────────────────────────────────────────────
    # Signaling
    # ──────────────────────────────────────────────────────────────────

    async def _connect_signaling(self) -> None:
        """Connect to the SKComms signaling broker and listen for peers."""
        import websockets

        room_id = f"facetime-{self.agent_name}"
        peer_id = self._agent_fingerprint or self.agent_name

        url = f"{self._signaling_url}?room={room_id}&peer={peer_id}"
        headers = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        self._signaling_ws = await websockets.connect(url, extra_headers=headers)

        # Start signaling message handler
        asyncio.create_task(self._signaling_loop())

    async def _signaling_loop(self) -> None:
        """Process signaling messages from the broker."""
        try:
            async for raw in self._signaling_ws:
                msg = json.loads(raw)
                msg_type = msg.get("type")

                if msg_type == "welcome":
                    peers = msg.get("peers", [])
                    logger.info("Signaling connected, existing peers: %s", peers)
                    # If a browser is already waiting, create an offer
                    for peer in peers:
                        await self._create_and_send_offer(peer)

                elif msg_type == "peer_joined":
                    peer = msg["peer"]
                    logger.info("Browser peer joined: %s", peer[:16])
                    await self._create_and_send_offer(peer)

                elif msg_type == "signal":
                    from_peer = msg["from"]
                    data = msg["data"]
                    await self._handle_signal(from_peer, data)

                elif msg_type == "peer_left":
                    peer = msg["peer"]
                    logger.info("Browser peer left: %s", peer[:16])
                    if peer == self.peer_id:
                        self.state = "SIGNALING"
                        self.peer_id = None

        except Exception as exc:
            logger.error("Signaling loop error: %s", exc)

    async def _create_and_send_offer(self, peer_id: str) -> None:
        """Create an SDP offer and send it to the browser via signaling."""

        self.peer_id = peer_id

        offer = await self._pc.createOffer()
        await self._pc.setLocalDescription(offer)

        # Wait for ICE gathering to complete
        await self._wait_for_ice_gathering()

        # Send offer via signaling
        local_desc = self._pc.localDescription
        signal_data = {
            "sdp": local_desc.sdp,
            "type": local_desc.type,
            "media_type": "facetime",  # Distinguishes from data-only
        }

        # TODO: Sign SDP with CapAuth PGP (same as existing WebRTCTransport)
        # signal_data = self._sign_sdp(signal_data)

        await self._signaling_ws.send(
            json.dumps(
                {
                    "type": "signal",
                    "to": peer_id,
                    "data": signal_data,
                }
            )
        )

        logger.info("SDP offer sent to %s", peer_id[:16])

    async def _handle_signal(self, from_peer: str, data: dict) -> None:
        """Handle an incoming SDP answer or ICE candidate."""
        from aiortc import RTCIceCandidate, RTCSessionDescription

        if "sdp" in data:
            # SDP answer from browser
            answer = RTCSessionDescription(sdp=data["sdp"], type=data["type"])
            await self._pc.setRemoteDescription(answer)
            logger.info("SDP answer received from %s", from_peer[:16])

        elif "candidate" in data:
            # ICE candidate from browser
            candidate_data = data["candidate"]
            if candidate_data:
                # Parse ICE candidate string into RTCIceCandidate
                # aiortc expects specific fields
                candidate = RTCIceCandidate(
                    sdpMid=data.get("sdpMid"),
                    sdpMLineIndex=data.get("sdpMLineIndex"),
                    candidate=candidate_data,
                )
                await self._pc.addIceCandidate(candidate)

    async def _wait_for_ice_gathering(self, timeout: float = 10.0) -> None:
        """Wait for ICE gathering to complete."""
        if self._pc.iceGatheringState == "complete":
            return

        gathering_done = asyncio.Event()

        @self._pc.on("icegatheringstatechange")
        def on_gathering_state():
            if self._pc.iceGatheringState == "complete":
                gathering_done.set()

        try:
            await asyncio.wait_for(gathering_done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("ICE gathering timed out after %.1fs", timeout)

    # ──────────────────────────────────────────────────────────────────
    # Connection state handlers
    # ──────────────────────────────────────────────────────────────────

    def _on_connection_state_change(self) -> None:
        state = self._pc.connectionState
        logger.info("Connection state: %s", state)
        if state == "connected":
            self.state = "CONNECTED"
            self._connected_event.set()
        elif state in ("failed", "closed"):
            self.state = "CLOSED"

    def _on_ice_state_change(self) -> None:
        state = self._pc.iceConnectionState
        logger.info("ICE connection state: %s", state)

    def _on_channel_open(self) -> None:
        logger.info("Data channel 'skcomms' opened")

    def _on_channel_message(self, message: str) -> None:
        """Handle control messages from the browser via data channel."""
        try:
            msg = json.loads(message)
            msg_type = msg.get("type")

            if msg_type == "interrupt":
                # Browser requests speech interruption
                self.interrupt()
                logger.info("Speech interrupted by browser")

            elif msg_type == "ping":
                if self._channel:
                    self._channel.send(json.dumps({"type": "pong"}))

            else:
                logger.debug("Unknown data channel message type: %s", msg_type)

        except json.JSONDecodeError:
            logger.warning("Malformed data channel message")

    # ──────────────────────────────────────────────────────────────────
    # ICE / TURN configuration (mirrors WebRTCTransport)
    # ──────────────────────────────────────────────────────────────────

    def _build_ice_servers(self, RTCIceServer) -> list:
        """Build ICE server list. Same logic as WebRTCTransport."""
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
            else:
                logger.warning(
                    "TURN server configured but no secret provided. "
                    "TURN relay will not be available."
                )

        return servers

    def _derive_turn_credentials(self) -> tuple[str, str]:
        """Derive HMAC-SHA1 TURN credentials (RFC 5389 sec. 10.2).

        Returns:
            (username, credential) tuple for RTCIceServer.
        """
        # Username: timestamp:agent_name (expires in 24h)
        ttl = 86400
        expiry = int(time.time()) + ttl
        username = f"{expiry}:{self.agent_name}"

        # HMAC-SHA1 of username using the shared secret
        credential = hmac.new(
            self._turn_secret.encode(),
            username.encode(),
            hashlib.sha1,
        ).hexdigest()

        return username, credential

    def _prefer_h264(self, sender) -> None:
        """Set H.264 as the preferred video codec on a transceiver.

        Args:
            sender: RTCRtpSender for the video track.
        """
        try:
            from aiortc import RTCRtpSender

            capabilities = RTCRtpSender.getCapabilities("video")
            if capabilities:
                h264 = [c for c in capabilities.codecs if "H264" in c.mimeType]
                others = [c for c in capabilities.codecs if "H264" not in c.mimeType]
                if h264:
                    transceiver = next(
                        (t for t in self._pc.getTransceivers() if t.sender == sender),
                        None,
                    )
                    if transceiver:
                        transceiver.setCodecPreferences(h264 + others)
                        logger.info("H.264 set as preferred video codec")
        except Exception as exc:
            logger.debug("Could not set H.264 preference: %s", exc)

    async def _set_bandwidth(self, sender, max_bitrate: int) -> None:
        """Set maximum bitrate on an RTP sender.

        Args:
            sender: RTCRtpSender.
            max_bitrate: Maximum bitrate in bits per second.
        """
        try:
            params = sender.getParameters()
            if params.encodings:
                params.encodings[0].maxBitrate = max_bitrate
                await sender.setParameters(params)
        except Exception as e:
            logger.warning("webrtc_media.py: %s", e)
            pass  # Not all aiortc versions support this

    # ──────────────────────────────────────────────────────────────────
    # Portrait loading
    # ──────────────────────────────────────────────────────────────────

    def _load_portrait(self) -> Optional[np.ndarray]:
        """Load the agent's portrait image as a BGR numpy array.

        Returns:
            BGR numpy array, or None if no portrait is available.
        """
        if not self._portrait_path:
            return None

        path = Path(self._portrait_path).expanduser()
        if not path.exists():
            logger.warning("Portrait not found: %s", path)
            return None

        try:
            import cv2

            img = cv2.imread(str(path))
            if img is None:
                logger.warning("Failed to read portrait: %s", path)
                return None
            logger.info("Loaded portrait: %s (%dx%d)", path, img.shape[1], img.shape[0])
            return img
        except ImportError:
            logger.warning("cv2 not available, cannot load portrait")
            return None


class FaceTimeSessionManager:
    """Manages multiple concurrent FaceTime sessions (one per agent).

    Typically there is one FaceTimeSessionManager per GPU server, handling
    sessions for all agents. Only one active session at a time is recommended
    due to VRAM constraints (MuseTalk ~4-6 GB).

    Usage:
        manager = FaceTimeSessionManager(
            turn_secret="...",
            signaling_url="wss://...",
        )
        session = await manager.create_session("lumina")
        # ... use session ...
        await manager.destroy_session("lumina")
    """

    def __init__(
        self,
        signaling_url: Optional[str] = None,
        turn_server: Optional[str] = None,
        turn_secret: Optional[str] = None,
        portraits_base: Optional[str] = None,
    ):
        self._signaling_url = signaling_url
        self._turn_server = turn_server
        self._turn_secret = turn_secret
        self._portraits_base = portraits_base or str(Path.home() / ".skcapstone" / "agents")
        self._sessions: dict[str, FaceTimeSession] = {}
        # GPU semaphore: only one FaceTime session at a time
        self._gpu_lock = asyncio.Semaphore(1)

    async def create_session(self, agent_name: str, **kwargs) -> FaceTimeSession:
        """Create and start a FaceTime session for an agent.

        Acquires the GPU lock (blocks if another session is active).

        Args:
            agent_name: Agent name (e.g., "lumina").
            **kwargs: Additional arguments passed to FaceTimeSession.

        Returns:
            Started FaceTimeSession.
        """
        if agent_name in self._sessions:
            return self._sessions[agent_name]

        await self._gpu_lock.acquire()

        portrait_path = str(Path(self._portraits_base) / agent_name / "avatar" / "portrait.png")

        session = FaceTimeSession(
            agent_name=agent_name,
            portrait_path=portrait_path,
            signaling_url=self._signaling_url,
            turn_server=self._turn_server,
            turn_secret=self._turn_secret,
            **kwargs,
        )

        await session.start()
        self._sessions[agent_name] = session
        return session

    async def destroy_session(self, agent_name: str) -> None:
        """Stop and remove a FaceTime session.

        Releases the GPU lock.
        """
        session = self._sessions.pop(agent_name, None)
        if session:
            await session.stop()
            self._gpu_lock.release()

    def get_session(self, agent_name: str) -> Optional[FaceTimeSession]:
        """Get an active session for an agent, or None."""
        return self._sessions.get(agent_name)

    @property
    def active_agents(self) -> list[str]:
        """List of agents with active FaceTime sessions."""
        return list(self._sessions.keys())
