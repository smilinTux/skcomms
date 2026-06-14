"""
WebSocket transport — real-time messaging for browser/mobile clients.

Maintains a persistent WebSocket connection to a SKComms relay server.
Authenticates with a CapAuth bearer token. Incoming messages are buffered
in a thread-safe queue; outgoing messages are written directly on the
open connection.

Protocol:
    - Client connects to ws(s)://server/skcomms/ws?agent=<name>
    - Authorization: Bearer <capauth_token> header on handshake
    - Messages exchanged as raw envelope bytes (JSON)
    - Heartbeat: periodic ping frames at configurable interval
    - Auto-reconnect: exponential backoff on disconnect

Connection model:
    A background daemon thread owns the persistent WebSocket connection.
    The main thread calls send() and receive() without blocking on I/O.
    A threading.Lock protects the connection reference during hand-off.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Optional

from ..transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

logger = logging.getLogger("skcomms.transports.websocket")

DEFAULT_URL = "ws://localhost:8765/skcomms/ws"
HEARTBEAT_INTERVAL = 30  # seconds between heartbeat pings
RECV_TIMEOUT = 1.0  # seconds for recv timeout (to check _running)
RECONNECT_DELAY_MIN = 2  # seconds initial backoff
RECONNECT_DELAY_MAX = 60  # seconds maximum backoff
CONNECT_SETTLE_TIME = 0.2  # seconds to wait after starting recv thread


class WebSocketTransport(Transport):
    """Real-time transport over a persistent WebSocket connection.

    Connects to a SKComms relay server. Authenticates via a CapAuth bearer
    token in the HTTP upgrade headers. A background daemon thread maintains
    the connection, buffers incoming envelopes, and sends heartbeat pings.

    Attributes:
        name: Always "websocket".
        priority: Default 2 (lower priority than syncthing file transport).
        category: REALTIME — low-latency direct network connection.
    """

    name: str = "websocket"
    priority: int = 2
    category: TransportCategory = TransportCategory.REALTIME

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        agent_name: Optional[str] = None,
        priority: int = 2,
        heartbeat_interval: int = HEARTBEAT_INTERVAL,
        auto_connect: bool = False,
        **kwargs,
    ):
        """Initialize the WebSocket transport.

        Args:
            url: WebSocket server URL. Defaults to ws://localhost:8765/skcomms/ws.
            token: CapAuth bearer token sent in the Authorization header.
            agent_name: This agent's name, appended as ?agent= query param.
            priority: Transport priority for routing (lower = higher priority).
            heartbeat_interval: Seconds between heartbeat pings.
            auto_connect: Start the background receiver thread immediately.
        """
        self._url = url or DEFAULT_URL
        self._token = token
        self._agent_name = agent_name
        self.priority = priority
        self._heartbeat_interval = heartbeat_interval

        self._ws = None  # websockets ClientConnection
        self._connected = False
        self._running = False
        self._connect_error: Optional[str] = None
        self._reconnect_count = 0
        self._last_ping: Optional[float] = None

        self._send_lock = threading.Lock()  # Serialises concurrent sends
        self._conn_lock = threading.Lock()  # Protects _ws reference
        self._inbox: queue.Queue[bytes] = queue.Queue(maxsize=10000)
        self._recv_thread: Optional[threading.Thread] = None

        if auto_connect:
            self.connect()

    # ------------------------------------------------------------------
    # Transport ABC implementation
    # ------------------------------------------------------------------

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys:
                url, token, agent_name, priority,
                heartbeat_interval, auto_connect.
        """
        was_running = self._running
        if was_running:
            self.disconnect()

        if "url" in config:
            self._url = config["url"]
        if "token" in config:
            self._token = config["token"]
        if "agent_name" in config:
            self._agent_name = config["agent_name"]
        if "priority" in config:
            self.priority = int(config["priority"])
        if "heartbeat_interval" in config:
            self._heartbeat_interval = int(config["heartbeat_interval"])

        if was_running or config.get("auto_connect", False):
            self.connect()

    def is_available(self) -> bool:
        """Return True if the WebSocket connection is currently active.

        Returns:
            True when connected and the background thread is running.
        """
        return self._connected

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Send an envelope via the open WebSocket connection.

        If not connected, returns a failure result immediately so the
        router can fall back to another transport.

        Args:
            envelope_bytes: Serialised MessageEnvelope bytes.
            recipient: Recipient identifier (informational; routing is
                       handled by the relay server).

        Returns:
            SendResult with success/failure and timing.
        """
        start = time.monotonic()
        envelope_id = self._extract_id(envelope_bytes)

        with self._conn_lock:
            ws = self._ws
            connected = self._connected

        if not ws or not connected:
            elapsed = (time.monotonic() - start) * 1000
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error="Not connected",
            )

        try:
            with self._send_lock:
                ws.send(envelope_bytes)
            elapsed = (time.monotonic() - start) * 1000
            logger.info(
                "Sent envelope %s to %s via WebSocket (%.1fms)",
                envelope_id[:8],
                recipient,
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
            logger.error("WebSocket send failed: %s", exc)
            with self._conn_lock:
                self._connected = False
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error=str(exc),
            )

    def receive(self) -> list[bytes]:
        """Drain all buffered incoming envelopes.

        The background receiver thread queues messages as they arrive.
        This method drains the queue non-blocking.

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
        """Detailed health and latency report.

        If connected, sends a ping and measures round-trip time.

        Returns:
            HealthStatus with connection state, latency, and details.
        """
        start = time.monotonic()

        if not self._running:
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.UNAVAILABLE,
                error="Transport not started (call connect())",
                details={"url": self._url, "connected": False},
            )

        with self._conn_lock:
            ws = self._ws
            connected = self._connected

        if not connected or not ws:
            latency = (time.monotonic() - start) * 1000
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.DEGRADED,
                latency_ms=latency,
                error=self._connect_error or "Disconnected",
                details={
                    "url": self._url,
                    "connected": False,
                    "reconnect_count": self._reconnect_count,
                },
            )

        # Measure ping round-trip
        try:
            ping_start = time.monotonic()
            ws.ping()
            ping_latency = (time.monotonic() - ping_start) * 1000
        except Exception as exc:
            logger.warning("websocket.py: %s", exc)
            latency = (time.monotonic() - start) * 1000
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.DEGRADED,
                latency_ms=latency,
                error=f"Ping failed: {exc}",
                details={"url": self._url, "connected": False},
            )

        return HealthStatus(
            transport_name=self.name,
            status=TransportStatus.AVAILABLE,
            latency_ms=ping_latency,
            details={
                "url": self._url,
                "connected": True,
                "reconnect_count": self._reconnect_count,
                "pending_inbox": self._inbox.qsize(),
            },
        )

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Start the background receiver thread.

        The thread manages the persistent connection, heartbeats, and
        auto-reconnect. Safe to call multiple times — no-op if running.

        Returns:
            True when the background thread has been started.
        """
        if self._running:
            return True

        self._running = True
        self._recv_thread = threading.Thread(
            target=self._receiver_loop,
            name="skcomms-ws-receiver",
            daemon=True,
        )
        self._recv_thread.start()

        # Allow the thread a moment to attempt the first connection
        time.sleep(CONNECT_SETTLE_TIME)
        return True

    def disconnect(self) -> None:
        """Stop the background thread and close the connection."""
        self._running = False

        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=5.0)

        with self._conn_lock:
            if self._ws:
                try:
                    self._ws.close()
                except Exception as e:
                    logger.warning("websocket.py: %s", e)
                    pass
                self._ws = None

        self._connected = False

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _receiver_loop(self) -> None:
        """Background thread: manage connection, buffer messages, heartbeat.

        Runs until self._running is False. On connection failure, waits
        with exponential backoff before reconnecting.
        """
        reconnect_delay = float(RECONNECT_DELAY_MIN)

        while self._running:
            try:
                self._connect_and_receive()
                reconnect_delay = float(RECONNECT_DELAY_MIN)  # Reset after clean exit

            except Exception as exc:
                with self._conn_lock:
                    self._connected = False
                    self._ws = None

                self._connect_error = str(exc)
                logger.warning(
                    "WebSocket connection error: %s — reconnecting in %.0fs",
                    exc,
                    reconnect_delay,
                )
                self._reconnect_count += 1

                # Interruptible sleep so disconnect() can stop us quickly
                deadline = time.monotonic() + reconnect_delay
                while self._running and time.monotonic() < deadline:
                    time.sleep(0.1)

                reconnect_delay = min(reconnect_delay * 2, RECONNECT_DELAY_MAX)

    def _connect_and_receive(self) -> None:
        """Open a WebSocket connection and run the receive loop.

        Raises:
            ImportError: If websockets is not installed.
            Exception: On connection failure or unexpected disconnect.
        """
        try:
            import websockets.sync.client as ws_sync
        except ImportError:
            self._connect_error = "websockets package not installed — pip install 'skcomms[nostr]'"
            logger.error(self._connect_error)
            self._running = False
            return

        url = self._build_url()
        headers = self._build_headers()

        logger.info("WebSocket connecting to %s", url)

        with ws_sync.connect(url, additional_headers=headers) as ws:
            with self._conn_lock:
                self._ws = ws
            self._connected = True
            self._connect_error = None
            self._last_ping = time.monotonic()
            logger.info("WebSocket connected to %s", url)

            try:
                while self._running:
                    self._maybe_send_heartbeat(ws)

                    try:
                        data = ws.recv(timeout=RECV_TIMEOUT)
                    except TimeoutError:
                        continue  # Normal — loop to check heartbeat/running

                    if isinstance(data, str):
                        data = data.encode()

                    try:
                        self._inbox.put_nowait(data)
                    except queue.Full:
                        logger.warning(
                            "WebSocket: inbox full (maxsize=%d), dropping %d-byte message",
                            self._inbox.maxsize,
                            len(data),
                        )
                        continue
                    logger.debug("Buffered WebSocket message (%d bytes)", len(data))

            finally:
                with self._conn_lock:
                    self._ws = None
                self._connected = False

    def _maybe_send_heartbeat(self, ws) -> None:
        """Send a heartbeat ping if the interval has elapsed.

        Args:
            ws: Open websockets ClientConnection.
        """
        now = time.monotonic()
        if self._last_ping is None or now - self._last_ping >= self._heartbeat_interval:
            try:
                ws.ping()
                self._last_ping = now
                logger.debug("WebSocket heartbeat ping sent")
            except Exception as exc:
                logger.warning("Heartbeat ping failed: %s", exc)
                raise

    def _build_url(self) -> str:
        """Construct the WebSocket URL with optional agent query param."""
        url = self._url
        if self._agent_name:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}agent={self._agent_name}"
        return url

    def _build_headers(self) -> dict:
        """Build HTTP headers for the WebSocket upgrade request."""
        headers: dict = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_id(envelope_bytes: bytes) -> str:
        """Best-effort extraction of envelope_id from raw bytes.

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
    url: Optional[str] = None,
    token: Optional[str] = None,
    agent_name: Optional[str] = None,
    priority: int = 2,
    heartbeat_interval: int = HEARTBEAT_INTERVAL,
    auto_connect: bool = False,
    **kwargs,
) -> WebSocketTransport:
    """Factory function for the router's transport loader.

    Args:
        url: WebSocket server URL.
        token: CapAuth bearer token for authentication.
        agent_name: This agent's name (sent as ?agent= query param).
        priority: Transport priority (lower = higher).
        heartbeat_interval: Seconds between heartbeat pings.
        auto_connect: Start background thread immediately.

    Returns:
        Configured WebSocketTransport instance.
    """
    return WebSocketTransport(
        url=url,
        token=token,
        agent_name=agent_name,
        priority=priority,
        heartbeat_interval=heartbeat_interval,
        auto_connect=auto_connect,
    )
