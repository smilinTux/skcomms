"""Tailscale transport — fast P2P messaging over the Tailscale mesh.

Sends envelope bytes directly over TCP to peer agents using their
Tailscale 100.x.x.x mesh IP addresses. When both agents are on the
same Tailscale tailnet (or Headscale network), this provides:

- Sub-millisecond LAN-equivalent latency even across continents
- No external relay required (Tailscale DERP is an automatic fallback)
- Works through corporate firewalls (Tailscale uses HTTPS port 443)
- Zero configuration once agents have joined the tailnet

Wire protocol:
    4-byte big-endian uint32 length prefix followed by the raw envelope
    bytes. One short-lived TCP connection per envelope (stateless delivery).

Availability:
    ``is_available()`` runs ``tailscale ip -4`` to confirm a 100.x.x.x
    address is assigned. Returns False gracefully if Tailscale is not
    installed or not connected — the router falls back transparently.

Peer IP discovery (in order of precedence):
    1. Manual: ``register_peer_ip(name, ip)`` at runtime
    2. Peer store: ``~/.skcomm/peers/<name>.yml`` → ``transports[].settings.tailscale_ip``
    3. Auto-detect: ``tailscale status --json`` hostname/DNS matching
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import struct
import subprocess
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

logger = logging.getLogger("skcomm.transports.tailscale")

LISTEN_PORT = 9385  # TCP port for incoming Tailscale envelopes
HEADER_SIZE = 4  # bytes for the big-endian uint32 length prefix
CONNECT_TIMEOUT = 5.0  # seconds for TCP connect
ACCEPT_TIMEOUT = 1.0  # seconds for server socket accept (interruptible)
MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50 MB — sanity limit


class TailscaleTransport(Transport):
    """Fast P2P transport using direct TCP over the Tailscale mesh.

    Establishes short-lived TCP connections to peer agents using their
    Tailscale 100.x.x.x addresses. A background thread listens for
    inbound connections and buffers them in a thread-safe queue.

    Falls back gracefully when Tailscale is not running, not installed,
    or a peer's Tailscale IP is unknown.

    Attributes:
        name: Always ``"tailscale"``.
        priority: Default 2 (second priority after WebRTC).
        category: ``REALTIME`` — selected by ``RoutingMode.SPEED``.
    """

    name: str = "tailscale"
    priority: int = 2
    category: TransportCategory = TransportCategory.REALTIME

    def __init__(
        self,
        listen_port: int = LISTEN_PORT,
        auto_detect: bool = True,
        priority: int = 2,
        **kwargs,
    ):
        """Initialize the Tailscale transport.

        Args:
            listen_port: TCP port to listen on for incoming envelopes.
                All tailnet peers must be able to reach this port.
            auto_detect: If True, discover peer IPs by querying
                ``tailscale status --json`` and matching hostnames.
            priority: Transport priority (lower = higher priority).
        """
        self._listen_port = listen_port
        self._auto_detect = auto_detect
        self.priority = priority

        self._running = False
        self._lifecycle_lock = threading.Lock()  # guards start/stop state transitions
        self._server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._inbox: queue.Queue[bytes] = queue.Queue(maxsize=10000)

        # Cached peer Tailscale IPs: name/fingerprint → 100.x.x.x
        self._peer_ips: dict[str, str] = {}
        self._peer_ips_lock = threading.Lock()

        # Local Tailscale IP (detected once on init, refreshed as needed)
        self._local_ip: Optional[str] = self._detect_local_ip()

    # ──────────────────────────────────────────────────────────────────────
    # Transport ABC implementation
    # ──────────────────────────────────────────────────────────────────────

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys: ``listen_port``, ``auto_detect``,
                ``priority``. Restart the listener if it was running.
        """
        with self._lifecycle_lock:
            was_running = self._running
        if was_running:
            self.stop()

        if "listen_port" in config:
            self._listen_port = int(config["listen_port"])
        if "auto_detect" in config:
            self._auto_detect = bool(config["auto_detect"])
        if "priority" in config:
            self.priority = int(config["priority"])

        self._local_ip = self._detect_local_ip()

        if was_running:
            self.start()

    def is_available(self) -> bool:
        """True if Tailscale is running and a 100.x.x.x IP is assigned.

        Returns:
            True when this machine has an active Tailscale connection.
        """
        if not self._local_ip:
            self._local_ip = self._detect_local_ip()
        return bool(self._local_ip)

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Send an envelope directly to a peer's Tailscale IP via TCP.

        Looks up the peer's 100.x.x.x address from the peer registry,
        peer store, or tailscale status. Opens a TCP connection, sends
        the length-prefixed envelope, and closes the connection.

        Args:
            envelope_bytes: Serialised MessageEnvelope bytes.
            recipient: Agent name, fingerprint, or Tailscale hostname.

        Returns:
            SendResult with success/failure and timing.
        """
        start = time.monotonic()
        envelope_id = self._extract_id(envelope_bytes)

        if not self.is_available():
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=(time.monotonic() - start) * 1000,
                error="Tailscale not available — not installed or not connected",
            )

        peer_ip = self._resolve_peer_ip(recipient)
        if not peer_ip:
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=(time.monotonic() - start) * 1000,
                error=f"No Tailscale IP known for '{recipient}'",
            )

        try:
            self._tcp_send(peer_ip, self._listen_port, envelope_bytes)
            elapsed = (time.monotonic() - start) * 1000
            logger.info(
                "Sent %d bytes to %s (%s) via Tailscale (%.1fms)",
                len(envelope_bytes),
                recipient,
                peer_ip,
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
            logger.warning("Tailscale send to %s (%s) failed: %s", recipient, peer_ip, exc)
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error=str(exc),
            )

    def receive(self) -> list[bytes]:
        """Drain all buffered incoming envelopes from the TCP listener.

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
        """Detailed health report for the Tailscale transport.

        Returns:
            HealthStatus with local IP, listener state, and known peers.
        """
        local_ip = self._detect_local_ip()
        if not local_ip:
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.UNAVAILABLE,
                error="Tailscale not running or not installed",
                details={"listen_port": self._listen_port},
            )

        with self._peer_ips_lock:
            known_peer_count = len(self._peer_ips)

        with self._lifecycle_lock:
            is_running = self._running

        return HealthStatus(
            transport_name=self.name,
            status=TransportStatus.AVAILABLE if is_running else TransportStatus.DEGRADED,
            details={
                "local_ip": local_ip,
                "listen_port": self._listen_port,
                "listener_running": is_running,
                "known_peers": known_peer_count,
                "inbox_pending": self._inbox.qsize(),
            },
        )

    # ──────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start the TCP listener thread.

        Uses ``_lifecycle_lock`` to prevent a TOCTOU race where two threads
        could both see ``_running == False`` and start duplicate listeners.

        Returns:
            True if started (or already running). False if Tailscale is absent.
        """
        with self._lifecycle_lock:
            if self._running:
                return True

            if not self.is_available():
                logger.debug("Tailscale not available — skipping listener start")
                return False

            self._running = True
            self._server_thread = threading.Thread(
                target=self._listen_loop,
                name="skcomm-tailscale-listener",
                daemon=True,
            )
            self._server_thread.start()
            logger.info(
                "Tailscale listener started on port %d (local IP: %s)",
                self._listen_port,
                self._local_ip,
            )
            return True

    def stop(self) -> None:
        """Stop the TCP listener and release the server socket.

        Uses ``_lifecycle_lock`` to prevent races with concurrent ``start()``
        calls and ensure the running flag and socket are updated atomically.
        """
        with self._lifecycle_lock:
            self._running = False

            if self._server_socket:
                try:
                    self._server_socket.close()
                except Exception as e:
                    logger.warning("tailscale.py: %s", e)
                    pass
                self._server_socket = None

        # Join outside the lock to avoid holding it during thread shutdown
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=3.0)

    def register_peer_ip(self, peer_name: str, tailscale_ip: str) -> None:
        """Manually register a peer's Tailscale IP address.

        Useful when auto-detection via hostname matching is ambiguous or when
        the peer store YAML is not yet configured.

        Args:
            peer_name: Agent name or fingerprint to register.
            tailscale_ip: The peer's 100.x.x.x Tailscale IP address.

        Raises:
            ValueError: If tailscale_ip is not a valid Tailscale address
                (must start with ``100.``).  Rejecting non-Tailscale IPs
                here prevents misconfiguration from silently routing traffic
                outside the mesh.
        """
        if not tailscale_ip.startswith("100."):
            raise ValueError(
                f"register_peer_ip: '{tailscale_ip}' is not a valid Tailscale IP "
                "(must start with 100.x.x.x)"
            )
        with self._peer_ips_lock:
            self._peer_ips[peer_name] = tailscale_ip
        logger.debug("Registered Tailscale peer: %s → %s", peer_name, tailscale_ip)

    # ──────────────────────────────────────────────────────────────────────
    # TCP listener (background thread)
    # ──────────────────────────────────────────────────────────────────────

    def _listen_loop(self) -> None:
        """Background thread: accept incoming TCP connections and buffer envelopes."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(("", self._listen_port))
            self._server_socket.listen(16)
            self._server_socket.settimeout(ACCEPT_TIMEOUT)
        except Exception as exc:
            logger.error(
                "Tailscale listener failed to bind port %d: %s",
                self._listen_port,
                exc,
            )
            with self._lifecycle_lock:
                self._running = False
            return

        while self._running:
            try:
                conn, addr = self._server_socket.accept()
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.warning("Tailscale listener accept error")

    def _handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        """Handle a single incoming TCP connection.

        Reads the 4-byte length header, reads that many bytes of envelope
        data, and puts it into the inbox queue.

        Args:
            conn: Accepted socket from the listener.
            addr: (host, port) of the connecting peer (informational).
        """
        try:
            conn.settimeout(30.0)

            header = self._recv_exact(conn, HEADER_SIZE)
            if len(header) < HEADER_SIZE:
                logger.debug("Tailscale: short header from %s — closing", addr[0])
                return

            msg_len = struct.unpack(">I", header)[0]
            if msg_len > MAX_MESSAGE_SIZE:
                logger.warning(
                    "Tailscale: oversized message (%d bytes) from %s — rejecting",
                    msg_len,
                    addr[0],
                )
                return

            data = self._recv_exact(conn, msg_len)
            if len(data) == msg_len:
                try:
                    self._inbox.put_nowait(data)
                except queue.Full:
                    logger.warning(
                        "Tailscale: inbox full (maxsize=%d), dropping %d-byte message from %s",
                        self._inbox.maxsize,
                        msg_len,
                        addr[0],
                    )
                    return
                logger.debug("Tailscale: buffered %d-byte envelope from %s", msg_len, addr[0])
        except Exception as exc:
            logger.debug("Tailscale connection from %s error: %s", addr[0], exc)
        finally:
            conn.close()

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        """Read exactly ``n`` bytes from a socket, handling short reads.

        Args:
            conn: Socket to read from.
            n: Number of bytes to read.

        Returns:
            Bytes read (may be shorter than ``n`` if connection closes).
        """
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # ──────────────────────────────────────────────────────────────────────
    # TCP send
    # ──────────────────────────────────────────────────────────────────────

    def _tcp_send(self, ip: str, port: int, data: bytes) -> None:
        """Open a TCP connection and write a length-prefixed envelope.

        Args:
            ip: Tailscale IP address of the target peer.
            port: Port to connect to (the peer's listener port).
            data: Raw envelope bytes to send.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect((ip, port))
            header = struct.pack(">I", len(data))
            sock.sendall(header + data)

    # ──────────────────────────────────────────────────────────────────────
    # Peer IP resolution
    # ──────────────────────────────────────────────────────────────────────

    def _resolve_peer_ip(self, recipient: str) -> Optional[str]:
        """Look up the Tailscale IP for a recipient agent.

        Checks (in order): manual registry → peer store YAML → tailscale status.

        Args:
            recipient: Agent name, fingerprint, or Tailscale hostname.

        Returns:
            A 100.x.x.x IP string, or None if not found.
        """
        # 1. Manual registry (fastest)
        with self._peer_ips_lock:
            ip = self._peer_ips.get(recipient)
        if ip:
            return ip

        # 2. Peer store YAML
        ip = self._peer_ip_from_store(recipient)
        if ip:
            with self._peer_ips_lock:
                self._peer_ips[recipient] = ip
            return ip

        # 3. Auto-detect from tailscale status JSON
        if self._auto_detect:
            ip = self._peer_ip_from_tailscale_status(recipient)
            if ip:
                with self._peer_ips_lock:
                    self._peer_ips[recipient] = ip
                return ip

        return None

    def _peer_ip_from_store(self, recipient: str) -> Optional[str]:
        """Look up the Tailscale IP from the SKComm peer store.

        The peer YAML should contain::

            transports:
              - transport: tailscale
                settings:
                  tailscale_ip: "100.64.x.y"

        Args:
            recipient: Agent name or fingerprint.

        Returns:
            IP string from the peer store, or None.
        """
        try:
            from skcomms.discovery import PeerStore

            store = PeerStore()
            peer = store.get(recipient)
            if peer:
                for t in peer.transports:
                    if t.transport == "tailscale":
                        return t.settings.get("tailscale_ip")
        except Exception as e:
            logger.warning("tailscale.py: %s", e)
            pass
        return None

    def _peer_ip_from_tailscale_status(self, recipient: str) -> Optional[str]:
        """Discover a peer's Tailscale IP by querying ``tailscale status --json``.

        Matches the recipient string against peer ``HostName`` (exact match,
        case-insensitive) and ``DNSName`` (recipient must be the first label
        before the first dot). This prevents false positives from substring
        matching (e.g. "ops" matching "devops-server").

        Args:
            recipient: Hostname or agent name to match exactly.

        Returns:
            First matching 100.x.x.x IP, or None.
        """
        try:
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if result.returncode != 0:
                return None

            data = json.loads(result.stdout)
            for _node_key, info in data.get("Peer", {}).items():
                hostname = info.get("HostName", "").lower()
                dns_name = info.get("DNSName", "").lower()
                recipient_lower = recipient.lower()

                # Exact match on hostname, or dns_name starts with recipient + "."
                # (e.g. recipient "opus" matches dns_name "opus.tail1234.ts.net.")
                if recipient_lower == hostname or dns_name.startswith(recipient_lower + "."):
                    for ip in info.get("TailscaleIPs", []):
                        if ip.startswith("100."):
                            return ip
        except Exception as exc:
            logger.debug("tailscale status lookup failed: %s", exc)

        return None

    # ──────────────────────────────────────────────────────────────────────
    # Local IP detection
    # ──────────────────────────────────────────────────────────────────────

    def _detect_local_ip(self) -> Optional[str]:
        """Detect this machine's Tailscale IPv4 address via ``tailscale ip -4``.

        Returns:
            A 100.x.x.x IP string, or None if Tailscale is absent/offline.
        """
        try:
            result = subprocess.run(
                ["tailscale", "ip", "-4"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            if result.returncode == 0:
                ip = result.stdout.strip()
                if ip.startswith("100."):
                    return ip
        except FileNotFoundError:
            logger.debug("tailscale binary not found — Tailscale transport unavailable")
        except Exception as exc:
            logger.debug("tailscale ip -4 failed: %s", exc)
        return None

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
    listen_port: int = LISTEN_PORT,
    auto_detect: bool = True,
    priority: int = 2,
    **kwargs,
) -> TailscaleTransport:
    """Factory function called by the SKComm router transport loader.

    Args:
        listen_port: TCP port for the inbound listener thread.
        auto_detect: Discover peer IPs from ``tailscale status --json``.
        priority: Transport priority (lower = higher priority in routing).

    Returns:
        Configured TailscaleTransport instance.
    """
    return TailscaleTransport(
        listen_port=listen_port,
        auto_detect=auto_detect,
        priority=priority,
    )
