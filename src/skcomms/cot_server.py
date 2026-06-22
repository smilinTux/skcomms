"""[CoT][CB2] TAK-server-compatible CoT streaming endpoint.

ATAK/iTAK/WinTAK connect to a "TAK Server" over a streaming TCP socket and
exchange **CoT** ``<event>`` XML documents back-to-back. This module implements
that streaming endpoint so a real TAK client can connect to a SKFed node:

  * inbound CoT  → parsed (CB1 codec) → handed to an ``ingest`` hook (which
    wraps it in the canonical signed Envelope and federates it) AND
    re-broadcast to the other connected TAK clients (local-TAK-server behavior),
  * outbound CoT (federation-inbound, or anything the node wants the operators
    to see) → :meth:`CotStreamServer.inject` pushes it to all connected clients.

Plain TCP (default :8087) here; TLS (:8089) + per-device capauth identity is
CB3. The server is rail-agnostic about ingest — it just speaks the wire and
calls back, so CB2 doesn't entangle with the federation send path.

TAK's classic XML streaming has no length framing: events are self-delimiting
``<event …>…</event>`` documents (optionally newline-separated, optionally with
an ``<?xml?>`` prologue). :func:`extract_events` buffers and splits them safely.
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
from typing import Awaitable, Callable, Optional

from .cot import CotEvent, parse_cot, to_cot

logger = logging.getLogger("skcomms.cot_server")

DEFAULT_COT_PORT = 8087  # TAK plain streaming (TLS is :8089, CB3)
DEFAULT_COT_TLS_PORT = 8089  # TAK SSL streaming (CB3 enrolled-server flow)
_EVENT_RE = re.compile(rb"<event\b.*?</event>", re.DOTALL)

IngestHook = Callable[[CotEvent], Optional[Awaitable[None]]]
# (cot, device_identity, fingerprint) — TLS ingest hook variant carrying the
# per-device identity extracted + TOFU-pinned from the client cert (CB3).
IdentIngestHook = Callable[[CotEvent, str, Optional[str]], Optional[Awaitable[None]]]


def extract_events(buf: bytes) -> tuple[list[bytes], bytes]:
    """Split a byte buffer into complete ``<event>…</event>`` docs + remainder.

    Returns ``(events, remaining)`` where ``events`` are complete event byte
    strings and ``remaining`` is the trailing partial (kept for the next read).
    """
    events: list[bytes] = []
    last = 0
    for m in _EVENT_RE.finditer(buf):
        events.append(m.group(0))
        last = m.end()
    return events, buf[last:]


class CotStreamServer:
    """An asyncio TAK-compatible CoT streaming server.

    Args:
        ingest: Optional callback invoked for each inbound :class:`CotEvent`
            (sync or async). This is where a caller wraps the CoT in the
            canonical Envelope and federates it (``cot_to_envelope`` + send).
        host/port: Bind address (default ``0.0.0.0:8087``; bind the tailnet in
            production — firewalld tailscale0 is trusted).
        rebroadcast: If True (default), inbound CoT is relayed to the OTHER
            connected clients (local TAK-server fan-out).
    """

    def __init__(
        self,
        *,
        ingest: Optional[IngestHook] = None,
        ident_ingest: Optional[IdentIngestHook] = None,
        host: str = "0.0.0.0",
        port: int = DEFAULT_COT_PORT,
        rebroadcast: bool = True,
    ) -> None:
        self._ingest = ingest
        self._ident_ingest = ident_ingest
        self._host = host
        self._port = port
        self._rebroadcast = rebroadcast
        self._clients: set[asyncio.StreamWriter] = set()
        self._server: Optional[asyncio.AbstractServer] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        """SSLContext for the listener (None = plain TCP). CB3 overrides this."""
        return None

    async def start(self) -> "CotStreamServer":
        """Start listening (call inside a running loop)."""
        self._loop = asyncio.get_running_loop()
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._port, ssl=self._ssl_context()
        )
        sockets = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
        logger.info("CoT stream server listening on %s", sockets)
        return self

    async def stop(self) -> None:
        for w in list(self._clients):
            with _suppress():
                w.close()
        self._clients.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        self._clients.add(writer)
        # CB3 subclasses populate a per-connection identity; plain TCP has none.
        identity = self._connection_identity(writer)
        logger.info(
            "TAK client connected: %s%s (now %d)",
            peer, f" as {identity}" if identity else "", len(self._clients),
        )
        buf = b""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                buf += data
                events, buf = extract_events(buf)
                for raw in events:
                    try:
                        cot = parse_cot(raw)
                    except ValueError as exc:
                        logger.debug("dropping malformed CoT from %s: %s", peer, exc)
                        continue
                    await self._dispatch(cot, origin=writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self._clients.discard(writer)
            with _suppress():
                writer.close()
            logger.info("TAK client disconnected: %s (now %d)", peer, len(self._clients))

    def _connection_identity(self, writer: asyncio.StreamWriter) -> Optional[str]:
        """Device identity attributed to a connection (None for plain TCP).

        CB3 (the TLS server) overrides this to return the TOFU-pinned identity
        derived from the presented client certificate.
        """
        return None

    async def _dispatch(self, cot: CotEvent, *, origin: asyncio.StreamWriter) -> None:
        # TAK keepalive: ATAK/WinTAK send a periodic ping (type t-x-c-t) and drop
        # the link (~20-30s) if the server doesn't pong (t-x-c-t-r). Answer it
        # point-to-point; don't rebroadcast/ingest pings.
        if cot.type.startswith("t-x-c-t") and not cot.type.startswith("t-x-c-t-r"):
            await self._send_pong(origin)
            return
        if self._rebroadcast:
            await self._broadcast(cot, exclude=origin)
        identity = self._connection_identity(origin)
        if self._ingest is not None:
            try:
                res = self._ingest(cot)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:  # noqa: BLE001 — never let one event kill the stream
                logger.warning("CoT ingest hook failed for %s: %s", cot.uid, exc)
        if self._ident_ingest is not None:
            try:
                fp = self._connection_fingerprint(origin)
                res = self._ident_ingest(cot, identity or "anonymous", fp)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:  # noqa: BLE001
                logger.warning("CoT ident-ingest hook failed for %s: %s", cot.uid, exc)

    def _connection_fingerprint(self, writer: asyncio.StreamWriter) -> Optional[str]:
        """Client-cert fingerprint for a connection (None for plain TCP)."""
        return None

    async def _broadcast(self, cot: CotEvent, *, exclude: Optional[asyncio.StreamWriter] = None) -> None:
        data = (to_cot(cot) + "\n").encode("utf-8")
        for w in list(self._clients):
            if w is exclude:
                continue
            try:
                w.write(data)
                await w.drain()
            except (ConnectionError, RuntimeError):
                self._clients.discard(w)

    async def _send_pong(self, writer: asyncio.StreamWriter) -> None:
        """Reply to a TAK ping with a pong (keeps ATAK/WinTAK connected)."""
        from .cot import CotPoint

        pong = CotEvent(uid="takPong", type="t-x-c-t-r", how="m-g", point=CotPoint())
        try:
            writer.write((to_cot(pong) + "\n").encode("utf-8"))
            await writer.drain()
        except (ConnectionError, RuntimeError):
            self._clients.discard(writer)

    async def push(self, cot: CotEvent) -> None:
        """Push a CoT event to ALL connected clients (e.g. federation-inbound)."""
        await self._broadcast(cot, exclude=None)

    def inject(self, cot: CotEvent) -> None:
        """Thread-safe :meth:`push` — schedule a broadcast onto the server loop.

        Use from outside the event loop (e.g. the federation receive path
        handing a remote node's CoT to local TAK operators).
        """
        if self._loop is None:
            return
        self._loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self.push(cot)))


def _cert_fingerprint_from_der(der: bytes) -> str:
    """SHA-256 fingerprint of a DER cert as ``AA:BB:...`` uppercase hex."""
    import hashlib

    digest = hashlib.sha256(der).digest()
    return ":".join(f"{b:02X}" for b in digest)


class TlsCotStreamServer(CotStreamServer):
    """[CoT][CB3] TLS-enrolled TAK streaming server (:8089).

    Serves the same CoT stream as :class:`CotStreamServer` but over TLS, with
    mutual-TLS-style **client-cert identity binding**:

      * the listener uses an :class:`ssl.SSLContext` built from the node's server
        cert + the CoT CA, with ``verify_mode=CERT_OPTIONAL`` so a presented
        client cert is read (and verified against the CA) without *requiring* one
        — plain reachability checks / phones mid-enrollment still connect;
      * on connect, the client cert is extracted (``getpeercert(binary_form)``),
        SHA-256-fingerprinted, **TOFU-pinned** (:mod:`skcomms.tofu`) under the
        device identity (``<cn>@<operator>.<realm>``), and that identity is
        attributed to every CoT the connection ingests via the ``ident_ingest``
        hook. A TOFU **conflict** (a different cert for a known device handle) is
        rejected — the connection is dropped.

    The plain :class:`CotStreamServer` on :8087 keeps working unchanged; run both.

    Args:
        server_cert/server_key/ca_cert: PEM paths (from :mod:`skcomms.cot_pki`).
            Default to the standard ``cot-pki/`` locations, creating them on
            first start if absent.
        require_client_cert: If True, use ``CERT_REQUIRED`` (reject certless
            clients). Default False (``CERT_OPTIONAL``) per the CB3 spec.
    """

    def __init__(
        self,
        *,
        ingest: Optional[IngestHook] = None,
        ident_ingest: Optional[IdentIngestHook] = None,
        host: str = "0.0.0.0",
        port: int = DEFAULT_COT_TLS_PORT,
        rebroadcast: bool = True,
        server_cert: Optional[str] = None,
        server_key: Optional[str] = None,
        ca_cert: Optional[str] = None,
        require_client_cert: bool = False,
    ) -> None:
        super().__init__(
            ingest=ingest, ident_ingest=ident_ingest, host=host, port=port,
            rebroadcast=rebroadcast,
        )
        self._server_cert = server_cert
        self._server_key = server_key
        self._ca_cert = ca_cert
        self._require_client_cert = require_client_cert
        # writer-id -> (identity, fingerprint) for the lifetime of the connection
        self._conn_identity: dict[int, tuple[str, str]] = {}

    def _resolve_pki_paths(self) -> tuple[str, str, str]:
        """Resolve (server_cert, server_key, ca_cert), creating PKI if needed."""
        from . import cot_pki

        if self._server_cert and self._server_key and self._ca_cert:
            return self._server_cert, self._server_key, self._ca_cert
        cot_pki.init_ca()
        sp, sk = cot_pki.init_server_cert()
        ca = cot_pki.pki_dir() / "ca.pem"
        return (
            self._server_cert or str(sp),
            self._server_key or str(sk),
            self._ca_cert or str(ca),
        )

    def _ssl_context(self) -> ssl.SSLContext:
        server_cert, server_key, ca_cert = self._resolve_pki_paths()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
        ctx.load_verify_locations(cafile=ca_cert)
        ctx.verify_mode = (
            ssl.CERT_REQUIRED if self._require_client_cert else ssl.CERT_OPTIONAL
        )
        # SNI: strict clients (iTAK) that can't import our CA connect by hostname
        # and get a publicly-trusted cert (e.g. `tailscale cert`); ATAK connects
        # by IP and gets the PKI cert (its data-package CA validates it). One
        # listener, one client pool, so everyone shares the same SA picture.
        import os as _os

        sni_cert = _os.environ.get("SKCOMMS_COT_SNI_CERT")
        sni_key = _os.environ.get("SKCOMMS_COT_SNI_KEY")
        sni_name = _os.environ.get("SKCOMMS_COT_SNI_NAME")
        if sni_cert and sni_key and sni_name:
            alt = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            alt.load_cert_chain(certfile=sni_cert, keyfile=sni_key)
            alt.load_verify_locations(cafile=ca_cert)
            alt.verify_mode = ctx.verify_mode

            def _sni(sslobj, server_name, _ctx):
                if server_name == sni_name:
                    sslobj.context = alt

            ctx.sni_callback = _sni
        return ctx

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Extract + TOFU-pin the client cert BEFORE serving the stream.
        ident, fp = self._extract_identity(writer)
        if ident is None:
            # CERT_OPTIONAL: certless connections are allowed but anonymous.
            logger.info("TLS TAK client without client cert: %s", writer.get_extra_info("peername"))
        else:
            from .tofu import verify_fingerprint

            result = verify_fingerprint(ident, fp)
            if not result.trusted:
                logger.warning(
                    "TLS client cert TOFU CONFLICT for %s (stored=%s presented=%s) — dropping",
                    ident, result.stored_fingerprint, fp,
                )
                with _suppress():
                    writer.close()
                return
            self._conn_identity[id(writer)] = (ident, fp)
            logger.info("TLS TAK client cert pinned: %s (%s, %s)", ident, result.status.value, fp)
        try:
            await super()._handle_client(reader, writer)
        finally:
            self._conn_identity.pop(id(writer), None)

    def _extract_identity(
        self, writer: asyncio.StreamWriter
    ) -> tuple[Optional[str], Optional[str]]:
        """Pull (device_identity, fingerprint) from the connection's client cert."""
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None, None
        der = ssl_obj.getpeercert(binary_form=True)
        if not der:
            return None, None
        fp = _cert_fingerprint_from_der(der)
        cn = self._cn_from_der(der)
        from .cot_pki import device_identity

        ident = device_identity(cn) if cn else f"device:fp:{fp[:17]}"
        return ident, fp

    @staticmethod
    def _cn_from_der(der: bytes) -> Optional[str]:
        """Extract the subject CN from a DER client cert (the device handle)."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID

            cert = x509.load_der_x509_certificate(der)
            attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None
        except Exception:  # noqa: BLE001
            return None

    def _connection_identity(self, writer: asyncio.StreamWriter) -> Optional[str]:
        ent = self._conn_identity.get(id(writer))
        return ent[0] if ent else None

    def _connection_fingerprint(self, writer: asyncio.StreamWriter) -> Optional[str]:
        ent = self._conn_identity.get(id(writer))
        return ent[1] if ent else None


TAK_MESH_GROUP = "239.2.3.1"  # ATAK default "Mesh SA" multicast group
TAK_MESH_PORT = 6969


class _MeshProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_datagram: Callable[[bytes, tuple], None]) -> None:
        self._on_datagram = on_datagram

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._on_datagram(data, addr)


class UdpMeshListener:
    """Listen on the ATAK mesh multicast group — no server/auth needed.

    Mesh-mode ATAK (the default with "Mesh Network enabled") broadcasts CoT over
    UDP multicast on the LAN. Joining that group lets a node ingest a phone's
    position/chat/markers with zero phone-side config — but multicast does NOT
    cross Tailscale, so the node must share the phone's WiFi/LAN.

    Args:
        on_event: callback(CotEvent) for each decoded mesh CoT.
        group/port: multicast group + port (ATAK defaults 239.2.3.1:6969).
    """

    def __init__(
        self,
        *,
        on_event: Callable[[CotEvent], Optional[Awaitable[None]]],
        group: str = TAK_MESH_GROUP,
        port: int = TAK_MESH_PORT,
    ) -> None:
        self._on_event = on_event
        self._group = group
        self._port = port
        self._transport: Optional[asyncio.BaseTransport] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def start(self) -> "UdpMeshListener":
        import socket
        import struct

        self._loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self._port))
        mreq = struct.pack("=4sl", socket.inet_aton(self._group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        self._transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _MeshProtocol(self._handle), sock=sock
        )
        logger.info("CoT mesh listener joined %s:%d", self._group, self._port)
        return self

    def _handle(self, data: bytes, addr: tuple) -> None:
        from .cot import parse_cot_datagram

        cot = parse_cot_datagram(data)
        if cot is None:
            logger.debug("undecodable mesh datagram from %s (%d bytes)", addr, len(data))
            return
        res = self._on_event(cot)
        if asyncio.iscoroutine(res):
            asyncio.ensure_future(res)

    def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()


def _federation_peer_fqids() -> list[str]:
    """Default peer set for CoT fan-out: federation peers with an inbox_url."""
    try:
        from .discovery import PeerStore

        return [p.fqid for p in PeerStore().list_all() if p.fqid and p.inbox_url()]
    except Exception:  # noqa: BLE001
        return []


def federation_ingest(
    skcomms,
    *,
    from_fqid: str,
    peers_provider: Optional[Callable[[], list[str]]] = None,
):
    """Build a CB2 ingest hook that federates inbound CoT to peer nodes.

    CoT is broadcast-by-default, so each inbound :class:`CotEvent` is wrapped in
    the canonical signed Envelope (``application/cot+xml``) and **fanned out**
    via ``skcomms.send_federated`` to every federation peer — where that node's
    own CoT server :meth:`CotStreamServer.inject`s it to its TAK operators.

    Args:
        skcomms: an SKComms (must expose ``send_federated``).
        from_fqid: this node/agent's FQID (the CoT's signed origin; CB3 refines
            this to the actual device identity).
        peers_provider: returns the recipient FQIDs (default: all federation
            peers from the PeerStore).
    """
    provider = peers_provider or _federation_peer_fqids

    def hook(cot: CotEvent) -> None:
        body = to_cot(cot)
        for peer_fqid in provider():
            try:
                skcomms.send_federated(peer_fqid, body, content_type="application/cot+xml")
            except Exception as exc:  # noqa: BLE001
                logger.warning("CoT federate to %s failed: %s", peer_fqid, exc)

    return hook


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return True
