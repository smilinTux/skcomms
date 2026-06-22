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
from typing import Awaitable, Callable, Optional

from .cot import CotEvent, parse_cot, to_cot

logger = logging.getLogger("skcomms.cot_server")

DEFAULT_COT_PORT = 8087  # TAK plain streaming (TLS is :8089, CB3)
_EVENT_RE = re.compile(rb"<event\b.*?</event>", re.DOTALL)

IngestHook = Callable[[CotEvent], Optional[Awaitable[None]]]


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
        host: str = "0.0.0.0",
        port: int = DEFAULT_COT_PORT,
        rebroadcast: bool = True,
    ) -> None:
        self._ingest = ingest
        self._host = host
        self._port = port
        self._rebroadcast = rebroadcast
        self._clients: set[asyncio.StreamWriter] = set()
        self._server: Optional[asyncio.AbstractServer] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def start(self) -> "CotStreamServer":
        """Start listening (call inside a running loop)."""
        self._loop = asyncio.get_running_loop()
        self._server = await asyncio.start_server(self._handle_client, self._host, self._port)
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
        logger.info("TAK client connected: %s (now %d)", peer, len(self._clients))
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

    async def _dispatch(self, cot: CotEvent, *, origin: asyncio.StreamWriter) -> None:
        if self._rebroadcast:
            await self._broadcast(cot, exclude=origin)
        if self._ingest is not None:
            try:
                res = self._ingest(cot)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:  # noqa: BLE001 — never let one event kill the stream
                logger.warning("CoT ingest hook failed for %s: %s", cot.uid, exc)

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
