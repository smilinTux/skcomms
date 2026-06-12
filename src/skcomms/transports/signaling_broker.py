"""Broker signaling backend — the low-latency fast path (sub-project B, 'get two').

Wraps the existing WebSocket relay broker (``signaling.py``) behind the same
:class:`~skcomms.transports.signaling_base.SignalingChannel` interface as the
sovereign :class:`MailboxSignaling`, so a :class:`P2PSessionManager` can use either
(``select_signaling`` prefers this when reachable, else falls back to the mailbox).

Wire protocol (relay only — no media through the broker):
    out:  {"type":"signal","to":"<fp>","data":{"kind":..., "payload":...}}
    in:   {"type":"signal","from":"<fp>","data":{"kind":..., "payload":...}}
The broker relays ``data`` opaquely, so the new stack's ``{kind, payload}`` rides
inside it. Addressing is by fingerprint, so the adapter maps FQID<->fingerprint via
injected resolvers (TOFU in production, stubs in tests).

The broker is async (a WebSocket); the SignalingChannel interface is poll-based, so
a background reader drains inbound frames into a deque that ``poll_signals`` returns.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
from typing import Callable, Optional

logger = logging.getLogger("skcomms.signaling_broker")


class BrokerSignaling:
    """SignalingChannel over the WebSocket relay broker.

    Args:
        ws: an open async websocket with ``await ws.send(str)`` and
            ``await ws.recv() -> str`` (e.g. a ``websockets`` client).
        fqid_to_fp: ``(fqid) -> fingerprint`` (TOFU lookup in production).
        fp_to_fqid: ``(fingerprint) -> fqid`` (reverse lookup).
    """

    def __init__(
        self,
        *,
        ws,
        fqid_to_fp: Callable[[str], str],
        fp_to_fqid: Callable[[str], str],
    ) -> None:
        self._ws = ws
        self._fqid_to_fp = fqid_to_fp
        self._fp_to_fqid = fp_to_fqid
        self._recv: collections.deque = collections.deque()
        self._reader: Optional[asyncio.Task] = None
        self._connected = False
        self._n = 0

    def is_reachable(self) -> bool:
        return self._connected

    async def start(self) -> None:
        """Mark reachable + start the background reader (idempotent)."""
        self._connected = True
        if self._reader is None:
            self._reader = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while True:
                raw = await self._ws.recv()
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if msg.get("type") != "signal":
                    continue  # welcome / peer_joined / peer_left / cancel_ice — ignore
                data = msg.get("data") or {}
                self._n += 1
                self._recv.append({
                    "from_fqid": self._fp_to_fqid(msg.get("from", "")),
                    "kind": data.get("kind"),
                    "payload": data.get("payload"),
                    "id": f"broker-{self._n}",
                })
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a closed socket just ends the reader
            self._connected = False
            logger.debug("broker reader stopped: %s", exc)

    async def send_signal(self, to_fqid: str, kind: str, payload: dict) -> dict:
        to_fp = self._fqid_to_fp(to_fqid)
        await self._ws.send(json.dumps({
            "type": "signal",
            "to": to_fp,
            "data": {"kind": kind, "payload": payload},
        }))
        return {"id": f"sent-{to_fp[:8]}-{kind}"}

    def poll_signals(self) -> list:
        """Drain + return inbound signals (single-consumer; the manager de-dups by id)."""
        out = list(self._recv)
        self._recv.clear()
        return out

    async def close(self) -> None:
        self._connected = False
        if self._reader is not None:
            self._reader.cancel()
            try:
                await self._reader
            except asyncio.CancelledError:
                pass
            self._reader = None
