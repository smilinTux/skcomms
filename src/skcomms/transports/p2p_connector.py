"""Connector that drives a :class:`P2PSession` over a polling signaling backend.

Ties the sovereign mailbox signaling (``signaling_mailbox.MailboxSignaling``) — or
any object exposing ``send_signal(to_fqid, kind, payload)`` + ``poll_signals()`` — to
a :class:`P2PSession`. It wires the session's outbound ``send_signal`` to the backend
and runs a poll loop that feeds verified inbound signals into ``handle_signal``,
de-duplicating by signal id (the mailbox returns the cumulative inbox each poll).

Live path: opus and lumina each run a connector; the offerer calls ``start("offer")``,
the answerer ``start("answer")``; the data channel opens P2P with no SFU, signaling
carried by signed mailbox envelopes.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .p2p_session import P2PSession

logger = logging.getLogger("skcomms.p2p_connector")


class P2PConnector:
    """Drive a P2PSession to ``peer_fqid`` over a polling signaling backend.

    Args:
        peer_fqid: the peer to connect to (inbound signals from others are ignored).
        signaling: object with ``send_signal(to_fqid, kind, payload)`` and
            ``poll_signals() -> list[{from_fqid, kind, payload, id}]`` (e.g.
            ``MailboxSignaling``). ``send_signal`` may be sync (mailbox) or async.
        ice_servers: optional RTCIceServer-shaped dicts from the connectivity ladder.
        poll_interval: seconds between signaling polls.
    """

    def __init__(
        self,
        *,
        peer_fqid: str,
        signaling,
        ice_servers: Optional[list[dict]] = None,
        poll_interval: float = 0.5,
    ) -> None:
        self.peer_fqid = peer_fqid
        self.signaling = signaling
        self.poll_interval = poll_interval
        self.session = P2PSession(send_signal=self._send, ice_servers=ice_servers)
        self._poll_task: Optional[asyncio.Task] = None
        self._seen: set = set()

    async def _send(self, kind: str, payload: dict) -> None:
        result = self.signaling.send_signal(self.peer_fqid, kind, payload)
        if asyncio.iscoroutine(result):  # tolerate async backends
            await result

    async def _poll_loop(self) -> None:
        while True:
            try:
                for sig in self.signaling.poll_signals():
                    sid = sig.get("id")
                    if sid in self._seen:
                        continue
                    self._seen.add(sid)
                    if sig.get("from_fqid") != self.peer_fqid:
                        continue
                    await self.session.handle_signal(sig["kind"], sig["payload"])
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — a poll error must not kill the loop
                logger.warning("p2p connector poll error: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def start(self, role: str) -> None:
        """Begin polling; if ``role == 'offer'`` also create + send the offer."""
        if self._poll_task is None:
            self._poll_task = asyncio.create_task(self._poll_loop())
        if role == "offer":
            await self.session.call()

    async def wait_open(self, timeout: float = 20.0) -> None:
        await self.session.wait_open(timeout)

    def send(self, data) -> None:
        self.session.send(data)

    async def recv(self, timeout: float = 20.0):
        return await self.session.recv(timeout)

    @property
    def is_open(self) -> bool:
        return self.session.is_open

    async def close(self) -> None:
        if self._poll_task is not None:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        await self.session.close()
