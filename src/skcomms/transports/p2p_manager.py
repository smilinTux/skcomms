"""Session manager — the home for long-lived P2P sessions (sub-project B).

Holds a :class:`P2PSession` per peer, runs one route loop that polls the signaling
backend and dispatches inbound signals to the right session — auto-creating an
*answering* session when an unknown peer sends an offer (auto-answer). This is what
skchat's ``initiate_call`` (``call``) and ``accept_call`` / incoming-ring
(``on_session`` callback) drive.

Transport-agnostic: pass any ``SignalingChannel`` (the sovereign
:class:`MailboxSignaling` by default in skchat, or a broker via ``select_signaling``).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional

from .p2p_session import P2PSession

logger = logging.getLogger("skcomms.p2p_manager")


class P2PSessionManager:
    """Manage P2P sessions keyed by peer FQID, with one shared route loop.

    Args:
        signaling: a ``SignalingChannel`` (send_signal + poll_signals).
        ice_servers: optional RTCIceServer-shaped dicts (connectivity ladder).
        auto_answer: auto-create an answering session for an unknown peer's offer.
        poll_interval: seconds between signaling polls.
        on_session: optional ``(peer_fqid, P2PSession) -> None`` — fires when a
            session is created (outbound or inbound); use to surface an incoming ring.
    """

    def __init__(
        self,
        *,
        signaling,
        ice_servers: Optional[list[dict]] = None,
        auto_answer: bool = True,
        poll_interval: float = 0.3,
        on_session: Optional[Callable[[str, P2PSession], None]] = None,
    ) -> None:
        self._signaling = signaling
        self._ice = ice_servers
        self._auto = auto_answer
        self._poll_interval = poll_interval
        self._on_session = on_session
        self._sessions: dict[str, P2PSession] = {}
        self._seen: set = set()
        self._route_task: Optional[asyncio.Task] = None

    def _make_send(self, peer: str):
        async def _send(kind: str, payload: dict) -> None:
            result = self._signaling.send_signal(peer, kind, payload)
            if asyncio.iscoroutine(result):
                await result
        return _send

    def _new_session(self, peer: str) -> P2PSession:
        session = P2PSession(send_signal=self._make_send(peer), ice_servers=self._ice)
        self._sessions[peer] = session
        if self._on_session is not None:
            try:
                self._on_session(peer, session)
            except Exception as exc:  # noqa: BLE001 — callback must not break routing
                logger.debug("on_session callback error: %s", exc)
        return session

    async def start(self) -> None:
        """Begin the route loop (idempotent)."""
        if self._route_task is None:
            self._route_task = asyncio.create_task(self._route_loop())

    async def call(self, peer: str) -> P2PSession:
        """Place an outbound call to ``peer`` (we are the offerer)."""
        await self.start()
        session = self._sessions.get(peer) or self._new_session(peer)
        await session.call()
        return session

    def get(self, peer: str) -> Optional[P2PSession]:
        return self._sessions.get(peer)

    def active(self) -> list[str]:
        return list(self._sessions)

    async def _route_loop(self) -> None:
        while True:
            try:
                for sig in self._signaling.poll_signals():
                    sid = sig.get("id")
                    if sid in self._seen:
                        continue
                    self._seen.add(sid)
                    peer = sig.get("from_fqid")
                    kind = sig.get("kind")
                    session = self._sessions.get(peer)
                    if session is None:
                        if kind == "offer" and self._auto:
                            session = self._new_session(peer)
                        else:
                            continue  # answer/ice for an unknown session — ignore
                    await session.handle_signal(kind, sig.get("payload"))
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — a route error must not kill the loop
                logger.warning("p2p route error: %s", exc)
            await asyncio.sleep(self._poll_interval)

    async def hangup(self, peer: str) -> None:
        session = self._sessions.pop(peer, None)
        if session is not None:
            await session.close()

    async def close(self) -> None:
        if self._route_task is not None:
            self._route_task.cancel()
            try:
                await self._route_task
            except asyncio.CancelledError:
                pass
            self._route_task = None
        for session in list(self._sessions.values()):
            await session.close()
        self._sessions.clear()
