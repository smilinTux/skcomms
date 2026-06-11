"""Direct P2P WebRTC data-channel session (sub-project B).

A thin, transport-agnostic wrapper over an aiortc ``RTCPeerConnection`` that
establishes a direct peer-to-peer data channel with **no SFU and no signaling
server in the media path**. SDP is exchanged via an injected ``send_signal``
coroutine + the ``handle_signal`` dispatcher — so the same session works over the
sovereign mailbox backend (``signaling_mailbox.MailboxSignaling``) or the
low-latency broker ("if you need one, get two").

Non-trickle ICE: each side waits for ICE gathering to complete so the candidates
are embedded in the SDP, then sends one full offer/answer. This tolerates the
mailbox backend's batch (non-datagram) delivery and keeps loopback/LAN simple.

Media tracks (TTS audio, MuseTalk video) attach to the same ``self.pc`` in a
later slice (B3); this module owns the data channel + negotiation.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

logger = logging.getLogger("skcomms.p2p_session")

CHANNEL_LABEL = "skcomm"


class P2PSession:
    """One direct P2P link to a single peer.

    Args:
        send_signal: ``async (kind: str, payload: dict) -> None`` — delivers a
            signaling message ('offer'|'answer') to the peer. May be set after
            construction (wired once both ends exist).
        ice_servers: optional list of RTCIceServer-shaped dicts (from the
            connectivity tier ladder). Empty/None → host candidates only
            (tier 1 tailnet / LAN — direct, no relay).
        label: data channel label.
    """

    def __init__(
        self,
        *,
        send_signal: Optional[Callable[[str, dict], Awaitable[None]]] = None,
        ice_servers: Optional[list[dict]] = None,
        label: str = CHANNEL_LABEL,
    ) -> None:
        from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection

        if ice_servers:
            cfg = RTCConfiguration(
                iceServers=[RTCIceServer(**s) for s in ice_servers]
            )
            self.pc = RTCPeerConnection(cfg)
        else:
            self.pc = RTCPeerConnection()

        self._send_signal = send_signal
        self._label = label
        self.channel = None
        self._open = asyncio.Event()
        self._inbox: asyncio.Queue = asyncio.Queue()

        @self.pc.on("datachannel")
        def _on_datachannel(ch) -> None:  # answerer receives the channel
            self._bind_channel(ch)

    # -- channel wiring -----------------------------------------------------
    def _bind_channel(self, channel) -> None:
        self.channel = channel

        @channel.on("open")
        def _on_open() -> None:
            self._open.set()

        @channel.on("message")
        def _on_message(message) -> None:
            self._inbox.put_nowait(message)

        if getattr(channel, "readyState", None) == "open":
            self._open.set()

    # -- negotiation --------------------------------------------------------
    async def call(self) -> None:
        """Offerer: create the data channel, send a full (non-trickle) offer."""
        channel = self.pc.createDataChannel(self._label, ordered=True)
        self._bind_channel(channel)
        await self.pc.setLocalDescription(await self.pc.createOffer())
        await self._await_ice_complete()
        await self._emit("offer", self.pc.localDescription)

    async def handle_signal(self, kind: str, payload: dict) -> None:
        """Dispatch an inbound signaling message ('offer'|'answer')."""
        from aiortc import RTCSessionDescription

        if kind == "offer":
            await self.pc.setRemoteDescription(
                RTCSessionDescription(sdp=payload["sdp"], type="offer")
            )
            await self.pc.setLocalDescription(await self.pc.createAnswer())
            await self._await_ice_complete()
            await self._emit("answer", self.pc.localDescription)
        elif kind == "answer":
            await self.pc.setRemoteDescription(
                RTCSessionDescription(sdp=payload["sdp"], type="answer")
            )
        else:
            logger.debug("p2p: ignoring unknown signal kind %r", kind)

    async def _emit(self, kind: str, desc) -> None:
        if self._send_signal is None:
            raise RuntimeError("P2PSession.send_signal is not wired")
        await self._send_signal(kind, {"type": desc.type, "sdp": desc.sdp})

    async def _await_ice_complete(self) -> None:
        """Block until ICE gathering finishes (candidates are then in the SDP)."""
        while self.pc.iceGatheringState != "complete":
            await asyncio.sleep(0.05)

    # -- data plane ---------------------------------------------------------
    def send(self, data) -> None:
        if not self.channel or getattr(self.channel, "readyState", None) != "open":
            raise RuntimeError("data channel not open")
        self.channel.send(data)

    async def wait_open(self, timeout: float = 20.0) -> None:
        await asyncio.wait_for(self._open.wait(), timeout)

    async def recv(self, timeout: float = 20.0):
        return await asyncio.wait_for(self._inbox.get(), timeout)

    @property
    def is_open(self) -> bool:
        return self._open.is_set()

    async def close(self) -> None:
        try:
            await self.pc.close()
        except Exception as exc:  # noqa: BLE001 — close must not raise
            logger.debug("p2p: close error: %s", exc)
