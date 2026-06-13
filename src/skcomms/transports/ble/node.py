"""MeshNode — wires packet + relay + identity over a Radio (spec §3).

This is the orchestrator the FakeRadio tests drive to prove multi-hop delivery.
It deliberately does NOT do Noise encryption yet for broadcast traffic (broadcast
is signed-plaintext per spec §3); directed-message encryption rides on the Noise
session work and is exercised at the transport layer in P3. P1 proves routing.
"""

from __future__ import annotations

import os
from typing import Callable

from skcomms.transports.ble import gatt
from skcomms.transports.ble.identity import MeshIdentity
from skcomms.transports.ble.protocol import (
    MeshPacket,
    PacketType,
    decode,
    encode,
)
from skcomms.transports.ble.radio import Radio
from skcomms.transports.ble.relay import RelayEngine

MessageCb = Callable[[MeshPacket], None]


class MeshNode:
    def __init__(self, *, identity: MeshIdentity, radio: Radio) -> None:
        self.identity = identity
        self.radio = radio
        self.relay = RelayEngine(my_id=identity.my_id)
        self._on_message: MessageCb | None = None
        radio.on_receive(self._handle_frame)

    def on_message(self, cb: MessageCb) -> None:
        self._on_message = cb

    async def start(self) -> None:
        await self.radio.start()

    async def stop(self) -> None:
        await self.radio.stop()

    def _new_packet(self, recipient_id: bytes, payload: bytes,
                    ptype: PacketType = PacketType.MESSAGE) -> MeshPacket:
        return MeshPacket(
            type=ptype, ttl=gatt.DEFAULT_TTL, flags=0, timestamp=0,
            msg_id=os.urandom(8), sender_id=self.identity.my_id,
            recipient_id=recipient_id, payload=payload,
        )

    async def send_broadcast(self, payload: bytes) -> None:
        pkt = self._new_packet(gatt.BROADCAST_ID, payload)
        self.relay.consider(pkt)  # mark our own msg_id as seen (no self-loop)
        await self.radio.broadcast(encode(pkt))

    async def send_to(self, recipient_id: bytes, payload: bytes) -> None:
        pkt = self._new_packet(recipient_id, payload)
        self.relay.consider(pkt)
        await self.radio.broadcast(encode(pkt))

    def _handle_frame(self, data: bytes, src: str) -> None:
        try:
            pkt = decode(data)
        except ValueError:
            return
        decision = self.relay.consider(pkt)
        if decision.duplicate:
            return
        if decision.deliver_local and pkt.sender_id != self.identity.my_id:
            if self._on_message is not None:
                self._on_message(pkt)
        if decision.forward:
            # schedule rebroadcast of the TTL-decremented packet
            import asyncio
            asyncio.create_task(self.radio.broadcast(encode(decision.packet)))
