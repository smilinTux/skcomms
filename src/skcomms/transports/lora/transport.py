"""LoRaTransport (spec §4, §6) — ships skcomms envelopes over a LoRaMeshInterface
as signed, fragmented MeshPackets. category=OFFLINE; priority below the BLE mesh.

Meshtastic owns the mesh, so we set ttl=1 (no SMP relay). The async send/receive
methods are the real path; the sync Transport ABC methods bridge to them (the sync
`send` returns a failure SendResult pointing callers at send_async()).
"""

from __future__ import annotations

import os

from skcomms.transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)
from skcomms.transports.ble import gatt
from skcomms.transports.ble.identity import MeshIdentity
from skcomms.transports.ble.protocol import (
    FLAG_SIGNED,
    MeshPacket,
    PacketType,
)
from skcomms.transports.lora import framing
from skcomms.transports.lora.addressing import NodeMap
from skcomms.transports.lora.interface import LoRaMeshInterface


class LoRaTransport(Transport):
    name = "lora"
    priority = 60  # below the BLE SMP transport; above pure-internet fallbacks
    category = TransportCategory.OFFLINE

    def __init__(self, *, identity: MeshIdentity,
                 interface: LoRaMeshInterface | None,
                 node_map: NodeMap | None = None) -> None:
        self.identity = identity
        self.iface = interface
        self.nodes = node_map or NodeMap()
        self._inbox: list[bytes] = []
        self._reasm = framing.FrameReassembler()
        self._config: dict = {}
        if interface is not None:
            interface.on_receive(self._on_frame)

    # -- lifecycle --
    async def start(self) -> None:
        if self.iface is not None:
            await self.iface.start()

    async def stop(self) -> None:
        if self.iface is not None:
            await self.iface.stop()

    # -- async send/receive (the real path) --
    async def send_async(self, envelope_bytes: bytes, *, recipient: str) -> None:
        rid = self.identity_id_for(recipient)
        pkt = MeshPacket(
            type=PacketType.MESSAGE, ttl=1, flags=FLAG_SIGNED, timestamp=0,
            msg_id=os.urandom(8), sender_id=self.identity.my_id,
            recipient_id=rid, payload=envelope_bytes,
            signature=self.identity.sign(envelope_bytes),
        )
        dest = self.nodes.node_for(recipient)
        for frame in framing.to_frames(pkt):
            await self.iface.send_frame(frame, dest=dest)

    def identity_id_for(self, recipient: str):
        from skcomms.transports.ble.identity import id_hash
        return id_hash(recipient) if recipient else gatt.BROADCAST_ID

    def _on_frame(self, data: bytes, src: str) -> None:
        pkt = self._reasm.feed(data)
        if pkt is None:
            return
        # deliver payload (signature carried; verification wired in L4 once the
        # sender's Ed25519 pubkey is resolvable from pairing).
        self._inbox.append(pkt.payload)

    def receive(self) -> list[bytes]:
        out, self._inbox = self._inbox, []
        return out

    # -- Transport ABC --
    def configure(self, config: dict) -> None:
        self._config = dict(config or {})

    def is_available(self) -> bool:
        return self.iface is not None and getattr(self.iface, "running", False)

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        # LoRaTransport is async; the sync ABC path is not used. Return a failure
        # SendResult that points callers at send_async() rather than raising.
        return SendResult(
            success=False,
            transport_name=self.name,
            envelope_id="",
            error="LoRaTransport is async — use send_async()",
        )

    def health_check(self) -> HealthStatus:
        info = self.iface.info() if self.iface is not None else {}
        status = (TransportStatus.AVAILABLE if self.is_available()
                  else TransportStatus.UNAVAILABLE)
        return HealthStatus(
            transport_name=self.name,
            status=status,
            details=info,
        )
