"""Frame a MeshPacket for LoRa (spec §4): fragment to the LoRa MTU, reassemble.

Reuses the SMP packet codec (transports/ble/protocol). A LoRa frame == one
encoded MeshPacket (or fragment) that fits a Meshtastic data payload, tagged with
the SK portnum at the interface layer.
"""

from __future__ import annotations

from skcomms.transports.ble.protocol import MeshPacket, Reassembler, decode, fragment

SK_PORTNUM = 260          # Meshtastic PRIVATE_APP id for SK traffic
LORA_MTU = 200            # bytes; conservative, fits a Meshtastic data payload


def to_frames(packet: MeshPacket, *, mtu: int = LORA_MTU) -> list[bytes]:
    """Encode + fragment a MeshPacket into <=mtu LoRa frames."""
    return fragment(packet, mtu=mtu)


class FrameReassembler:
    """Feed received LoRa frames; returns the original MeshPacket once complete."""

    def __init__(self) -> None:
        self._r = Reassembler()

    def feed(self, frame: bytes) -> MeshPacket | None:
        try:
            pkt = decode(frame)
        except ValueError:
            return None
        return self._r.feed(pkt)
