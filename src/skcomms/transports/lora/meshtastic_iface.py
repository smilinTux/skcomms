"""MeshtasticInterface (spec §4) — the real LoRa radio backend.

Talks to a Meshtastic node via the `meshtastic` lib (serial/USB by default; TCP/BLE
selectable). SK frames use a dedicated portnum so they demux from ordinary
Meshtastic traffic on a shared mesh. The `meshtastic` import is LAZY (only in
start()) so this module imports + constructs on a box without the dep (L1); the
live radio test is L2.
"""

from __future__ import annotations

from skcomms.transports.lora import framing
from skcomms.transports.lora.interface import LoRaMeshInterface, ReceiveCb


class MeshtasticInterface(LoRaMeshInterface):
    def __init__(self, *, device: str = "/dev/ttyUSB0", tcp_host: str | None = None) -> None:
        self.device = device
        self.tcp_host = tcp_host
        self._cb: ReceiveCb | None = None
        self._iface = None
        self.running = False

    async def start(self) -> None:
        import meshtastic.serial_interface as si
        import meshtastic.tcp_interface as ti
        from pubsub import pub
        self._iface = (ti.TCPInterface(self.tcp_host) if self.tcp_host
                       else si.SerialInterface(self.device))
        pub.subscribe(self._on_meshtastic_receive, "meshtastic.receive.data")
        self.running = True

    async def stop(self) -> None:
        if self._iface is not None:
            self._iface.close()
        self.running = False

    async def send_frame(self, data: bytes, *, dest: str | None) -> None:
        if self._iface is None:
            raise RuntimeError("interface not started")
        self._iface.sendData(data, destinationId=dest or "^all",
                             portNum=framing.SK_PORTNUM)

    def on_receive(self, cb: ReceiveCb) -> None:
        self._cb = cb

    def _on_meshtastic_receive(self, packet=None, interface=None) -> None:
        if not packet:
            return
        decoded = packet.get("decoded", {})
        if decoded.get("portnum") != framing.SK_PORTNUM and \
           decoded.get("portnum") != "PRIVATE_APP":
            return
        payload = decoded.get("payload")
        src = str(packet.get("fromId") or packet.get("from") or "")
        if payload and self._cb is not None:
            self._cb(bytes(payload), src)

    def info(self) -> dict:
        return {"backend": "meshtastic", "device": self.device,
                "tcp_host": self.tcp_host, "running": self.running}
