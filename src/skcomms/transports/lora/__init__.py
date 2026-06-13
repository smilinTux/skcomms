"""SK LoRa transport — long-range off-grid mesh over Meshtastic.

Sibling OFFLINE transport to the BLE/SMP mesh: ships compact Ed25519-signed
MeshPacket payloads (reused from transports/ble) over a LoRa mesh. Meshtastic
owns the mesh; we ride on top. L1 = hardware-free core (FakeLoRaInterface). See
docs/superpowers/specs/2026-06-13-lora-meshtastic-transport-design.md.
"""

__all__ = []
