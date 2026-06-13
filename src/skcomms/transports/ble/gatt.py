"""BLE GATT profile + protocol constants — shared by every SMP radio driver.

These UUIDs identify the SK mesh service/characteristic and MUST stay stable so
Python (bleak), Flutter (flutter_blue_plus), and any future driver interoperate.
"""

# SK-mesh GATT profile (custom 128-bit UUIDs, lowercase canonical form).
SERVICE_UUID = "534b4d45-5348-0000-8000-00805f9b34fb"   # "SKME SH" namespaced
MESH_CHAR_UUID = "534b4d45-5348-0001-8000-00805f9b34fb"  # write + notify

# Protocol constants (see spec §4).
PROTOCOL_VERSION = 1
DEFAULT_TTL = 7
HEADER_LEN = 38  # fixed MeshPacket header size (see protocol.HEADER_SIZE)
PAD_BLOCKS = (256, 512, 1024, 2048)
BROADCAST_ID = b"\xff" * 8
