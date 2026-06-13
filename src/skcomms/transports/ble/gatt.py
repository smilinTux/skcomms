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
# Fixed header byte layout (see protocol.py): version(1) type(1) ttl(1) flags(1)
# timestamp(8) msg_id(8) sender_id(8) recipient_id(8) payload_len(2) = 38? No:
# 1+1+1+1+8+8+8+8+2 = 38. Keep HEADER_LEN authoritative here.
HEADER_LEN = 30  # version+type+ttl+flags(4) + timestamp(8) + msg_id(8) + payload_len(2) + ids handled separately
PAD_BLOCKS = (256, 512, 1024, 2048)
BROADCAST_ID = b"\xff" * 8
