import re
import uuid

from skcomms.transports.ble import gatt

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def test_uuids_are_valid_and_distinct():
    vals = [gatt.SERVICE_UUID, gatt.MESH_CHAR_UUID]
    for v in vals:
        assert _UUID_RE.match(v), f"{v} is not a lowercase canonical UUID"
        uuid.UUID(v)  # parses
    assert len(set(vals)) == len(vals), "UUIDs must be distinct"


def test_protocol_constants():
    assert gatt.PROTOCOL_VERSION == 1
    assert gatt.DEFAULT_TTL == 7
    assert gatt.HEADER_LEN == 30
    assert gatt.PAD_BLOCKS == (256, 512, 1024, 2048)
    assert gatt.BROADCAST_ID == b"\xff" * 8
