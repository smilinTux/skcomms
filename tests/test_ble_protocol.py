import pytest

from skcomms.transports.ble import gatt
from skcomms.transports.ble.protocol import (
    MeshPacket,
    PacketType,
    decode,
    encode,
    pad,
    unpad,
)


def _pkt(**kw):
    base = dict(
        type=PacketType.MESSAGE,
        ttl=7,
        flags=0,
        timestamp=1_700_000_000_000,
        msg_id=b"\x01" * 8,
        sender_id=b"\xaa" * 8,
        recipient_id=b"\xbb" * 8,
        payload=b"hello mesh",
        signature=None,
    )
    base.update(kw)
    return MeshPacket(**base)


def test_roundtrip_unsigned():
    p = _pkt()
    raw = encode(p)
    out = decode(raw)
    assert out == p


def test_roundtrip_signed():
    p = _pkt(flags=0x01, signature=b"\x07" * 64)
    raw = encode(p)
    out = decode(raw)
    assert out == p
    assert out.signature == b"\x07" * 64


def test_broadcast_recipient():
    p = _pkt(recipient_id=gatt.BROADCAST_ID)
    out = decode(encode(p))
    assert out.recipient_id == gatt.BROADCAST_ID
    assert out.is_broadcast()


def test_version_is_stamped():
    raw = encode(_pkt())
    assert raw[0] == gatt.PROTOCOL_VERSION


def test_decode_rejects_wrong_version():
    raw = bytearray(encode(_pkt()))
    raw[0] = 9
    with pytest.raises(ValueError, match="version"):
        decode(bytes(raw))


def test_decode_rejects_truncated():
    raw = encode(_pkt())
    with pytest.raises(ValueError):
        decode(raw[:10])


def test_pad_rounds_to_block_and_unpads():
    for n in (10, 200, 256, 257, 1000):
        body = b"x" * n
        padded = pad(body)
        assert len(padded) in gatt.PAD_BLOCKS or len(padded) > gatt.PAD_BLOCKS[-1]
        assert unpad(padded) == body


def test_signature_flag_without_sig_raises():
    p = _pkt(flags=0x01, signature=None)
    with pytest.raises(ValueError, match="signature"):
        encode(p)
