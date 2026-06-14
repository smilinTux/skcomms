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


def test_encode_rejects_wrong_length_signature():
    p = _pkt(flags=0x01, signature=b"\x07" * 32)  # 32 != 64
    with pytest.raises(ValueError, match="64 bytes"):
        encode(p)


def test_encode_rejects_wrong_length_ids():
    for field in ("msg_id", "sender_id", "recipient_id"):
        with pytest.raises(ValueError, match=field):
            encode(_pkt(**{field: b"\x00" * 4}))  # 4 != 8


def test_decode_rejects_truncated_signature():
    raw = bytearray(encode(_pkt(flags=0x01, signature=b"\x07" * 64)))
    truncated = bytes(raw[:-10])  # chop the signature short
    with pytest.raises(ValueError, match="signature truncated"):
        decode(truncated)


def test_decode_rejects_truncated_payload():
    raw = encode(_pkt(payload=b"x" * 50))
    # keep the header (declares plen=50) but drop most of the payload
    from skcomms.transports.ble.protocol import HEADER_SIZE

    with pytest.raises(ValueError, match="payload truncated"):
        decode(raw[: HEADER_SIZE + 5])


def test_pad_unpad_empty_body():
    padded = pad(b"")
    assert unpad(padded) == b""


def test_unpad_rejects_too_short():
    with pytest.raises(ValueError):
        unpad(b"\x00")  # < 2 bytes


def test_unpad_rejects_length_prefix_overrun():
    import struct as _s
    # declares true_len=100 but provides far fewer bytes
    bogus = _s.pack(">H", 100) + b"short"
    with pytest.raises(ValueError, match="exceeds"):
        unpad(bogus)
