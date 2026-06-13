from skcomms.transports.ble.protocol import MeshPacket, PacketType, decode
from skcomms.transports.lora import framing


def _pkt(payload):
    return MeshPacket(
        type=PacketType.MESSAGE, ttl=1, flags=0, timestamp=0,
        msg_id=b"\x01" * 8, sender_id=b"\xaa" * 8, recipient_id=b"\xbb" * 8,
        payload=payload,
    )


def test_constants_in_private_range_and_small_mtu():
    assert 256 <= framing.SK_PORTNUM <= 511    # Meshtastic PRIVATE_APP range
    assert framing.LORA_MTU <= 237             # fits a Meshtastic data payload


def test_small_packet_one_frame():
    frames = framing.to_frames(_pkt(b"hi"))
    assert len(frames) == 1
    assert decode(frames[0]).payload == b"hi"


def test_large_packet_fragments_and_reassembles():
    big = bytes(range(256)) * 4  # 1024 bytes -> several LoRa frames
    frames = framing.to_frames(_pkt(big))
    assert len(frames) > 1
    assert all(len(f) <= framing.LORA_MTU for f in frames)
    r = framing.FrameReassembler()
    out = None
    for f in frames:
        out = r.feed(f)
    assert out is not None
    assert out.payload == big


def test_reassembler_returns_none_until_complete():
    frames = framing.to_frames(_pkt(b"y" * 800))
    r = framing.FrameReassembler()
    results = [r.feed(f) for f in frames[:-1]]
    assert all(x is None for x in results)
