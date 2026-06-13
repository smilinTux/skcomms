from skcomms.transports.ble.protocol import (
    MeshPacket,
    PacketType,
    Reassembler,
    decode,
    encode,
    fragment,
)


def _msg(payload):
    return MeshPacket(
        type=PacketType.MESSAGE, ttl=7, flags=0, timestamp=1,
        msg_id=b"\x09" * 8, sender_id=b"\xaa" * 8, recipient_id=b"\xbb" * 8,
        payload=payload,
    )


def test_small_payload_single_fragment():
    frags = fragment(_msg(b"tiny"), mtu=512)
    assert len(frags) == 1
    assert decode(frags[0]).type == PacketType.MESSAGE


def test_large_payload_splits_and_reassembles():
    original = bytes(range(256)) * 8  # 2048 bytes
    frags = fragment(_msg(original), mtu=185)
    assert len(frags) > 1
    types = [decode(f).type for f in frags]
    assert types[0] == PacketType.FRAGMENT_START
    assert types[-1] == PacketType.FRAGMENT_END
    assert all(t == PacketType.FRAGMENT_CONTINUE for t in types[1:-1])

    r = Reassembler()
    out = None
    for f in frags:
        out = r.feed(decode(f))
    assert out is not None
    assert out.payload == original
    assert out.type == PacketType.MESSAGE


def test_reassembler_ignores_unrelated_fragment_ids():
    r = Reassembler()
    big = fragment(_msg(b"y" * 1000), mtu=185)
    # feed all but last → no output yet
    last = None
    for f in big[:-1]:
        last = r.feed(decode(f))
    assert last is None
