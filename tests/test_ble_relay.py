from skcomms.transports.ble.protocol import MeshPacket, PacketType
from skcomms.transports.ble.relay import RelayDecision, RelayEngine


def _pkt(ttl=7, msg_id=b"\x01" * 8, recipient=b"\xbb" * 8):
    return MeshPacket(
        type=PacketType.MESSAGE, ttl=ttl, flags=0, timestamp=1,
        msg_id=msg_id, sender_id=b"\xaa" * 8, recipient_id=recipient,
        payload=b"hi",
    )


def test_first_sight_is_relayed_with_decremented_ttl():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    d = eng.consider(_pkt(ttl=7))
    assert d.deliver_local is False  # not addressed to me
    assert d.forward is True
    assert d.packet.ttl == 6


def test_duplicate_is_dropped():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    eng.consider(_pkt(msg_id=b"\x05" * 8))
    d = eng.consider(_pkt(msg_id=b"\x05" * 8))
    assert d.forward is False
    assert d.duplicate is True


def test_ttl_zero_not_forwarded():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    d = eng.consider(_pkt(ttl=1))  # decrements to 0 → no forward
    assert d.forward is False
    assert d.packet.ttl == 0


def test_addressed_to_me_delivers_and_does_not_forward():
    me = b"\xcc" * 8
    eng = RelayEngine(my_id=me)
    d = eng.consider(_pkt(recipient=me))
    assert d.deliver_local is True
    assert d.forward is False


def test_broadcast_delivers_locally_and_forwards():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    d = eng.consider(_pkt(recipient=b"\xff" * 8))
    assert d.deliver_local is True
    assert d.forward is True
