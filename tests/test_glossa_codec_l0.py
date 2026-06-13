from skcomms.glossa import codec
from skcomms.glossa.message import Message


def test_level_constants():
    assert codec.L0_ENGLISH == 0
    assert codec.L1_SCHEMA == 1
    assert codec.L2_CODEBOOK == 2


def test_l0_roundtrip():
    m = Message(intent="coord.claim", args={"task": "abc", "n": 3},
                refs=["t1", "t2"], text="claiming this")
    raw = codec.encode(m, codec.L0_ENGLISH)
    assert isinstance(raw, bytes)
    out = codec.decode(raw, codec.L0_ENGLISH)
    assert out == m


def test_l0_is_human_readable_text():
    raw = codec.encode(Message(intent="ack"), codec.L0_ENGLISH)
    assert b"ack" in raw                  # the floor is literally readable
