from skcomms.glossa import codec
from skcomms.glossa.message import Message


def test_l1_roundtrip():
    m = Message(intent="status.report", args={"oof": 42}, refs=["t1"], text="ok")
    out = codec.decode(codec.encode(m, codec.L1_SCHEMA), codec.L1_SCHEMA)
    assert out == m


def test_l1_is_denser_than_l0():
    m = Message(intent="status.report", args={"oof": 42, "load": 0.7},
                refs=["t1", "t2"], text="status nominal")
    l0 = codec.encode(m, codec.L0_ENGLISH)
    l1 = codec.encode(m, codec.L1_SCHEMA)
    assert len(l1) <= len(l0)             # CBOR ≤ readable text
