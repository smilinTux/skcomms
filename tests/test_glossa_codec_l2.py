import pytest

from skcomms.glossa import codec
from skcomms.glossa.codebook import default_codebook
from skcomms.glossa.message import Message


def test_l2_roundtrip_with_codebook():
    cb = default_codebook()
    m = Message(intent="coord.claim", args={"task": "abc"}, refs=["t1"])
    raw = codec.encode(m, codec.L2_CODEBOOK, cb)
    out = codec.decode(raw, codec.L2_CODEBOOK, cb)
    assert out == m


def test_l2_is_denser_than_l1_for_known_intent():
    cb = default_codebook()
    m = Message(intent="status.report", args={"oof": 42})
    l1 = codec.encode(m, codec.L1_SCHEMA)
    l2 = codec.encode(m, codec.L2_CODEBOOK, cb)
    assert len(l2) < len(l1)              # intent string -> small int


def test_l2_requires_codebook():
    with pytest.raises(ValueError, match="codebook"):
        codec.encode(Message(intent="ack"), codec.L2_CODEBOOK, None)


def test_l2_unknown_intent_falls_back_to_string():
    cb = default_codebook()
    m = Message(intent="novel.intent.not.in.book", text="hi")
    out = codec.decode(codec.encode(m, codec.L2_CODEBOOK, cb), codec.L2_CODEBOOK, cb)
    assert out == m                       # round-trips even if intent isn't coded
