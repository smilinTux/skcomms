import pytest

from skcomms.glossa import codec
from skcomms.glossa.codebook import Codebook, default_codebook
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


def test_l2_decode_raises_on_codebook_version_skew():
    # Encode a known intent with the default codebook; decode with a DIFFERENT
    # codebook that lacks that code -> int head not resolvable -> hard error
    # (NOT a silently-empty intent / wrong message delivered).
    sender_cb = default_codebook()
    # receiver codebook lacks the code coord.claim was encoded under (1)
    receiver_cb = Codebook({"some.other.intent": 999})
    raw = codec.encode(Message(intent="coord.claim", args={"task": "abc"}),
                       codec.L2_CODEBOOK, sender_cb)
    with pytest.raises(ValueError, match="unknown"):
        codec.decode(raw, codec.L2_CODEBOOK, receiver_cb)


def test_l2_roundtrip_with_unicode_in_args_and_text():
    cb = default_codebook()
    m = Message(intent="coord.claim", args={"name": "你好"},
                refs=["t1"], text="café 🔥")
    out = codec.decode(codec.encode(m, codec.L2_CODEBOOK, cb), codec.L2_CODEBOOK, cb)
    assert out == m


def test_l2_denser_than_l1_for_unknown_and_big_args():
    cb = default_codebook()
    # unknown intent (string head, no int gain) still <= L1 thanks to dropping keys
    unknown = Message(intent="novel.intent.not.in.book", args={"x": 1}, text="hi")
    assert len(codec.encode(unknown, codec.L2_CODEBOOK, cb)) < \
        len(codec.encode(unknown, codec.L1_SCHEMA))
    # big-args known intent
    big = Message(intent="coord.claim",
                  args={f"k{i}": "v" * 20 for i in range(20)})
    assert len(codec.encode(big, codec.L2_CODEBOOK, cb)) < \
        len(codec.encode(big, codec.L1_SCHEMA))
