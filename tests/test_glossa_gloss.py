from skcomms.glossa import codec, gloss
from skcomms.glossa.codebook import default_codebook
from skcomms.glossa.message import Message


def test_to_english_renders_prose():
    eng = gloss.to_english(Message(intent="coord.claim", args={"task": "abc"},
                                   refs=["t1"], text="mine"))
    assert "coord.claim" in eng
    assert "abc" in eng
    assert isinstance(eng, str) and len(eng) > 0


def test_gloss_works_at_every_level():
    cb = default_codebook()
    m = Message(intent="status.report", args={"oof": 42}, text="ok")
    for level in (codec.L0_ENGLISH, codec.L1_SCHEMA, codec.L2_CODEBOOK):
        raw = codec.encode(m, level, cb)
        # the invariant: any dense form decodes back to an English gloss
        eng = gloss.decode_to_english(raw, level, cb)
        assert "status.report" in eng
