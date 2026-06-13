from skcomms.glossa.macros import default_macro_lexicon
from skcomms.glossa.emergent import (
    SessionMacros,
    apply_propose,
    frame_propose,
    parse_propose,
)


def test_propose_frame_roundtrip():
    raw = frame_propose("Q1", "the open question")
    phrase, definition = parse_propose(raw)
    assert phrase == "Q1"
    assert definition == "the open question"


def test_apply_propose_adds_to_a_peers_session_macros():
    a = SessionMacros(base=default_macro_lexicon())
    b = SessionMacros(base=default_macro_lexicon())
    a.propose("Q1", "the open question")
    # A sends its proposal over the wire; B applies it
    apply_propose(b, frame_propose("Q1", a.expand("Q1")))
    assert b.expand("Q1") == "the open question"
    # both now agree on the session macro
    assert a.version == b.version


def test_parse_rejects_malformed():
    import pytest
    with pytest.raises(ValueError):
        parse_propose(b"not-cbor-or-json{{{")
