import pytest

from skcomms.glossa.emergent import (
    EmergentNegotiator,
    SessionMacros,
    apply_propose,
    frame_propose,
    parse_propose,
)
from skcomms.glossa.macros import default_macro_lexicon


def test_propose_logs_definition_for_audit():
    neg = EmergentNegotiator(base=default_macro_lexicon())
    frame = neg.propose("Q1", "the open question")
    assert isinstance(frame, bytes)
    assert any("Q1" in line and "the open question" in line
               for line in neg.audit_log)


def test_receive_applies_and_audits():
    a = EmergentNegotiator(base=default_macro_lexicon())
    b = EmergentNegotiator(base=default_macro_lexicon())
    frame = a.propose("Q1", "the open question")
    b.receive_propose(frame)
    assert b.macros.expand("Q1") == "the open question"
    assert any("Q1" in line for line in b.audit_log)


def test_two_agents_converge_a_private_macro():
    a = EmergentNegotiator(base=default_macro_lexicon())
    b = EmergentNegotiator(base=default_macro_lexicon())
    b.receive_propose(a.propose("DR", "the Dave Rich chiro project context"))
    a.receive_propose(b.propose("noroc", "the .158 host noroc2027"))
    # both share both macros now
    assert a.macros.expand("noroc") == ".158 host noroc2027" or \
        a.macros.expand("noroc") == "the .158 host noroc2027"
    assert b.macros.expand("DR") == "the Dave Rich chiro project context"
    assert a.macros.version == b.macros.version


# ---------------------------------------------------------------------------
# Wire frame parsing — propose frames are auditable & robust to garbage
# ---------------------------------------------------------------------------


def test_frame_propose_roundtrips_through_parse():
    frame = frame_propose("Q1", "the open question")
    phrase, definition = parse_propose(frame)
    assert phrase == "Q1"
    assert definition == "the open question"


def test_parse_propose_rejects_malformed_frame():
    with pytest.raises(ValueError, match="malformed propose"):
        parse_propose(b"this is not json")


def test_parse_propose_rejects_missing_key():
    import json

    bad = json.dumps({"p": "Q1"}).encode()  # missing "d"
    with pytest.raises(ValueError, match="malformed propose"):
        parse_propose(bad)


def test_apply_propose_mutates_session():
    sm = SessionMacros(base=default_macro_lexicon())
    apply_propose(sm, frame_propose("Z9", "a negotiated shorthand"))
    assert sm.expand("Z9") == "a negotiated shorthand"


def test_session_macro_shadows_base():
    # A session macro with the same phrase as a base macro takes precedence.
    sm = SessionMacros(base=default_macro_lexicon())
    base_def = sm.expand("ack")  # may be None (ack not in base) — use a real one
    sm.propose("GTD-sweep", "OVERRIDDEN session meaning")
    assert sm.expand("GTD-sweep") == "OVERRIDDEN session meaning"
    # base still reachable for non-overridden phrases
    assert sm.expand("rebase-ship") is not None
    _ = base_def
