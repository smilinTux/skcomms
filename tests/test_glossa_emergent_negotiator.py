from skcomms.glossa.emergent import EmergentNegotiator
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
