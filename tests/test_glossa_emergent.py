from skcomms.glossa.emergent import SessionMacros
from skcomms.glossa.macros import default_macro_lexicon


def test_starts_from_base_and_expands_base_macros():
    sm = SessionMacros(base=default_macro_lexicon())
    assert sm.expand("GTD-sweep") is not None          # base macro visible


def test_propose_adds_a_session_macro():
    sm = SessionMacros(base=default_macro_lexicon())
    sm.propose("Q1", "the highest-priority open question in this thread")
    assert sm.expand("Q1") == "the highest-priority open question in this thread"


def test_session_macro_shadows_nothing_and_versions_change():
    sm = SessionMacros(base=default_macro_lexicon())
    v0 = sm.version
    sm.propose("Q1", "def one")
    v1 = sm.version
    assert v1 != v0                                    # adding a macro re-versions
    sm.propose("Q1", "def one")                        # idempotent re-propose (same)
    assert sm.version == v1


def test_render_prompt_block_includes_base_and_session_macros():
    sm = SessionMacros(base=default_macro_lexicon())
    sm.propose("Q1", "the open question")
    block = sm.render_prompt_block()
    assert "GTD-sweep" in block                        # base
    assert "Q1" in block and "the open question" in block  # session
