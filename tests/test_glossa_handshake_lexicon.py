from skcomms.glossa import codec
from skcomms.glossa.handshake import CapabilityDescriptor, negotiate


def _d(fqid, lex_ver):
    return CapabilityDescriptor(fqid=fqid, model_tier="large",
                                max_level=codec.L1_SCHEMA, codebook_version="cb1",
                                lexicon_version=lex_ver)


def test_macros_enabled_only_on_matching_lexicon_version():
    s = negotiate(_d("a@x.y", "lexAAA"), _d("b@x.y", "lexAAA"))
    assert s.macros_enabled is True
    assert s.lexicon_version == "lexAAA"


def test_macros_disabled_on_mismatched_lexicon():
    s = negotiate(_d("a@x.y", "lexAAA"), _d("b@x.y", "lexBBB"))
    assert s.macros_enabled is False
    assert s.lexicon_version == ""        # no shared lexicon


def test_macros_symmetric():
    a, b = _d("a@x.y", "lexAAA"), _d("b@x.y", "lexBBB")
    assert negotiate(a, b).macros_enabled == negotiate(b, a).macros_enabled
