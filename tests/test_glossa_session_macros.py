from skcomms.glossa import codec
from skcomms.glossa.codebook import default_codebook
from skcomms.glossa.handshake import CapabilityDescriptor
from skcomms.glossa.macros import default_macro_lexicon
from skcomms.glossa.message import Message
from skcomms.glossa.session import GlossaSession


def _desc(fqid):
    lex = default_macro_lexicon()
    return CapabilityDescriptor(fqid=fqid, model_tier="large",
                                max_level=codec.L1_SCHEMA,
                                codebook_version=default_codebook().version,
                                lexicon_version=lex.version)


def test_session_exposes_macro_prompt_block():
    s = GlossaSession(local=_desc("a@x.y"), codebook=default_codebook(),
                      lexicon=default_macro_lexicon())
    block = s.macro_prompt_block()
    assert "GTD-sweep" in block


def test_audit_log_shows_expanded_macro_meaning():
    cb, lex = default_codebook(), default_macro_lexicon()
    a = GlossaSession(local=_desc("a@x.y"), codebook=cb, lexicon=lex)
    b = GlossaSession(local=_desc("b@x.y"), codebook=cb, lexicon=lex)
    a.set_transport(b.receive)
    a.handshake(b.local)
    a.say(Message(intent="instruct", text="ROLLBACK <host> prev"))
    # the audit log carries the EXPANDED meaning (host pinned), not just the shorthand
    assert any("roll back the deployment ON HOST" in line for line in a.audit_log)
