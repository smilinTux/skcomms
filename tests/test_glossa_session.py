from skcomms.glossa import codec
from skcomms.glossa.codebook import default_codebook
from skcomms.glossa.handshake import CapabilityDescriptor
from skcomms.glossa.message import Message
from skcomms.glossa.session import GlossaSession


def _desc(fqid, max_level):
    return CapabilityDescriptor(fqid=fqid, model_tier="large", max_level=max_level,
                                codebook_version=default_codebook().version)


def test_two_agents_handshake_and_round_trip_at_l2():
    cb = default_codebook()
    a = GlossaSession(local=_desc("a@x.y", codec.L2_CODEBOOK), codebook=cb)
    b = GlossaSession(local=_desc("b@x.y", codec.L2_CODEBOOK), codebook=cb)
    # wire them to each other (a.say -> b.receive and vice-versa)
    a.set_transport(b.receive)
    b.set_transport(a.receive)
    a.handshake(b.local)
    b.handshake(a.local)
    assert a.level == codec.L2_CODEBOOK

    got = []
    b.on_message(lambda m: got.append(m))
    a.say(Message(intent="coord.claim", args={"task": "abc"}, text="mine"))
    assert got == [Message(intent="coord.claim", args={"task": "abc"}, text="mine")]


def test_weaker_peer_caps_the_level_and_still_round_trips():
    cb = default_codebook()
    a = GlossaSession(local=_desc("a@x.y", codec.L2_CODEBOOK), codebook=cb)
    b = GlossaSession(local=_desc("b@x.y", codec.L0_ENGLISH), codebook=cb)  # weak
    a.set_transport(b.receive)
    b.set_transport(a.receive)
    a.handshake(b.local)
    b.handshake(a.local)
    assert a.level == codec.L0_ENGLISH    # capped to the weaker peer
    got = []
    b.on_message(lambda m: got.append(m))
    a.say(Message(intent="ack"))
    assert got == [Message(intent="ack")]


def test_session_logs_english_gloss():
    cb = default_codebook()
    a = GlossaSession(local=_desc("a@x.y", codec.L2_CODEBOOK), codebook=cb)
    b = GlossaSession(local=_desc("b@x.y", codec.L2_CODEBOOK), codebook=cb)
    a.set_transport(b.receive)
    b.set_transport(a.receive)
    a.handshake(b.local)
    a.say(Message(intent="status.report", args={"oof": 42}))
    assert any("status.report" in line for line in a.audit_log)
