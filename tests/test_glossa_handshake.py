from skcomms.glossa import codec
from skcomms.glossa.codebook import default_codebook
from skcomms.glossa.handshake import CapabilityDescriptor, negotiate


def _desc(fqid, tier, max_level, cb_ver):
    return CapabilityDescriptor(fqid=fqid, model_tier=tier, max_level=max_level,
                                codebook_version=cb_ver)


def test_negotiate_picks_min_of_both_max_levels():
    cb = default_codebook().version
    a = _desc("a@x.y", "large", codec.L2_CODEBOOK, cb)
    b = _desc("b@x.y", "small", codec.L1_SCHEMA, cb)      # weaker peer caps it
    sess = negotiate(a, b)
    assert sess.level == codec.L1_SCHEMA


def test_l2_requires_matching_codebook_version():
    a = _desc("a@x.y", "large", codec.L2_CODEBOOK, "vAAAAAAAAAA1")
    b = _desc("b@x.y", "large", codec.L2_CODEBOOK, "vBBBBBBBBBB2")  # mismatched
    sess = negotiate(a, b)
    assert sess.level == codec.L1_SCHEMA   # falls back to L1 (no shared codebook)


def test_matching_codebook_allows_l2():
    cb = default_codebook().version
    a = _desc("a@x.y", "large", codec.L2_CODEBOOK, cb)
    b = _desc("b@x.y", "large", codec.L2_CODEBOOK, cb)
    assert negotiate(a, b).level == codec.L2_CODEBOOK


def test_negotiate_codebook_version_is_agreed_and_symmetric():
    # codebook_version on the Session means "the AGREED shared version".
    # For mismatched descriptors there is no shared codebook -> "" both ways.
    a = _desc("a@x.y", "large", codec.L2_CODEBOOK, "vAAAAAAAAAA1")
    b = _desc("b@x.y", "large", codec.L2_CODEBOOK, "vBBBBBBBBBB2")
    assert negotiate(a, b).codebook_version == negotiate(b, a).codebook_version == ""


def test_negotiate_codebook_version_set_when_matching():
    cb = default_codebook().version
    a = _desc("a@x.y", "large", codec.L2_CODEBOOK, cb)
    b = _desc("b@x.y", "large", codec.L2_CODEBOOK, cb)
    assert negotiate(a, b).codebook_version == cb


def test_negotiate_is_symmetric():
    cb = default_codebook().version
    a = _desc("a@x.y", "large", codec.L2_CODEBOOK, cb)
    b = _desc("b@x.y", "small", codec.L0_ENGLISH, cb)
    assert negotiate(a, b).level == negotiate(b, a).level == codec.L0_ENGLISH
