from skcomms.glossa.codebook import Codebook, default_codebook


def test_concept_code_roundtrip():
    cb = Codebook({"coord.claim": 1, "status.report": 2})
    assert cb.code_for("coord.claim") == 1
    assert cb.concept_for(1) == "coord.claim"


def test_unknown_concept_returns_none():
    cb = Codebook({"x": 1})
    assert cb.code_for("nope") is None
    assert cb.concept_for(999) is None


def test_version_is_stable_hash_of_contents():
    a = Codebook({"coord.claim": 1, "status.report": 2})
    b = Codebook({"status.report": 2, "coord.claim": 1})  # same mapping, diff order
    assert a.version == b.version          # order-independent
    c = Codebook({"coord.claim": 1})
    assert a.version != c.version          # different mapping → different version


def test_default_codebook_has_seed_vocab():
    cb = default_codebook()
    # seeded from real SK vocabulary (coord/itil/gtd/status intents)
    assert cb.code_for("coord.claim") is not None
    assert cb.code_for("status.report") is not None
    assert len(cb.version) == 12           # short hex version tag
