from skcomms.glossa import gloss
from skcomms.glossa.message import Message


def test_to_human_en_is_the_english_gloss():
    m = Message(intent="coord.claim", args={"task": "abc"})
    assert gloss.to_human(m, "en") == gloss.to_english(m)


def test_to_human_uses_injected_translator_for_other_langs():
    m = Message(intent="ack")
    out = gloss.to_human(m, "zh", translate=lambda text, lang: f"<{lang}>{text}")
    assert out == f"<zh>{gloss.to_english(m)}"


def test_to_human_unknown_lang_without_translator_falls_back_to_english():
    m = Message(intent="ack")
    # no translator provided → safe English fallback, never crashes the audit
    assert gloss.to_human(m, "zh") == gloss.to_english(m)


def test_to_human_falls_back_when_translator_returns_none():
    m = Message(intent="ack")
    # a translator returning None/"" must NOT propagate — audit never fails
    assert gloss.to_human(m, "zh", translate=lambda t, lang: None) == \
        gloss.to_english(m)
    assert gloss.to_human(m, "zh", translate=lambda t, lang: "") == \
        gloss.to_english(m)
