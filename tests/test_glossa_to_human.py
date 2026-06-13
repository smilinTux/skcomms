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
