"""The audit invariant (spec §5): every SKGlossa message renders to English.

`to_english(Message)` is the human-facing prose; `decode_to_english(bytes, level)`
proves the invariant holds at every density tier — the oversight guarantee.
"""

from __future__ import annotations

from typing import Callable

from skcomms.glossa import codec
from skcomms.glossa.codebook import Codebook
from skcomms.glossa.message import Message


def to_english(m: Message) -> str:
    parts = [f"intent '{m.intent}'"]
    if m.args:
        kv = ", ".join(f"{k}={v}" for k, v in m.args.items())
        parts.append(f"with {kv}")
    if m.refs:
        parts.append(f"referencing {', '.join(map(str, m.refs))}")
    if m.text:
        parts.append(f": {m.text}")
    return " ".join(parts)


def to_human(m: Message, lang: str = "en",
             translate: Callable[[str, str], str] | None = None) -> str:
    """Render the audit gloss in `lang`. en = the English renderer; other languages
    go through an injected `translate(text, lang)` seam (a model call in production,
    a fake in tests). Falls back to English if no translator — the audit must never
    fail. Presentation only; off the hot path (spec §5a)."""
    english = to_english(m)
    if lang == "en" or translate is None:
        return english
    return translate(english, lang)


def decode_to_english(raw: bytes, level: int, codebook: Codebook | None = None) -> str:
    m = codec.decode(raw, level, codebook)
    return to_english(m)
