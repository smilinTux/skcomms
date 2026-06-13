"""Message — the typed IR every SKGlossa codec level encodes/decodes."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(eq=True)
class Message:
    intent: str                          # e.g. "coord.claim", "status.report"
    args: dict = field(default_factory=dict)
    refs: list = field(default_factory=list)   # references (ids) into shared context
    text: str = ""                       # free-text slot (escape hatch / nuance)

    def to_dict(self) -> dict:
        return {"i": self.intent, "a": self.args, "r": self.refs, "t": self.text}

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        return cls(intent=d.get("i", ""), args=dict(d.get("a", {})),
                   refs=list(d.get("r", [])), text=d.get("t", ""))
