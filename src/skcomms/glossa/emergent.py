"""Emergent tier (spec §1c/§6): agents negotiate their OWN macros mid-session.

SessionMacros = a mutable lexicon layered on the base MacroLexicon. Proposed macros
are session-private; the definition is the audit gloss (auditability by
construction). A frozen model can't remember these across sessions, so they live in
the shared in-context prompt block (re-prefixed per session)."""

from __future__ import annotations

import hashlib
import json

from skcomms.glossa.macros import MacroLexicon


class SessionMacros:
    def __init__(self, *, base: MacroLexicon) -> None:
        self._base = base
        self._session: dict[str, str] = {}

    def expand(self, phrase: str) -> str | None:
        """Session macros take precedence, then base."""
        if phrase in self._session:
            return self._session[phrase]
        return self._base.expand(phrase)

    def propose(self, phrase: str, definition: str) -> None:
        self._session[phrase] = definition

    def items(self):
        merged = {p: d for p, d in self._base.items()}
        merged.update(self._session)
        return merged.items()

    @property
    def session_items(self):
        return dict(self._session).items()

    @property
    def version(self) -> str:
        canonical = json.dumps(
            {"base": self._base.version, "session": self._session},
            sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:12]

    def render_prompt_block(self) -> str:
        block = self._base.render_prompt_block()
        if self._session:
            lines = ["", "Session macros (negotiated this conversation):"]
            for phrase, definition in self._session.items():
                lines.append(f"- `{phrase}` := {definition}")
            block = block + "\n" + "\n".join(lines)
        return block


def frame_propose(phrase: str, definition: str) -> bytes:
    return json.dumps({"p": phrase, "d": definition},
                      separators=(",", ":")).encode()


def parse_propose(raw: bytes) -> tuple[str, str]:
    try:
        d = json.loads(raw.decode())
        return d["p"], d["d"]
    except Exception as exc:
        raise ValueError(f"malformed propose frame: {exc}") from exc


def apply_propose(session: "SessionMacros", raw: bytes) -> None:
    phrase, definition = parse_propose(raw)
    session.propose(phrase, definition)
