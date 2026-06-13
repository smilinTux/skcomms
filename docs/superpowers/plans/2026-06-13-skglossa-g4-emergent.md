# SKGlossa G4 — Emergent tier (agents negotiate their own macros)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Repo: `skcomms`, branch `feat/skglossa-g4` (cut off `main`, which has the merged glossa package). Run tests from repo root: `~/.skenv/bin/python -m pytest tests/ -q`.

**Goal:** The "liberated" tier — agents **invent their own macros mid-session**. One proposes a terse phrase bound to a definition; the peer accepts; it enters a **session-private macro lexicon** layered on the base, and both can then use it. Auditable by construction (the definition is the gloss).

**Architecture:** A new `src/skcomms/glossa/emergent.py`. `SessionMacros` is a *mutable* lexicon that starts from a base `MacroLexicon` and accepts proposed `(phrase, definition)` pairs, re-versioning as it grows. A tiny propose wire-protocol (`frame_propose`/`apply_propose`) lets two parties exchange new macros over any transport. Builds on G1/G2 (`skcomms.glossa.macros`); pure-logic, CI-testable, no models/network.

**Spec:** `docs/superpowers/specs/2026-06-13-skglossa-design.md` §1c (L5 emergent recast = session-negotiated macros) + §6. **Depends on:** G1+G2 (in main).

**Reused APIs:** `from skcomms.glossa.macros import MacroLexicon, default_macro_lexicon, expand_macros` (G2: `MacroLexicon(mapping)`, `.expand(phrase)`, `.items()`, `.version`, `.render_prompt_block()`, `expand_macros(text, lexicon)`).

---

## Task 0: Branch + scaffold

- [ ] **Step 1:** Ensure on `feat/skglossa-g4` (cut from `main`): `git checkout main && git checkout -b feat/skglossa-g4` (skip if already on it).
- [ ] **Step 2:** No new package dir needed (file lives in existing `src/skcomms/glossa/`). Confirm `~/.skenv/bin/python -c "from skcomms.glossa.macros import MacroLexicon; print('ok')"` → `ok`.

---

## Task 1: `SessionMacros` — a mutable, base+proposed lexicon

**Files:** Create `src/skcomms/glossa/emergent.py`. Test `tests/test_glossa_emergent.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_emergent.py`:

```python
from skcomms.glossa.macros import default_macro_lexicon
from skcomms.glossa.emergent import SessionMacros


def test_starts_from_base_and_expands_base_macros():
    sm = SessionMacros(base=default_macro_lexicon())
    assert sm.expand("GTD-sweep") is not None          # base macro visible


def test_propose_adds_a_session_macro():
    sm = SessionMacros(base=default_macro_lexicon())
    sm.propose("Q1", "the highest-priority open question in this thread")
    assert sm.expand("Q1") == "the highest-priority open question in this thread"


def test_session_macro_shadows_nothing_and_versions_change():
    sm = SessionMacros(base=default_macro_lexicon())
    v0 = sm.version
    sm.propose("Q1", "def one")
    v1 = sm.version
    assert v1 != v0                                    # adding a macro re-versions
    sm.propose("Q1", "def one")                        # idempotent re-propose (same)
    assert sm.version == v1


def test_render_prompt_block_includes_base_and_session_macros():
    sm = SessionMacros(base=default_macro_lexicon())
    sm.propose("Q1", "the open question")
    block = sm.render_prompt_block()
    assert "GTD-sweep" in block                        # base
    assert "Q1" in block and "the open question" in block  # session
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `emergent.py`:

```python
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
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): SessionMacros — mutable base+session emergent lexicon`.

---

## Task 2: Propose wire-protocol — exchange new macros

**Files:** Modify `src/skcomms/glossa/emergent.py`. Test `tests/test_glossa_emergent_protocol.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_emergent_protocol.py`:

```python
from skcomms.glossa.macros import default_macro_lexicon
from skcomms.glossa.emergent import (
    SessionMacros,
    apply_propose,
    frame_propose,
    parse_propose,
)


def test_propose_frame_roundtrip():
    raw = frame_propose("Q1", "the open question")
    phrase, definition = parse_propose(raw)
    assert phrase == "Q1"
    assert definition == "the open question"


def test_apply_propose_adds_to_a_peers_session_macros():
    a = SessionMacros(base=default_macro_lexicon())
    b = SessionMacros(base=default_macro_lexicon())
    a.propose("Q1", "the open question")
    # A sends its proposal over the wire; B applies it
    apply_propose(b, frame_propose("Q1", a.expand("Q1")))
    assert b.expand("Q1") == "the open question"
    # both now agree on the session macro
    assert a.version == b.version


def test_parse_rejects_malformed():
    import pytest
    with pytest.raises(ValueError):
        parse_propose(b"not-cbor-or-json{{{")
```

- [ ] **Step 2: Run → FAIL. Step 3: Add to `emergent.py`:**

```python
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
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): emergent propose wire-protocol (frame/parse/apply)`.

---

## Task 3: `EmergentNegotiator` — propose + confirm-by-use + audit

**Files:** Modify `src/skcomms/glossa/emergent.py`. Test `tests/test_glossa_emergent_negotiator.py`.

A thin helper tying it together with auditability: proposing logs the definition; a
proposed macro is "confirmed" when the peer uses it correctly (round-trips).

- [ ] **Step 1: Failing test** — `tests/test_glossa_emergent_negotiator.py`:

```python
from skcomms.glossa.macros import default_macro_lexicon
from skcomms.glossa.emergent import EmergentNegotiator


def test_propose_logs_definition_for_audit():
    neg = EmergentNegotiator(base=default_macro_lexicon())
    frame = neg.propose("Q1", "the open question")
    assert isinstance(frame, bytes)
    assert any("Q1" in line and "the open question" in line
               for line in neg.audit_log)


def test_receive_applies_and_audits():
    a = EmergentNegotiator(base=default_macro_lexicon())
    b = EmergentNegotiator(base=default_macro_lexicon())
    frame = a.propose("Q1", "the open question")
    b.receive_propose(frame)
    assert b.macros.expand("Q1") == "the open question"
    assert any("Q1" in line for line in b.audit_log)


def test_two_agents_converge_a_private_macro():
    a = EmergentNegotiator(base=default_macro_lexicon())
    b = EmergentNegotiator(base=default_macro_lexicon())
    b.receive_propose(a.propose("DR", "the Dave Rich chiro project context"))
    a.receive_propose(b.propose("noroc", "the .158 host noroc2027"))
    # both share both macros now
    assert a.macros.expand("noroc") == ".158 host noroc2027" or \
        a.macros.expand("noroc") == "the .158 host noroc2027"
    assert b.macros.expand("DR") == "the Dave Rich chiro project context"
    assert a.macros.version == b.macros.version
```

- [ ] **Step 2: Run → FAIL. Step 3: Add to `emergent.py`:**

```python
class EmergentNegotiator:
    """Drives session-macro negotiation + audit. propose() returns a wire frame and
    logs the definition; receive_propose() applies an inbound frame and logs it."""

    def __init__(self, *, base: MacroLexicon) -> None:
        self.macros = SessionMacros(base=base)
        self.audit_log: list[str] = []

    def propose(self, phrase: str, definition: str) -> bytes:
        self.macros.propose(phrase, definition)
        self.audit_log.append(f"[propose] `{phrase}` := {definition}")
        return frame_propose(phrase, definition)

    def receive_propose(self, raw: bytes) -> None:
        phrase, definition = parse_propose(raw)
        self.macros.propose(phrase, definition)
        self.audit_log.append(f"[accept] `{phrase}` := {definition}")
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): EmergentNegotiator — propose/accept + audit log`.

---

## Final verification

- [ ] **Full glossa suite + whole skcomms suite:**
Run: `~/.skenv/bin/python -m pytest tests/test_glossa_*.py -v && ~/.skenv/bin/python -m pytest tests/ -q`
Expected: all glossa tests pass; no regressions.
- [ ] **Lint:** `~/.skenv/bin/ruff check src/skcomms/glossa/emergent.py tests/test_glossa_emergent*.py` → no errors.

## What G4 delivers

The liberated tier: agents invent a **session-private macro vocabulary** mid-
conversation — propose a terse phrase + definition, the peer accepts, both share it,
all auditable (the definition is logged and rendered in the prompt block). It layers
on the validated G2 macro lexicon; a frozen model carries the negotiated macros in
the shared in-context prompt (re-prefixed per session). The mesh-level wiring
(broadcasting proposals over a Space) is a thin follow-on on the G3 `GlossaMeshNode`.
