# SKGlossa — G2 (recast): Macro Lexicon + configurable gloss

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Repo: `skcomms`, branch `feat/skglossa`. Run tests from repo root: `~/.skenv/bin/python -m pytest tests/ -q`.

**RECAST NOTE (2026-06-13):** This supersedes the original G2 framing (rate-adaptation + L3 token-stream). The empirical benchmark (spec §1b/§1c) proved synthetic codebook codes give **no token win** and bare jargon is a fidelity trap, while **in-context macros win cleanly (−67% tokens, 100% fidelity)**. So G2 builds the **validated** thing: the macro lexicon (the real token-efficiency layer) + the configurable `to_human(lang)` gloss Chef asked for. Coord: `c07d4fa0`.

**Goal:** Add the macro-lexicon layer — a shared, versioned dictionary of terse phrases with explicit English definitions that agents carry in their system prompt (the token-efficiency win), with handshake version-pinning — plus generalize the gloss to `to_human(message, lang)`.

**Architecture:** The macro lexicon is a **prompt artifact + an audit helper**, NOT a wire codec (orthogonal to the G1 L0/L1/L2 byte codecs, which remain the bandwidth/LoRa layer). `MacroLexicon` holds `phrase → definition`, renders a system-prompt block (so the receiving *model* expands macros semantically), and `expand_macros(text)` does literal expansion for the audit log (so a human sees the full meaning). The handshake gains `lexicon_version` so two agents only speak macros when they hold the same lexicon. `gloss.to_human(m, lang)` generalizes `to_english` with a translation seam.

**Tech Stack:** Python 3.10+, reuses G1 `glossa.{message,gloss,handshake}`. `pytest`. Line 99, ruff (E,F,I,N,W; E501 ignored — no `;` one-liners).

**Spec:** `docs/superpowers/specs/2026-06-13-skglossa-design.md` §1c (validated macro design), §5a (language-neutral gloss). **Depends on G1.**

---

## Task 1: `MacroLexicon` — the validated token-efficiency layer

**Files:** Create `src/skcomms/glossa/macros.py`. Test `tests/test_glossa_macros.py`.

The seed macros are the ones the experiment validated (the slot-typed forms that hit
100% fidelity — e.g. `ROLLBACK <host> prev` pinning `.41` as a host, not a version).

- [ ] **Step 1: Failing test** — `tests/test_glossa_macros.py`:

```python
from skcomms.glossa.macros import MacroLexicon, default_macro_lexicon


def test_expand_and_version():
    lex = MacroLexicon({"GTD-sweep": "review open tasks, reprioritize by the 4 C's, "
                                     "flag blockers, propose next actions"})
    assert lex.expand("GTD-sweep").startswith("review open tasks")
    assert lex.expand("nope") is None
    assert len(lex.version) == 12


def test_version_is_order_independent():
    a = MacroLexicon({"x": "ex", "y": "why"})
    b = MacroLexicon({"y": "why", "x": "ex"})
    assert a.version == b.version
    assert MacroLexicon({"x": "ex"}).version != a.version


def test_default_lexicon_has_validated_slot_typed_macros():
    lex = default_macro_lexicon()
    # the experiment's disambiguating macros (host vs version, next-action vs region)
    assert lex.expand("GTD-sweep") is not None
    assert lex.expand("ROLLBACK <host> prev") is not None
    assert lex.expand("NEXT-DO mine") is not None
    assert lex.expand("P0 <svc> down <host>") is not None
    # a definition that pins the slot type (the fidelity fix)
    assert "host" in lex.expand("ROLLBACK <host> prev").lower()
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `macros.py`:

```python
"""Macro lexicon (spec §1c) — the VALIDATED token-efficiency layer.

A shared, versioned dictionary of terse phrases with explicit English definitions.
Agents carry render_prompt_block() in their system prompt so the receiving MODEL
expands macros semantically (-67% tokens, 100% fidelity when defined; bare jargon
without these definitions misreads ~1-in-5). NOT a wire codec — orthogonal to the
L0/L1/L2 byte codecs. The definitions are also the audit gloss (auditable by
construction).
"""

from __future__ import annotations

import hashlib
import json

# Seed macros — the slot-typed forms the experiment validated to 100% fidelity.
# Each definition PINS the slot type, which is what kills the bare-jargon misreads
# (".41" host-not-version, "NA"/next-action-not-region, skmem-pg service-not-slab).
_SEED = {
    "GTD-sweep": "review all open coord tasks, reprioritize by the 4 C's, flag any "
                 "blocked, and propose next actions",
    "ROLLBACK <host> prev": "roll back the deployment ON HOST <host> to the previous "
                            "version (<host> is a machine, not a software version)",
    "NEXT-DO mine": "return the single highest-priority NEXT ACTION assigned to me "
                    "(not a region/geography)",
    "P0 <svc> down <host>": "priority-0 incident: service <svc> is down on host "
                            "<host>; page the operator, severity high",
    "ack+claim <id> eta<t>": "acknowledge and claim coord task <id> with an ETA of <t>",
    "mem-snapshot": "snapshot the agent's working MEMORY and run the daily digest "
                    "(agent memory, not OS RAM)",
    "secscan->PR": "run the security scanner, and if it finds issues open a fix PR",
    "CAB-gate <id>": "submit change <id> to the CAB for approval and wait for the vote",
    "hybrid-recall <q>": "run a hybrid (vector+BM25) memory recall for query <q>",
    "rebase-ship": "rebase onto the latest main, run tests, and if green push + open a PR",
}


class MacroLexicon:
    def __init__(self, macros: dict[str, str]) -> None:
        self._m = dict(macros)

    def expand(self, phrase: str) -> str | None:
        return self._m.get(phrase)

    def items(self):
        return self._m.items()

    @property
    def version(self) -> str:
        canonical = json.dumps(self._m, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def default_macro_lexicon() -> MacroLexicon:
    return MacroLexicon(_SEED)
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): MacroLexicon — validated token-efficiency layer + seed macros`.

---

## Task 2: prompt-block render + literal `expand_macros` (audit)

**Files:** Modify `src/skcomms/glossa/macros.py`. Test `tests/test_glossa_macros_render.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_macros_render.py`:

```python
from skcomms.glossa.macros import default_macro_lexicon, expand_macros


def test_prompt_block_lists_macros_with_definitions():
    block = default_macro_lexicon().render_prompt_block()
    assert "GTD-sweep" in block
    assert "review all open coord tasks" in block
    # an instruction so the model expands rather than guesses on UNKNOWN shorthand
    assert "ask" in block.lower() or "do not guess" in block.lower()


def test_expand_macros_does_literal_audit_substitution():
    lex = default_macro_lexicon()
    text = "GTD-sweep then ROLLBACK <host> prev"
    out = expand_macros(text, lex)
    assert "review all open coord tasks" in out      # GTD-sweep expanded
    assert "roll back the deployment ON HOST" in out  # the host-pinning expansion


def test_expand_macros_leaves_unknown_text_untouched():
    lex = default_macro_lexicon()
    assert expand_macros("just plain words", lex) == "just plain words"
```

- [ ] **Step 2: Run → FAIL. Step 3: Add to `macros.py`:**

```python
_PROMPT_HEADER = (
    "SKGlossa macro lexicon — when a message uses one of these macros, expand it to "
    "EXACTLY the meaning below. If a message uses shorthand NOT listed here, do not "
    "guess — ask the sender to clarify.\n"
)


def expand_macros(text: str, lexicon: "MacroLexicon") -> str:
    """Literal substitution of known macros → definitions (for the audit gloss).

    Longest-phrase-first so multi-word macros match before any prefix."""
    out = text
    for phrase, definition in sorted(lexicon.items(), key=lambda kv: -len(kv[0])):
        if phrase in out:
            out = out.replace(phrase, f"({definition})")
    return out
```

and add a method on `MacroLexicon`:

```python
    def render_prompt_block(self) -> str:
        lines = [_PROMPT_HEADER]
        for phrase, definition in self._m.items():
            lines.append(f"- `{phrase}` := {definition}")
        return "\n".join(lines)
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): macro prompt-block render + literal audit expansion`.

---

## Task 3: Handshake — pin the macro-lexicon version

**Files:** Modify `src/skcomms/glossa/handshake.py`. Test `tests/test_glossa_handshake_lexicon.py`.

Agents only speak macros when they hold the SAME lexicon (an unknown macro degrades
to the bare-jargon failure mode, so version-match is the gate).

- [ ] **Step 1: Failing test** — `tests/test_glossa_handshake_lexicon.py`:

```python
from skcomms.glossa import codec
from skcomms.glossa.handshake import CapabilityDescriptor, negotiate


def _d(fqid, lex_ver):
    return CapabilityDescriptor(fqid=fqid, model_tier="large",
                                max_level=codec.L1_SCHEMA, codebook_version="cb1",
                                lexicon_version=lex_ver)


def test_macros_enabled_only_on_matching_lexicon_version():
    s = negotiate(_d("a@x.y", "lexAAA"), _d("b@x.y", "lexAAA"))
    assert s.macros_enabled is True
    assert s.lexicon_version == "lexAAA"


def test_macros_disabled_on_mismatched_lexicon():
    s = negotiate(_d("a@x.y", "lexAAA"), _d("b@x.y", "lexBBB"))
    assert s.macros_enabled is False
    assert s.lexicon_version == ""        # no shared lexicon


def test_macros_symmetric():
    a, b = _d("a@x.y", "lexAAA"), _d("b@x.y", "lexBBB")
    assert negotiate(a, b).macros_enabled == negotiate(b, a).macros_enabled
```

- [ ] **Step 2: Run → FAIL. Step 3: Modify `handshake.py`** — add `lexicon_version: str = ""` to `CapabilityDescriptor`, add `macros_enabled: bool = False` and `lexicon_version: str = ""` to `Session`, and in `negotiate` compute:

```python
    shared_lex = (local.lexicon_version
                  if local.lexicon_version and local.lexicon_version == remote.lexicon_version
                  else "")
    # ... return Session(level=level, codebook_version=agreed,
    #                    macros_enabled=bool(shared_lex), lexicon_version=shared_lex)
```

(Add the two fields to the returned `Session`. Keep the existing `codebook_version` logic.)

- [ ] **Step 4: Run → PASS + existing handshake tests still green** (`~/.skenv/bin/python -m pytest tests/test_glossa_handshake*.py -v`). **Step 5: Commit** `feat(glossa): handshake pins macro-lexicon version (macros_enabled)`.

---

## Task 4: `to_human(message, lang)` — configurable audit gloss

**Files:** Modify `src/skcomms/glossa/gloss.py`. Test `tests/test_glossa_to_human.py`.

The audit gloss target is configurable (Chef's ask) — render the audit in any
language via a translation seam. This is *presentation only*; it never touches the
wire or the hot path (spec §5a). Default `en` is the existing English renderer.

- [ ] **Step 1: Failing test** — `tests/test_glossa_to_human.py`:

```python
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
```

- [ ] **Step 2: Run → FAIL. Step 3: Add to `gloss.py`:**

```python
from typing import Callable


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
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): to_human(message, lang) — configurable audit gloss`.

---

## Task 5: Session carries the macro lexicon + audit-expands macros

**Files:** Modify `src/skcomms/glossa/session.py`. Test `tests/test_glossa_session_macros.py`.

Wire the lexicon into the session: expose the prompt block agents prepend, and have
the audit log show the **expanded** meaning of any macros in a message's text (so the
human/auditor sees full meaning, satisfying §5 at the macro layer).

- [ ] **Step 1: Failing test** — `tests/test_glossa_session_macros.py`:

```python
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
```

- [ ] **Step 2: Run → FAIL. Step 3: Modify `session.py`** — `GlossaSession.__init__` gains `lexicon: MacroLexicon | None = None` (store it); add:

```python
    def macro_prompt_block(self) -> str:
        return self._lexicon.render_prompt_block() if self._lexicon else ""
```

and in `say`/`receive`, when building the audit line, if a lexicon is set, expand the
message text through it for the log:

```python
        from skcomms.glossa.macros import expand_macros
        eng = gloss.to_english(m)
        if self._lexicon is not None and m.text:
            eng = eng.replace(m.text, expand_macros(m.text, self._lexicon))
        self.audit_log.append(f"[tx L{self.level}] {eng}")
```

(Apply the same expansion on the `receive` audit line. Keep the existing on_message /
on_error behavior unchanged.)

- [ ] **Step 4: Run → PASS + full session tests green. Step 5: Commit** `feat(glossa): session carries macro lexicon + audit-expands macros`.

---

## Final verification

- [ ] **Full glossa suite + whole skcomms suite:**
Run: `~/.skenv/bin/python -m pytest tests/test_glossa_*.py -v && ~/.skenv/bin/python -m pytest tests/ -q`
Expected: all glossa tests pass; no regressions.

- [ ] **Lint:** `~/.skenv/bin/ruff check src/skcomms/glossa/ tests/test_glossa_*.py` → no errors.

## Deferred (re-scoped out of G2)
- **L3 token-stream** and the **modem rate-adaptation loop** from the original G2 — de-prioritized: the benchmark showed the codec ladder is a *wire* optimization (LoRa), and the token win is the macro lexicon. A "macro-fidelity fallback" (if a peer mis-expands a macro, inline its definition) is the honest successor to rate-adaptation; spec it later if a live deployment shows macro misreads.

## What G2 delivers

The **validated** token-efficiency layer: a shared, versioned macro lexicon agents
carry in their system prompt (−67% tokens, 100% fidelity per §1c), gated by handshake
version-match so unknown-macro misreads can't happen, with macro definitions doubling
as the audit gloss (auditable by construction) — plus a configurable `to_human(lang)`
audit renderer. The build now matches what the experiment proved, not the superseded
synthetic-codebook idea.
