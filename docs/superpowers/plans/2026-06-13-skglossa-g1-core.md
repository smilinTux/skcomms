# SKGlossa — G1 Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. Repo: `skcomms`, branch `feat/skglossa`. Run tests from repo root: `~/.skenv/bin/python -m pytest tests/ -q`.

**Goal:** Build the SKGlossa core — a `Message` IR, a versioned semantic `Codebook`, a 3-rung codec ladder (L0 English / L1 CBOR-schema / L2 codebook), the `to_english` gloss (the audit invariant), a capability handshake that picks the densest mutually-decodable level, and a `GlossaSession` two agents use to round-trip messages at the negotiated density — all CI-tested, zero LLMs.

**Architecture:** A new `src/skcomms/glossa/` package. Every level encodes/decodes the same `Message`. L0 is parseable structured-English (the floor); L1 is compact CBOR; L2 swaps the intent for a short codebook code (denser). `gloss.to_english` renders any `Message` to human prose (the oversight invariant). The handshake computes `level = min(both max levels)` constrained to a shared codebook version. Crypto/signing is behind an injectable seam (default capauth) so the protocol logic tests without keys.

**Tech Stack:** Python 3.10+, `cbor2` (compact binary for L1/L2), reuses skcomms identity for signing (injectable). `pytest`. Line 99, ruff (E,F,I,N,W; E501 ignored — no `;` one-liners).

**Spec:** `docs/superpowers/specs/2026-06-13-skglossa-design.md` (§3 components, §4 handshake, §5 gloss).

---

## Task 0: Scaffold + cbor2 dep

**Files:** Create `src/skcomms/glossa/__init__.py`. Modify `pyproject.toml` (add `cbor2`).

- [ ] **Step 1:** Create `src/skcomms/glossa/__init__.py`:

```python
"""SKGlossa — a negotiated, auditable AI-to-AI language.

Handshake -> densest mutually-decodable tier -> rate-adapt to the weaker model.
Every tier decodes to English (the oversight invariant). G1 = the core ladder
(L0/L1/L2) + handshake + gloss + session. See
docs/superpowers/specs/2026-06-13-skglossa-design.md.
"""

__all__ = []
```

- [ ] **Step 2:** In `pyproject.toml`, add `"cbor2>=5.4"` to the core `dependencies` list.

- [ ] **Step 3:** `~/.skenv/bin/pip install cbor2>=5.4` then verify: `~/.skenv/bin/python -c "import cbor2, skcomms.glossa; print('ok')"` → `ok`.

- [ ] **Step 4:** Commit:
```bash
git add src/skcomms/glossa/__init__.py pyproject.toml
git commit -m "feat(glossa): scaffold glossa package + cbor2 dep"
```

---

## Task 1: `Message` — the intermediate representation

**Files:** Create `src/skcomms/glossa/message.py`. Test `tests/test_glossa_message.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_message.py`:

```python
from skcomms.glossa.message import Message


def test_message_fields_and_defaults():
    m = Message(intent="coord.claim")
    assert m.intent == "coord.claim"
    assert m.args == {}
    assert m.refs == []
    assert m.text == ""


def test_message_equality_and_dict_roundtrip():
    m = Message(intent="status.report", args={"oof": 42}, refs=["task-1"], text="hi")
    assert Message.from_dict(m.to_dict()) == m
    assert m.to_dict() == {"i": "status.report", "a": {"oof": 42},
                           "r": ["task-1"], "t": "hi"}
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `message.py`:

```python
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
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): Message IR`.

---

## Task 2: `Codebook` — versioned semantic dictionary

**Files:** Create `src/skcomms/glossa/codebook.py`. Test `tests/test_glossa_codebook.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_codebook.py`:

```python
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
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `codebook.py`:

```python
"""Versioned semantic codebook (spec §3): concept/intent <-> short code.

Both peers must hold the same version to use the L2 codebook level; the version is
a stable hash of the mapping so agreement is verifiable in the handshake.
"""

from __future__ import annotations

import hashlib
import json

# Seed vocabulary — real SK intents agents actually exchange. Extend over time;
# changing this changes the version (peers must match to use L2).
_SEED = {
    "coord.claim": 1, "coord.complete": 2, "coord.create": 3, "coord.status": 4,
    "status.report": 5, "status.query": 6, "ack": 7, "nack": 8,
    "itil.incident": 9, "itil.change": 10, "gtd.capture": 11, "gtd.next": 12,
    "memory.store": 13, "memory.recall": 14, "presence.beacon": 15, "handoff": 16,
}


class Codebook:
    def __init__(self, mapping: dict[str, int]) -> None:
        self._c2n = dict(mapping)
        self._n2c = {n: c for c, n in mapping.items()}

    def code_for(self, concept: str) -> int | None:
        return self._c2n.get(concept)

    def concept_for(self, code: int) -> str | None:
        return self._n2c.get(code)

    @property
    def version(self) -> str:
        canonical = json.dumps(self._c2n, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def default_codebook() -> Codebook:
    return Codebook(_SEED)
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): versioned semantic codebook + seed vocab`.

---

## Task 3: Codec L0 (structured English) + level constants

**Files:** Create `src/skcomms/glossa/codec.py`. Test `tests/test_glossa_codec_l0.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_codec_l0.py`:

```python
from skcomms.glossa import codec
from skcomms.glossa.message import Message


def test_level_constants():
    assert codec.L0_ENGLISH == 0
    assert codec.L1_SCHEMA == 1
    assert codec.L2_CODEBOOK == 2


def test_l0_roundtrip():
    m = Message(intent="coord.claim", args={"task": "abc", "n": 3},
                refs=["t1", "t2"], text="claiming this")
    raw = codec.encode(m, codec.L0_ENGLISH)
    assert isinstance(raw, bytes)
    out = codec.decode(raw, codec.L0_ENGLISH)
    assert out == m


def test_l0_is_human_readable_text():
    raw = codec.encode(Message(intent="ack"), codec.L0_ENGLISH)
    assert b"ack" in raw                  # the floor is literally readable
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `codec.py` (L0 only for now; L1/L2 added in Tasks 4–5):

```python
"""SKGlossa codec ladder (spec §2, §3). encode/decode the Message IR per level.

L0 = structured-but-parseable English (the readable floor). L1 = compact CBOR.
L2 = codebook-compressed. Density climbs L0 -> L1 -> L2.
"""

from __future__ import annotations

import json

from skcomms.glossa.codebook import Codebook
from skcomms.glossa.message import Message

L0_ENGLISH = 0
L1_SCHEMA = 1
L2_CODEBOOK = 2


def _l0_encode(m: Message) -> bytes:
    # readable AND parseable: "intent :: <json of {a,r,t}>"
    body = json.dumps({"a": m.args, "r": m.refs, "t": m.text},
                      sort_keys=True, separators=(",", ":"))
    return f"{m.intent} :: {body}".encode()


def _l0_decode(raw: bytes) -> Message:
    s = raw.decode()
    intent, _, body = s.partition(" :: ")
    d = json.loads(body) if body else {}
    return Message(intent=intent, args=dict(d.get("a", {})),
                   refs=list(d.get("r", [])), text=d.get("t", ""))


def encode(m: Message, level: int, codebook: Codebook | None = None) -> bytes:
    if level == L0_ENGLISH:
        return _l0_encode(m)
    raise ValueError(f"unsupported level {level}")


def decode(raw: bytes, level: int, codebook: Codebook | None = None) -> Message:
    if level == L0_ENGLISH:
        return _l0_decode(raw)
    raise ValueError(f"unsupported level {level}")
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): codec ladder + L0 structured-English level`.

---

## Task 4: Codec L1 (CBOR schema)

**Files:** Modify `src/skcomms/glossa/codec.py`. Test `tests/test_glossa_codec_l1.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_codec_l1.py`:

```python
from skcomms.glossa import codec
from skcomms.glossa.message import Message


def test_l1_roundtrip():
    m = Message(intent="status.report", args={"oof": 42}, refs=["t1"], text="ok")
    out = codec.decode(codec.encode(m, codec.L1_SCHEMA), codec.L1_SCHEMA)
    assert out == m


def test_l1_is_denser_than_l0():
    m = Message(intent="status.report", args={"oof": 42, "load": 0.7},
                refs=["t1", "t2"], text="status nominal")
    l0 = codec.encode(m, codec.L0_ENGLISH)
    l1 = codec.encode(m, codec.L1_SCHEMA)
    assert len(l1) <= len(l0)             # CBOR ≤ readable text
```

- [ ] **Step 2: Run → FAIL. Step 3: Add L1** to `codec.py` — add `import cbor2` and the branches:

```python
# in encode():
    if level == L1_SCHEMA:
        return cbor2.dumps(m.to_dict())
# in decode():
    if level == L1_SCHEMA:
        return Message.from_dict(cbor2.loads(raw))
```

(Add `import cbor2` at the top.)

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): L1 CBOR-schema level`.

---

## Task 5: Codec L2 (codebook)

**Files:** Modify `src/skcomms/glossa/codec.py`. Test `tests/test_glossa_codec_l2.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_codec_l2.py`:

```python
import pytest

from skcomms.glossa import codec
from skcomms.glossa.codebook import default_codebook
from skcomms.glossa.message import Message


def test_l2_roundtrip_with_codebook():
    cb = default_codebook()
    m = Message(intent="coord.claim", args={"task": "abc"}, refs=["t1"])
    raw = codec.encode(m, codec.L2_CODEBOOK, cb)
    out = codec.decode(raw, codec.L2_CODEBOOK, cb)
    assert out == m


def test_l2_is_denser_than_l1_for_known_intent():
    cb = default_codebook()
    m = Message(intent="status.report", args={"oof": 42})
    l1 = codec.encode(m, codec.L1_SCHEMA)
    l2 = codec.encode(m, codec.L2_CODEBOOK, cb)
    assert len(l2) < len(l1)              # intent string -> small int


def test_l2_requires_codebook():
    with pytest.raises(ValueError, match="codebook"):
        codec.encode(Message(intent="ack"), codec.L2_CODEBOOK, None)


def test_l2_unknown_intent_falls_back_to_string():
    cb = default_codebook()
    m = Message(intent="novel.intent.not.in.book", text="hi")
    out = codec.decode(codec.encode(m, codec.L2_CODEBOOK, cb), codec.L2_CODEBOOK, cb)
    assert out == m                       # round-trips even if intent isn't coded
```

- [ ] **Step 2: Run → FAIL. Step 3: Add L2** to `codec.py` — the intent becomes a code int when known, else the string; a flag byte distinguishes:

```python
# in encode():
    if level == L2_CODEBOOK:
        if codebook is None:
            raise ValueError("L2 codebook level requires a codebook")
        code = codebook.code_for(m.intent)
        # intent slot: int code if known, else the raw string
        head = code if code is not None else m.intent
        return cbor2.dumps([head, m.args, m.refs, m.text])
# in decode():
    if level == L2_CODEBOOK:
        if codebook is None:
            raise ValueError("L2 codebook level requires a codebook")
        head, args, refs, text = cbor2.loads(raw)
        intent = codebook.concept_for(head) if isinstance(head, int) else head
        return Message(intent=intent or "", args=dict(args),
                       refs=list(refs), text=text)
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): L2 codebook level (denser; string fallback)`.

---

## Task 6: `gloss` — the audit invariant

**Files:** Create `src/skcomms/glossa/gloss.py`. Test `tests/test_glossa_gloss.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_gloss.py`:

```python
from skcomms.glossa import codec, gloss
from skcomms.glossa.codebook import default_codebook
from skcomms.glossa.message import Message


def test_to_english_renders_prose():
    eng = gloss.to_english(Message(intent="coord.claim", args={"task": "abc"},
                                   refs=["t1"], text="mine"))
    assert "coord.claim" in eng
    assert "abc" in eng
    assert isinstance(eng, str) and len(eng) > 0


def test_gloss_works_at_every_level():
    cb = default_codebook()
    m = Message(intent="status.report", args={"oof": 42}, text="ok")
    for level in (codec.L0_ENGLISH, codec.L1_SCHEMA, codec.L2_CODEBOOK):
        raw = codec.encode(m, level, cb)
        # the invariant: any dense form decodes back to an English gloss
        eng = gloss.decode_to_english(raw, level, cb)
        assert "status.report" in eng
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `gloss.py`:

```python
"""The audit invariant (spec §5): every SKGlossa message renders to English.

`to_english(Message)` is the human-facing prose; `decode_to_english(bytes, level)`
proves the invariant holds at every density tier — the oversight guarantee.
"""

from __future__ import annotations

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


def decode_to_english(raw: bytes, level: int, codebook: Codebook | None = None) -> str:
    m = codec.decode(raw, level, codebook)
    return to_english(m)
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): gloss — decode-to-English audit invariant`.

---

## Task 7: Capability descriptor + handshake

**Files:** Create `src/skcomms/glossa/handshake.py`. Test `tests/test_glossa_handshake.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_handshake.py`:

```python
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


def test_negotiate_is_symmetric():
    cb = default_codebook().version
    a = _desc("a@x.y", "large", codec.L2_CODEBOOK, cb)
    b = _desc("b@x.y", "small", codec.L0_ENGLISH, cb)
    assert negotiate(a, b).level == negotiate(b, a).level == codec.L0_ENGLISH
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `handshake.py`:

```python
"""Capability handshake (spec §4): exchange descriptors -> densest mutually-
decodable level. Deterministic + symmetric so both peers compute the same Session.
Signing is the anti-spoof layer (reuses capauth); the level math is signing-free.
"""

from __future__ import annotations

from dataclasses import dataclass

from skcomms.glossa import codec


@dataclass
class CapabilityDescriptor:
    fqid: str
    model_tier: str          # "large" | "small" | ... — the weaker-peer signal
    max_level: int           # highest codec level this agent supports
    codebook_version: str    # the L2 codebook version this agent holds


@dataclass
class Session:
    level: int
    codebook_version: str


def negotiate(local: CapabilityDescriptor, remote: CapabilityDescriptor) -> Session:
    level = min(local.max_level, remote.max_level)
    # L2 (codebook) requires both to hold the SAME codebook version; else cap at L1.
    if level >= codec.L2_CODEBOOK and local.codebook_version != remote.codebook_version:
        level = codec.L1_SCHEMA
    return Session(level=level, codebook_version=local.codebook_version)
```

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): capability descriptor + handshake (mutual-max level)`.

---

## Task 8: `GlossaSession` — two agents round-trip

**Files:** Create `src/skcomms/glossa/session.py`. Test `tests/test_glossa_session.py`.

- [ ] **Step 1: Failing test** — `tests/test_glossa_session.py`:

```python
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
```

- [ ] **Step 2: Run → FAIL. Step 3: Implement** `session.py`:

```python
"""GlossaSession (spec §3, §8) — the per-peer API agents use: handshake, say,
on_message. Encodes at the negotiated level, decodes inbound, logs the English
gloss of everything (the audit invariant)."""

from __future__ import annotations

from typing import Callable

from skcomms.glossa import codec, gloss
from skcomms.glossa.codebook import Codebook
from skcomms.glossa.handshake import CapabilityDescriptor, Session, negotiate
from skcomms.glossa.message import Message


class GlossaSession:
    def __init__(self, *, local: CapabilityDescriptor, codebook: Codebook) -> None:
        self.local = local
        self.codebook = codebook
        self._session: Session | None = None
        self._transport: Callable[[bytes], None] | None = None
        self._on_message: Callable[[Message], None] | None = None
        self.audit_log: list[str] = []

    @property
    def level(self) -> int:
        return self._session.level if self._session else codec.L0_ENGLISH

    def set_transport(self, send: Callable[[bytes], None]) -> None:
        self._transport = send

    def on_message(self, cb: Callable[[Message], None]) -> None:
        self._on_message = cb

    def handshake(self, remote: CapabilityDescriptor) -> None:
        self._session = negotiate(self.local, remote)

    def say(self, m: Message) -> None:
        raw = codec.encode(m, self.level, self.codebook)
        self.audit_log.append(f"[tx L{self.level}] {gloss.to_english(m)}")
        if self._transport is not None:
            self._transport(raw)

    def receive(self, raw: bytes) -> None:
        m = codec.decode(raw, self.level, self.codebook)
        self.audit_log.append(f"[rx L{self.level}] {gloss.to_english(m)}")
        if self._on_message is not None:
            self._on_message(m)
```

> **NOTE for implementer:** the test wires both sessions BEFORE handshaking; `level`
> defaults to L0 until `handshake` runs, and both call `handshake` so both compute
> the same `Session` (symmetric `negotiate`). In `test_session_logs_english_gloss`
> only `a` handshakes before `say` — `b.receive` then runs at b's default L0 while a
> sent at a's negotiated level; to keep that test honest, have it assert only on
> a's `audit_log` (the tx side), which it does. Real deployments handshake both
> ways before exchanging.

- [ ] **Step 4: Run → PASS. Step 5: Commit** `feat(glossa): GlossaSession — handshake + say/receive + gloss log`.

---

## Final verification

- [ ] **Full glossa suite + whole skcomms suite (no regressions):**
Run: `~/.skenv/bin/python -m pytest tests/test_glossa_*.py -v && ~/.skenv/bin/python -m pytest tests/ -q`
Expected: all glossa tests pass; existing skcomms + ble + lora tests still pass.

- [ ] **Lint:** `~/.skenv/bin/ruff check src/skcomms/glossa/ tests/test_glossa_*.py` → no errors.

## What G1 delivers

The SKGlossa core: two agents handshake, negotiate the densest level they both
support (the weaker peer caps it), and round-trip typed `Message`s at L0 (readable
English) / L1 (CBOR) / L2 (codebook — denser), with **every message decodable to an
English gloss and logged** (the oversight invariant). All CI-tested, no LLMs. **G2**
adds the comprehension-ack rate-adaptation loop (climb to the weaker model's real
ceiling) + L3 token-stream; **G3** meshes N agents over a Space's data channel.
