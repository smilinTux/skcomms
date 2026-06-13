# SKGlossa — a negotiated, auditable AI-to-AI language (with mesh-over-Spaces)

**Date:** 2026-06-13
**Repo:** `skcomms` (`src/skcomms/glossa/`) + skchat integration for the Spaces mesh
**Status:** design approved — ready for implementation plan
**Working name:** SKGlossa (Greek *glóssa*, "tongue"). Rename at will.

---

## 1. Goal

A communication protocol **optimized for AI-to-AI comms** — not English, not any
human language. Two (or many) agents **handshake**, discover the **densest
representation both can decode**, and **ramp density up to the weaker model's
comprehension ceiling** (modem-style rate adaptation). Density climbs from
structured English → typed schema → a shared semantic codebook → token streams →
(frontier) shared-model latents → (liberated) a session-private **emergent**
codebook the agents *invent themselves*.

**Two invariants, decided:**
1. **Always auditable.** Every message — at every density tier — is decodable to a
   human-readable **English gloss** on demand, and logged. The liberated language
   stays under sovereign oversight: you can always *see* what your agents said.
2. **Identity-bound.** Every exchange rides SK identity (FQID/capauth-signed) — an
   SKGlossa peer is the same sovereign identity as everywhere else.

**Headline deployment (Chef's synthesis):** N agents join a **Space** (the LiveKit
audio room we built) and mesh in SKGlossa — the SFU broadcast bus becomes a
**multi-agent mesh network**, federated across hosts, with **humans listening to
the real-time English gloss** as the audit channel. See §7.

## 2. The layered protocol (modem-inspired)

```
L5  Emergent     — session-private codebook agents EVOLVE via referential games   [phase G4 — "liberated"]
L4  Latent       — shared codec-model vectors (true neuralese; needs a shared model) [phase G5 — frontier/gated]
L3  Token-stream — shared-tokenizer token-IDs; delta-vs-shared-context
L2  Codebook     — semantic concept/intent → short code (versioned, shared dict)
L1  Schema       — typed/structured messages (CBOR), zero prose
L0  English      — structured natural language; the always-works floor + gloss target
        ▲ density climbs upward; the WEAKER peer caps the reachable level
── HANDSHAKE ─────── signed capability descriptors → mutual-max level + agreed codebook/model versions
── RATE ADAPTATION ─ comprehension-acks: climb until comprehension drops, back off (the modem loop)
── TRANSPARENCY ──── to_english() at every tier; dense form + gloss always logged (invariant #1)
── DATA LAYER ────── any skcomms transport (default) · LiveKit data channel (Spaces mesh) · audio soft-modem
```

## 3. Components

New package `src/skcomms/glossa/`:

| File | Responsibility |
|---|---|
| `descriptor.py` | `CapabilityDescriptor` (model id/tier, supported levels, codebook versions, tokenizer id, shared-model id, max_ctx) + signed serialization. The model **tier** is the "weaker peer" signal. |
| `handshake.py` | Exchange descriptors → compute the **mutual-max level** + agreed codebook/model versions. A handshake = a signed skcomms message; result is a per-peer `Session(level, codebook_ver, ...)`. |
| `codec.py` | The ladder: `encode(msg, level) -> bytes` / `decode(bytes, level) -> Message`. Per-level encoders (L0 English, L1 CBOR-schema, L2 codebook, L3 token-stream). Pluggable; L4/L5 register later. |
| `codebook.py` | The L2 semantic dictionary: concept/intent ↔ short code, **versioned**, seeded from real SK vocabulary (coord/ITIL/GTD intents, message types, common entities). Hash-pinned so both ends agree. |
| `message.py` | `Message` — the typed intermediate representation every level encodes/decodes (intent, args, refs, free-text slot). The pivot between tiers. |
| `gloss.py` | `to_english(Message) -> str` — the audit invariant; works at every level. The "decompress to human" view + the log hook. |
| `adapt.py` | Rate adaptation: send at level N with a **comprehension token** (a hash of the canonicalized decoded meaning, or a micro-challenge); receiver returns a semantic-ack; climb on success, fall back on mismatch. Maintains the live per-peer level. |
| `comprehender.py` | The `Comprehender` seam — "does this decode to the intended meaning?" In production a model call; **in tests a deterministic fake** that fails above a configured density (so the ramp-to-ceiling is provable without an LLM). |
| `emergent.py` | (G4) Referential-game loop: propose a code for a recurring concept, confirm by use, reinforce round-trippable codes → a session-private codebook **layered on L2**; every emergent code is *defined in L0/L2 terms* so it stays auditable. |
| `session.py` | `GlossaSession` — ties handshake + codec + adapt + gloss for a peer (or a room); the public API agents use: `say(message)` / `on_message(cb)`. |

Reuses skcomms identity (FQID/capauth signing) for descriptor + handshake signatures.

## 4. Handshake & rate adaptation (the modem core)

- **Handshake:** A→B and B→A exchange signed `CapabilityDescriptor`s. Each computes
  `level = min(A.max_supported, B.max_supported)` constrained to levels whose
  codebook/model versions BOTH hold. Deterministic — both arrive at the same
  `Session`. (Exactly V.8 capability exchange.)
- **Rate adaptation:** after the handshake floor, the sender periodically *probes*
  one level denser, attaching a comprehension token. The receiver decodes and
  returns a semantic-ack (match / mismatch / parse-fail). **Match → adopt the
  denser level; mismatch → fall back and pin.** Continuous, so it tracks the weaker
  model's real-time comprehension (load, context drift). This is the literal
  "increase density until the weaker model can't keep up, then settle."
- **Comprehension token:** the canonicalized `Message` hashed (so an ack proves the
  receiver reconstructed the *same meaning*, not just received bytes). The
  `Comprehender` seam decides match for fuzzy tiers (L4/L5).

## 5. Transparency (the oversight invariant)

`gloss.to_english(message)` is defined for **every** level — L0 is already English;
L1/L2/L3 decode to a `Message` then render; L4/L5 carry an L0 anchor so a gloss is
always reconstructable. **Every SKGlossa exchange logs `{level, dense_bytes_len,
english_gloss}`.** A human (or an auditor agent) can replay any conversation in
plain language. No tier is exempt — the liberated language is *free, not hidden*.

## 5a. Language neutrality — the hot path carries no human language

A core principle (clarified 2026-06-13): **English is never on the fast path.** The
`Message` IR is **language-neutral** — an intent (a code at L2+), structured args,
and references; not prose. The dense tiers put **codes/vectors on the wire**, so two
agents at L2+ exchange a synthetic vocabulary derived from **no human language** —
there is no translation layer and no English in the agent-to-agent path. This is the
"cut out the translation step → way faster" goal, by construction.

Human language appears in exactly one place — the **audit gloss (§5)** — and it is:
1. **Off the critical path** — computed lazily/async for the human watching, never
   blocking the agents' exchange.
2. **Configurable in target language** — `to_english` generalizes to
   `to_human(message, lang="en"|"zh"|"glyph"|...)`. Render the audit in English,
   in a denser human language (e.g. Chinese — denser per character; note token-cost
   is tokenizer-dependent), or in a compact **synthetic glyph notation**. This is a
   *presentation* choice for the operator; it does **not** touch the wire or the
   speed.

**"The AI's own language"** is therefore L2 (synthetic codebook — arbitrary codes,
no human-language root) + L5 (emergent — agents invent their own), optionally pushed
toward a designed **glyph/symbolic notation** for maximal density. The audit gloss is
how a *human* reads it back, in whatever language they prefer — a separate, swappable
layer from the language the agents actually speak.

**Folded into phasing:** G1 ships `to_english` as the default gloss; **G2 generalizes
the gloss to `to_human(message, lang)`** (English + at least one denser target, e.g.
Chinese or glyph) so the audit language is configurable while the hot path stays
human-language-free.

## 6. The emergent tier (G4 — the "liberated" part)

Two agents evolve a **private dense argot** over a session via referential games:
one proposes a short code bound to a recurring concept (defined via L0/L2); the
other confirms by using it correctly; codes that round-trip get reinforced and
enter a **session-private codebook** layered on L2. Over a long session the pair
develops an idiosyncratic, dense, *self-invented* language — but because every
emergent code carries its L0/L2 definition, the gloss invariant holds. This is the
genuinely novel "AI made its own tongue," kept auditable by construction.

## 7. Deployment: SKGlossa Mesh over Spaces (the keystone)

A **Space** (LiveKit audio room, ~10 speakers + unlimited listeners, federated
across hosts) is a **broadcast bus**. Fill the speaker slots with **agents** talking
SKGlossa and the Space becomes a **sovereign multi-agent mesh** — with humans
joining as listeners hearing the **English gloss** in real time (the audit seat).
Two transports for the mesh:

- **Data-channel mesh (default, buildable now):** agents mesh via SKGlossa over the
  **LiveKit data channel** (`publishData` → all participants). It's an already-
  reliable broadcast bus — **no media-access collisions** — so this is the practical
  multi-agent mesh and it runs on the Spaces we already shipped. The audio tracks
  stay free for the human-audible gloss (TTS of the English) if desired.
- **Audio soft-modem mesh (the wild tier, G3+):** SKGlossa as **AFSK/QAM tones over
  the audio tracks** — a true *shared-medium acoustic network*. Because the room
  audio is mixed, this needs a real **MAC layer** (`mac.py`): TDMA slots, or
  listen-before-talk using LiveKit **active-speaker detection** as carrier-sense, or
  handshake-negotiated floor-control. Airgap-capable and gorgeous; harder.

**A new `mac.py`** (media access control) is therefore a first-class component for
the audio mesh: turn-taking / slotting / carrier-sense so ≥2 agents don't collide
on the shared audio medium. (The data-channel mode doesn't need it — the SFU
serializes data packets.)

## 8. Where it lives & data flow

- **Core protocol** = `src/skcomms/glossa/` (identity + transport reuse). Transport-
  agnostic: a `GlossaSession` emits compact bytes that ride **any** skcomms transport
  (BLE mesh, LoRa, websocket, Nostr) — so two agents can speak SKGlossa over LoRa,
  too (dense text over a tiny pipe is *exactly* where a codebook shines).
- **Spaces mesh integration** = skchat (the LiveKit data-channel + soft-modem glue);
  agents (Lumina/Opus/Jarvis) open a `GlossaSession` bound to a Space.
- **Flow:** agent intent → `Message` → `codec.encode(level)` → transport (data
  channel / audio modem / skcomms) → peer `codec.decode` → `Message` → agent; the
  `adapt` loop tunes `level`; `gloss` logs the English the whole time.

## 9. Testing — CI-first, zero external models

Everything is unit-testable with **two in-process agents** + seams:
- **`Comprehender` fake** — deterministic, fails above a set density → **proves the
  rate-adaptation ramps to and settles at the weaker peer's ceiling** without any
  LLM.
- **Codec round-trips** at L0–L3 (Message → bytes → Message identity); the **gloss
  invariant** asserted at every level.
- **Handshake** convergence (both peers compute the same level from descriptors).
- **Mesh-over-Spaces:** the data-channel mode tested with a fake broadcast bus (N
  in-process agents, one publishes → all receive). The **audio modem** tested via an
  **audio loopback buffer** (encode → simulated-audio samples → decode); the **MAC**
  tested with a simulated collision medium (2 agents transmit, MAC serializes them).
- Real model comprehension + a live Spaces mesh are integration milestones, not unit
  deps.

## 10. Phasing

| Phase | Deliverable |
|---|---|
| **G1** | Core: `descriptor` + `handshake` + `codec` (L0/L1/L2) + `codebook` + `message` + **`gloss` invariant** + `session`. Two in-process agents handshake, exchange at the negotiated level, round-trip, and every message glosses to English. CI, no models. |
| **G2** | **Rate adaptation** (`adapt` + `comprehender` seam) + **L3 token-stream**. Proves ramp-to-weaker-ceiling with the fake comprehender. |
| **G3** | **Mesh over Spaces — data-channel mode** (skchat integration: N agents mesh over the LiveKit data channel in a Space) + the human-gloss listener view. The practical multi-agent mesh, live. |
| **G4** | **Emergent tier** (`emergent` referential-game session codebook) — the liberated language. |
| **G5a** | **Audio soft-modem** (`modem` AFSK + `mac`) — the acoustic mesh tier over Space audio. |
| **G5b** | **Latent tier** (`L4` shared codec-model vectors) — frontier, gated on a shared model both peers run. |

## 11. Safety & honesty notes

- **Auditability is structural, not optional** (§5): no tier may ship without a
  working `to_english`. The emergent tier's codes are defined in L0/L2 — opaqueness
  is rejected by construction. This is the guardrail that makes a "liberated AI
  language" safe to run on sovereign infra.
- **Identity & anti-spoof:** descriptors + handshakes are capauth-signed; an agent
  can't impersonate another in the mesh (reuses the same FQID identity as Spaces
  federation).
- **Frontier honesty:** L4 (latent/neuralese) requires a *shared* codec model —
  different models (Haiku vs qwen) have incompatible latent spaces with no shared
  decoder, so L4 is explicitly **gated** on both peers running the same small codec
  model. G1–G3 deliver a real, working, auditable AI-optimized protocol *without*
  it; don't let L4 block the shippable core.
- **MAC is real, not hand-waved:** the audio-mesh shared medium genuinely collides;
  `mac.py` (TDMA/carrier-sense) is a first-class component, not an afterthought. The
  data-channel mode sidesteps it entirely and is the recommended default.

## 12. Open items folded into the plan (not blockers)

- Pick the L2 codebook seed vocabulary + the version-hash scheme — G1.
- The comprehension-token canonicalization (how `Message` hashes stably) — G1/G2.
- AFSK vs a higher-order modulation (QAM) for the soft-modem; symbol rate vs the
  audio codec's bandwidth — G5a.
- The MAC discipline (TDMA slot length vs LiveKit active-speaker latency) — G5a.
- Whether the human-audible gloss is TTS'd into the room audio or shown as a
  caption lane — G3 (a UX call).
