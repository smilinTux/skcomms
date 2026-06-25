# RFC-0001 — Post-Quantum Ratchet, Metadata Privacy & Dual Identity

**Status:** Draft / for-implementation · **Date:** 2026-06-25 · **Owners:** Chef & Lumina
**Repos:** skcomms (transport/envelope/routing) · skchat (DM/group ratchet, app) · capauth (identity) · sksecurity (self-report)
**Standards:** [sk-standards](https://github.com/smilinTux/sk-standards) (crypto / doc-SOP / data-flow). Honest-claim rules apply throughout.

> One sentence: **adopt the best ideas from SimpleX, Signal, Apple, and MLS — Level-3
> post-quantum healing, metadata privacy, and a no-identity anonymity mode — as new
> suite-ids and backends on our existing crypto-agility scaffolding, never a rewrite,
> and never by copying AGPL code.**

---

## 0. Clean-room & license guardrail (read first)

SimpleX (`simplexmq`, `simplex-chat`) and Signal's SPQR (`SparsePostQuantumRatchet`)
are **AGPL-3.0**. We are **Apache-2.0**. Therefore:

- ✅ **Read the public protocol specs, RFCs, and blogs for *ideas* and wire-shape** —
  algorithms, message fields, sizes, and design patterns are facts/methods, not
  copyrightable expression.
- ❌ **Never paste or close-paraphrase their source** (Haskell/Rust/Kotlin/Swift) into
  our tree — it would force AGPL onto skchat. Clean-room: reimplement from the *spec*,
  document independent derivation in commits.
- Apple PQ3 and IETF MLS are ideas/standards-only by nature (no AGPL code).

---

## 1. Why (grounded comparison)

| Design | PQ handshake | PQ *ongoing* ratchet | Groups | Metadata | Identity | Agility |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **Signal PQXDH** | ✅ ML-KEM | ❌ (L2) | n/a | — | classical sig | — |
| **Signal SPQR / Triple Ratchet** | ✅ | ✅ per-msg, chunked+RS (L3) | — | — | classical sig | — |
| **Apple PQ3** | ✅ ML-KEM-1024 | ✅ periodic ~50msg/≤7d (L3) | — | — | classical ECDSA | — |
| **SimpleX** | ✅ sntrup761 | ✅ per-msg dual-KEM (L3) | ❌ (keygen) | 🥇 onion + padding + no-IDs | deniable **or** signed | ❌ hardcoded |
| **IETF MLS PQ (draft-04)** | ✅ | ✅ **per-epoch** | 🥇 TreeKEM O(log N) | — | classical **or** ML-DSA | suite-registry |
| **us (today)** | ✅ ML-KEM-768 (`pqdm1:`) | ❌ (L2) | ✅ epoch-ratchet | ⚠️ weak (signed envelopes) | 🥇 sovereign FQID + **hybrid ML-DSA sig** | 🥇 suite-ids + backend ABC + self-report |
| **us (this RFC)** | ✅ | ✅ **L3** | ✅ epoch (MLS-mapped) | ✅ padding + PQ-metadata + onion | 🥇 **dual: anon ↔ sovereign** | 🥇 |

**Takeaways that shaped this RFC:**
- Our `pqdm1:` prekey is already PQXDH (Level 2). Closing to **Level 3** is the clearest crypto win.
- **Per-message PQ doesn't scale to groups** (SimpleX admits sntrup761 keygen kills groups >10–20). MLS/TreeKEM and our **epoch-ratchet** are the right answer — *validated*.
- SimpleX leaves its **routing/metadata layer classical** — we can do **hybrid-ML-KEM on metadata** and *beat them on harvest-now-decrypt-later for metadata*.
- Our **hybrid Ed25519+ML-DSA-65 signatures are ahead** of PQ3 and the first seven MLS suites (still classical sigs).
- SimpleX already ships **deniable vs signed auth per-queue** → our **dual-identity switch is a proven design**, not a gamble.

---

## 2. Design

### 2.1 Dual identity — `auth_mode` is a suite-id, not an architecture

One envelope, one ratchet, one transport. The *identity layer* flips by a per-conversation
(or per-deployment-default) suite-id:

```mermaid
flowchart TD
    msg[outbound message] --> mode{auth_mode suite-id}
    mode -->|"anonymous (default)"| AN["🕶️ no capauth identity<br/>ephemeral per-queue keys<br/>deniable X25519/crypto_box-style MAC<br/>opaque queue IDs (RID/SID)"]
    mode -->|"sovereign (enterprise flag)"| SV["🪪 capauth FQID<br/>hybrid Ed25519+ML-DSA-65 sig<br/>federated, non-repudiable, auditable"]
    AN --> core[shared KEM + ratchet core]
    SV --> core
    core --> tx[padded, metadata-sealed transport]
```

- **anonymous** (default) — SimpleX topology: pairwise opaque queue IDs, **no capauth identity**, **deniable** auth (no signatures on content), MITM-resisted by OOB/QR link exchange (secrets in the URI hash fragment, never sent to the relay).
- **sovereign** (flag) — our FQID + **hybrid Ed25519+ML-DSA-65** identity signature, federated, auditable.
- **Invariants (enforced + self-reported):** a *sovereign* conversation **never silently downgrades** to anonymous; signatures stay **off the ratchet steps** in both modes so **content deniability** survives even in sovereign mode (identity is asserted only at session establishment). `sksecurity` self-report declares the active mode + what the relay can/can't see.

### 2.2 Level-3 post-quantum ratchet for 1:1 DMs

Make `pqdm1:` (Level 2) into **Level 3** by adding a hybrid **ML-KEM-768** rekey to the
*ongoing* ratchet — a **Triple Ratchet** (our X25519 Double Ratchet **and** an ML-KEM
ratchet in parallel, **KDF-combined so an attacker must break BOTH**):

```
RK', CKx = KDF_RK( RK,  X25519(dh_self, dh_peer)  ||  ML-KEM_ss )   # concat-then-KDF, never XOR
```

ML-KEM `ss` is already the FIPS-203 FO-hashed 32 bytes (the implicit-rejection hash sntrup
lacks), so concat-then-KDF is safe and strictly hybrid. **Two delivery strategies** behind
one suite-id family:

- **`pqdr-periodic-v1` (ship first, interim):** Apple-PQ3-style — trigger a hybrid ML-KEM
  rekey **adaptively (~every 50 messages, guaranteed ≤ every 7 days)**. A few-line policy,
  earns Level 3 immediately, ~2.3 KB ek+ct only on rekey messages.
- **`pqdr-braid-v1` (later, continuous PCS):** Signal-SPQR-style — **chunk** the ML-KEM
  ek/ct across consecutive messages and reconstruct with **Reed-Solomon systematic erasure
  codes** (any N-of-M), so per-message overhead is small and loss/reorder-tolerant; new
  shared secret begins a new epoch. Tighter PCS window at higher engineering cost.

Cold-start gap: PQ engages after a round-trip each way. We avoid ever being classical-only
at message 1 by keeping the **`pqdm1:` hybrid prekey** (PQXDH) for session establishment.

### 2.3 Groups — epoch-amortized, MLS-mapped (keep & formalize)

Do **not** per-message PQ for groups. Keep our **epoch-ratchet**; pay the hybrid
ML-KEM-768 keygen/encapsulation **once per epoch** (membership delta / time / message
bound), **O(log N)** the MLS/TreeKEM way. Map our suite-ids onto MLS naming for
standards-traceability and negotiation, e.g.
`skc-mlkem768x25519-aes256gcm-sha384-mldsa65` ≈
`MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`'s lower-tier sibling. (MLS PQ ciphersuites
are draft-04, Informational — pin the draft, keep agility to renumber.)

### 2.4 Metadata privacy — tiered, cheapest first

```mermaid
flowchart LR
    P["content padding<br/>(size ladder / fixed bucket)"]:::a
      --> M["metadata sealed in encrypted envelope<br/>(outer routing header vs inner meta+content)<br/>🟢 HYBRID ML-KEM — beats SimpleX's classical s2d"]:::b
      --> O["2-hop onion private routing<br/>sender picks hop-1, recipient picks hop-2<br/>(= the anonymity mode)"]:::c
    classDef a fill:#06281e,stroke:#34d399,color:#fff;
    classDef b fill:#0a1a2a,stroke:#67e8f9,color:#fff;
    classDef c fill:#1a0a2a,stroke:#c084fc,color:#fff;
```

1. **Content padding** *(low effort, do first)* — length-prefix + pad each envelope to a
   bucket **before** transport encrypt. Prefer a small **ladder** (e.g. 4/16/64/256 KiB)
   over SimpleX's single 16 KiB bucket (their bucket wastes bandwidth on small DMs; a
   ladder leaks only a coarse size class). Suite-flag `pad=ladder-v1` for the self-report.
2. **Metadata-in-encrypted-envelope** *(medium effort, best value)* — split envelope into an
   **outer routing header** (only what the next hop needs) and an **inner metadata+content**
   blob sealed to the destination with our **hybrid X25519+ML-KEM-768** KEM (new suite-id
   `pqroute1:`). Intermediate relays/federation nodes see neither the final FQID nor flags.
   *This is where we beat SimpleX* (they kept routing classical).
3. **2-hop onion private routing** *(high effort = the anonymity mode)* — sender chooses
   the forwarding node, recipient publishes the destination node; per-hop ephemeral hybrid
   KEM; the forwarding node **re-encrypts outbound** so no ciphertext/identifier is common
   in/out (the f2d traffic-correlation defense, even if TLS breaks).
4. **Transport:** TLS 1.3 only; bind the app session with **RFC 9266 `tls-exporter`** (not
   SimpleX's `tls-unique`, which is TLS≤1.2 semantics).

> **Honest scope:** over a *small sovereign tailnet* the anonymity set is tiny → weaker
> unlinkability than SimpleX's public relay pool. The self-report must say so; never claim
> Tor-grade anonymity on a 3-node net.

### 2.5 Architecture — one shared crypto core (the core-library pattern)

Mirror SimpleX's shared-core design: **one audited crypto/protocol core** (our hybrid
prekey, Triple Ratchet, epoch-ratchet, hybrid sigs, suite-ids, `CryptoBackend` ABC) compiled
**native (Rust)** and exposed to every client (Flutter mobile/web/desktop, CLI) through a
**thin JSON command/event FFI** (`send_cmd(json) -> {response | event}`), via
`flutter_rust_bridge` / `dart:ffi`. One implementation to audit instead of re-coding the
KEM/ratchet in Dart — and the natural convergence point with `sk_pqc` (Dart) / `sk_pgp`
(Rust/PyO3). The self-report (suite-ids + backend) rides in every response envelope.

### 2.6 Honesty self-report extensions (sksecurity)

Per conversation/channel, declare: `auth_mode` (anonymous/sovereign), `ratchet_level`
(L2/L3 + strategy), `pad` profile, `route` (direct / pq-metadata / onion), and **what the
relay can/can't see** — so the privacy posture is **machine-auditable** and no claim
outruns the live suite. Forbidden-words discipline as ever.

---

## 3. What we deliberately do NOT copy

- ❌ **sntrup761** — keep **FIPS-203 ML-KEM-768** (and keep sntrup761 reachable as an
  alternate suite-id *only if* FIPS guidance shifts — agility, not adoption).
- ❌ **NaCl crypto_box hardcoding / no negotiation** — every layer is a suite-id behind the backend ABC.
- ❌ **Single 16 KiB padding bucket** — use a ladder per lane.
- ❌ **Per-message PQ for groups** — epoch-amortized.
- ❌ **`tls-unique`** — use RFC 9266 `tls-exporter` (TLS 1.3).

---

## 4. Phased implementation plan

| Phase | Deliverable | Effort | Repo | Suite-ids |
|---|---|:--:|---|---|
| **P1** | **Level-3 1:1 ratchet — periodic rekey** (`pqdr-periodic-v1`) + Triple-Ratchet KDF combine | M | skchat | `pqdr-periodic-v1` |
| **P2** | **Content padding** ladder on the envelope (`pad=ladder-v1`) | S | skcomms | `pad-ladder-v1` |
| **P3** | **Metadata-sealed envelope** (outer header / inner blob, hybrid ML-KEM) | M | skcomms | `pqroute1:` |
| **P4** | **Self-report** extensions (mode/level/pad/route) | S | sksecurity | — |
| **P5** | **Anonymous-queue mode** (opaque RID/SID, OOB invite links, deniable auth, queue rotation) | L | skcomms+skchat | `auth=anon-v1` |
| **P6** | **2-hop onion private routing** (the full anonymity transport) | L | skcomms | `route=onion-v1` |
| **P7** | **Shared Rust crypto core + FFI** (multi-client convergence) | XL | new `sk-core`? | — |
| **P8** | **SPQR-style chunked braid** (`pqdr-braid-v1`, continuous PCS) | L | skchat | `pqdr-braid-v1` |
| **P9** | **MLS-mapped group suite naming** + negotiation | M | skcomms | `skc-mlkem768x25519-…` |

**Recommended start: P1** (Level-3 periodic rekey) — most self-contained, highest crypto
value, pure agility-extension of the shipped `pqdm1:`/`pqsig` machinery. P2 (padding) is a
trivial parallel quick-win.

---

## 5. Open decisions (Chef's call)

1. **1:1 strategy order:** ship **PQ3-style periodic rekey first** (P1, few lines, Level 3
   now) then SPQR-braid later (P8) — *recommended* — vs. go straight to the braid.
2. **Padding:** size **ladder** (4/16/64/256 KiB, recommended) vs SimpleX's single 16 KiB bucket.
3. **Anonymity-mode default:** anonymous-by-default (your stated preference) with sovereign
   as the enterprise flag — confirm this is the global default, or per-deployment policy.
4. **Shared Rust core (P7):** commit to the FFI core now (big, but the right long-term
   multi-client foundation) vs keep Dart/Python per-client for now and converge later.

---

## 6. References

SimpleX SMP/agent/pqdr specs (AGPL — read-only): `simplexmq/protocol/{simplex-messaging,agent-protocol,pqdr}.md` · SimpleX v5.6 PQ blog · v5.8 private-routing blog.
Signal: [PQXDH spec](https://signal.org/docs/specifications/pqxdh/) · [SPQR blog](https://signal.org/blog/spqr/).
Apple: [iMessage PQ3](https://security.apple.com/blog/imessage-pq3/) + Stebila analysis.
IETF: [draft-ietf-mls-pq-ciphersuites-04](https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-04).
FIPS 203 (ML-KEM), 204 (ML-DSA); RFC 9266 (tls-exporter), 9420 (MLS).
