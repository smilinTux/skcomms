# SK LoRa Transport — long-range off-grid mesh for skcomms (Meshtastic-first)

**Date:** 2026-06-13
**Repo:** `skcomms` (`src/skcomms/transports/lora/`)
**Status:** design approved — ready for implementation plan
**Sibling of:** the BLE proximity mesh / SMP (`2026-06-13-ble-mesh-proximity-transport-design.md`) — reuses its `MeshPacket` payload format

---

## 1. Goal

A **long-range, off-grid** transport for skcomms: ship sovereign SK messages
(chat / presence / alerts / control) over **LoRa** — kilometers of range, no
internet, no cell, no infrastructure — by riding on a **Meshtastic** mesh. It is
the bottom rung of the off-grid ladder:

```
BLE / SMP (proximity, ~10–100 m, higher bandwidth, phone-native)
   ↓ fall back when out of BLE range
LoRa / Meshtastic (long range, ~km, TINY bandwidth, text only)   ← THIS
   ↓ when there's any internet
Nostr / Tailscale (full bandwidth)
```

It fills the same `TransportCategory.OFFLINE` slot as SMP — a **second** offline
transport, selected when nothing higher-bandwidth is reachable. **"Text gets
through when nothing else does."**

**Non-goal:** voice, video, files. LoRa's bandwidth forbids it (§3). Audio stays
on BLE/Tailscale; LoRa carries messages, presence beacons, and alerts only.

## 2. Design stance (decided)

- **Abstract both, Meshtastic first.** A generic `LoRaMeshInterface` seam (the SMP
  `Radio`-abstraction analog); `MeshtasticInterface` implemented first; `FakeLoRa`
  for CI; `ReticulumInterface` a future second adapter behind the same seam.
- **Meshtastic owns the mesh — NO SMP relay on top.** Meshtastic already does
  robust multi-hop routing + AES link crypto + duty-cycle handling. LoRa airtime
  is the scarcest resource on the whole fleet; running SMP's TTL-flood relay *on
  top* of Meshtastic's relay would double-spend it. So Meshtastic provides the
  radio mesh; we ride on top. (This is the key difference from SMP, where *we*
  owned the mesh because BLE GATT has none.)
- **Reuse SMP's `MeshPacket` as the LoRa *payload*.** We do NOT ship heavy
  capauth/PGP envelopes (a PGP signature alone overflows a LoRa frame). The SMP
  `MeshPacket` is already the right shape — compact binary, 8-byte FQID-hash
  sender/recipient, **Ed25519** signature (64 B), fragmentation — designed for
  exactly this constraint. A Meshtastic data message carries one (fragment of a)
  `MeshPacket`. Same sovereign identity, radio-sized. Meshtastic's AES protects
  the link; our Ed25519/`MeshPacket` gives **end-to-end SK identity** on top.

## 3. The bandwidth reality (the binding constraint)

- LoRa frames are **~200–237 bytes** of usable payload; data rate ~0.3–50 kbps;
  **legally duty-cycle-limited** (e.g. 1% → ~36 s airtime/hour per node in some
  bands). A single SK message may fragment across several frames, each spaced out.
- Therefore: **text/control only**, aggressive compactness, and **store-and-forward
  with backoff** is mandatory, not optional. The transport advertises itself as
  `category=OFFLINE`, `priority` below SMP, with a low MTU so the router/codec
  fragments correctly.
- Meshtastic's own data message has a `portnum` (app id) and a payload; we use a
  dedicated **SK portnum** (private app id) so SK traffic is demuxed from ordinary
  Meshtastic text/telemetry on a shared mesh.

## 4. Architecture & components

New package `src/skcomms/transports/lora/`:

```
LoRaTransport(Transport, category=OFFLINE)        # the skcomms transport
   │  packs/unpacks MeshPacket payloads (reuses ble/protocol.py), fragments to MTU,
   │  maps FQID ↔ Meshtastic node, store-and-forward queue + duty-cycle backoff
   ▼
LoRaMeshInterface (ABC)                            # the seam (send_frame/recv/info)
   ├─ MeshtasticInterface   — `meshtastic` py lib over serial(USB)/TCP/BLE; uses a
   │                          dedicated SK portnum; pubsub for received packets   ← L2 (needs hardware)
   ├─ FakeLoRaInterface     — in-memory bus + duty-cycle/airtime simulation       ← L1 (CI)
   └─ ReticulumInterface    — future, same seam                                   ← L3
```

| File | Responsibility |
|---|---|
| `interface.py` | `LoRaMeshInterface` ABC (`send_frame(bytes, dest)`, `on_receive(cb)`, `start/stop`, `info()`), `FakeLoRaInterface` (in-memory, airtime sim) |
| `framing.py` | Pack a `MeshPacket` (from `ble.protocol`) into ≤MTU Meshtastic-payload frames + reassemble; SK portnum constant; MTU constant |
| `addressing.py` | FQID ↔ Meshtastic node-id map (persisted, pairing-populated); broadcast channel name |
| `store.py` | Store-and-forward queue + duty-cycle/backoff scheduler (don't exceed airtime budget) |
| `transport.py` | `LoRaTransport(Transport)` — `configure/is_available/send/receive/health_check`; drives the interface; reuses `ble.protocol` for the payload codec |
| `meshtastic_iface.py` | `MeshtasticInterface` (real radio; `meshtastic` lib) — written in L1, live-tested in L2 |

Reuses: `src/skcomms/transports/ble/protocol.py` (`MeshPacket`, `encode/decode`,
`fragment`, `Reassembler`) and `identity.py` (`MeshIdentity`, `id_hash`, Ed25519
sign/verify, fingerprint) — the SMP sovereign-identity layer, unchanged.

## 5. Identity, pairing & addressing

- SK identity is the **same** as SMP: FQID → `id_hash` (8-byte sender/recipient),
  Ed25519 signing, fingerprint = SHA-256(noise static pub). A LoRa peer is the
  same sovereign identity as a BLE peer — **one identity, many radios.**
- **Pairing** reuses the `skp://` bundle (already extended with the Noise key in
  SMP); add an optional `meshtastic_node` hint so a scanned peer's FQID maps to
  their Meshtastic node-id. Until paired, a node is addressed by broadcast on the
  SK channel + Ed25519-verified by fingerprint (TOFU), exactly like SMP.

## 6. Routing integration

- Register `LoRaTransport` in the skcomms transport registry as `OFFLINE`,
  `priority` just below the BLE SMP transport (BLE preferred when both available —
  it's faster). The router's reachability selection becomes:
  **BLE (proximity) → LoRa (long-range) → Tailscale → Nostr.**
- **Store-and-forward** is first-class here (not deferred like SMP's): the duty
  cycle means a send may be queued for seconds–minutes; the scheduler drains the
  queue within the airtime budget, retrying with backoff, and flushes on peer
  presence.

## 7. Testing — CI-first, hardware-deferred (mirrors SMP P1/P2)

1. **`FakeLoRaInterface` (in-memory, NO hardware)** — simulates N nodes, an MTU,
   and an **airtime/duty-cycle budget** (so tests prove the store-and-forward
   scheduler respects limits). Proves: framing/reassembly of a `MeshPacket` across
   sub-MTU frames, FQID↔node addressing, signed-payload round-trip, store-and-
   forward backoff, and the `Transport` ABC contract — all in CI, zero radios.
2. **`MeshtasticInterface` live test** — one (or two) real **Meshtastic nodes over
   USB/serial**; deferred until hardware exists (Chef has none yet). Confirms the
   `meshtastic` lib wiring + SK portnum demux + real airtime.
3. Unit tests are pure where possible (framing, addressing, store scheduler).

## 8. Phasing

| Phase | Deliverable |
|---|---|
| **L1** | **Core, CI-tested, no hardware:** `interface` (+`FakeLoRaInterface`) · `framing` (MeshPacket↔frames + SK portnum) · `addressing` (FQID↔node) · `store` (duty-cycle scheduler) · `LoRaTransport` · `meshtastic_iface` written against the lib (not live-run). |
| **L2** | **Real Meshtastic node** over USB (needs a board): live `MeshtasticInterface` test, SK-portnum demux on a shared mesh, airtime verification. |
| **L3** | **Reticulum** interface behind the same seam (future). |
| **L4** | **Router wiring**: reachability selection (BLE→LoRa→TS→Nostr) + presence-driven store-and-forward flush. |

## 9. Security & honesty notes

- **End-to-end SK identity** rides over Meshtastic via the Ed25519-signed
  `MeshPacket` payload — a Meshtastic relay node forwards but can't forge an SK
  sender (it lacks the Ed25519 key). Meshtastic's channel AES is the *link* layer;
  it is NOT the SK trust boundary (anyone on the channel key can inject Meshtastic
  frames, but not valid SK-signed payloads).
- **Privacy caveat:** LoRa is a broadcast medium and Meshtastic metadata (node
  ids, positions if enabled) is visible to anyone listening on the channel.
  Disable Meshtastic position broadcast for SK nodes; treat LoRa as
  **low-confidentiality, high-resilience** — the channel of last resort, not the
  private one.
- **No amplification/DoS:** the store-and-forward scheduler hard-caps airtime; a
  flood of inbound can't make us exceed the duty cycle.

## 10. Open items folded into the plan (not blockers)

- Pick the SK Meshtastic **portnum** (PRIVATE_APP range) — fixed in L1 framing.
- The `meshtastic` Python lib's exact send/recv API (pubsub topics, `sendData`
  with `portnum`) — verified when writing `meshtastic_iface.py` in L1; live-bound
  in L2.
- Duty-cycle budget defaults (band-dependent) — config, conservative default in L1.
- Whether to also expose presence beacons (periodic signed `ANNOUNCE` MeshPackets)
  on LoRa — yes, but rate-limited by the airtime scheduler; detailed in L4.
