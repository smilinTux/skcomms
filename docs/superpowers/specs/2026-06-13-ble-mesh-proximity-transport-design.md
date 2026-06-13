# SK Mesh Protocol (SMP) — BLE proximity transport for skcomms

**Date:** 2026-06-13
**Repo:** `skcomms` (`src/skcomms/transports/ble/`)
**Status:** design approved — ready for implementation plan
**Reference inspiration:** [Bitchat](https://github.com/permissionlesstech/bitchat) (Jack Dorsey / permissionlesstech) — BLE mesh, TTL gossip, Noise_XX, store-and-forward

---

## 1. Goal

A **sovereign, offline, proximity** transport for skcomms: two people scan each
other's QR (TOFU pairing we already have), then chat **device-to-device over
Bluetooth Low Energy with zero network** — relaying through intermediate peers
(multi-hop "peer hopping") so messages travel beyond direct radio range. When a
peer leaves proximity, the message falls back to an internet transport (Nostr /
Tailscale) we already have, then resumes over BLE when they return.

It fills the **`TransportCategory.OFFLINE`** slot that already exists in
`transport.py` and is currently empty.

**Non-goal (this spec):** replacing the existing online transports. SMP is one
more `Transport` beneath the same signed-envelope/identity layer — an offline
pipe, not a new messaging model.

## 2. Design stance (decided)

- **Hybrid: SK-native core + Bitchat bridge.** The primary transport is
  SK-native — it carries **our** capauth/fqid identity, our signing, our
  envelope — borrowing Bitchat's *proven mesh mechanics* (TTL flooding, bloom
  dedup, store-and-forward, Noise session crypto) but **not** wire-compatible by
  default. A **Bitchat wire-compat bridge is a real first-class goal** (Phase 5),
  so SK users can chat with real Bitchat users in the wild — with those peers
  **clearly marked untrusted/unverified** (open mesh, not capauth-bound).
- **Protocol-first, then Flutter.** One wire protocol, implemented twice:
  Python/`bleak` (laptops + agents like Lumina) first as the conformance
  reference, then Flutter/`flutter_blue_plus` (phones — the headline use case).
- **Session crypto = Noise_XX** (`Noise_XX_25519_ChaChaPoly_SHA256`), for forward
  secrecy — chosen over reusing PGP signing, which has no forward secrecy and is
  heavy for ephemeral proximity sessions. PGP/capauth still anchors *long-term
  identity*; Noise secures the *session*.

## 3. The layer stack (bottom-up)

```
┌─ Routing / bridge ── reachability-based transport selection:
│                      BLE (peer advertising nearby) → else Nostr / Tailscale.
│                      Store-and-forward cache + retry for "they walked away."
│
├─ Transport ──────── BleMeshTransport(Transport), category=OFFLINE.
│                      Plugs into the existing registry + router unchanged.
│
├─ Session crypto ─── Noise_XX (Curve25519 / ChaCha20-Poly1305 / SHA-256).
│                      E2E private messages, forward secrecy. Broadcast = unencrypted-but-signed.
│
├─ Relay ──────────── Gossip flooding. Bloom-filter dedup by msg-id; if not-for-me
│                      and TTL>0, decrement TTL and rebroadcast → multi-hop peer hopping.
│
├─ Packet ─────────── MeshPacket binary codec. Fragment start/cont/end for >MTU.
│                      PKCS#7 padding to fixed blocks (traffic-analysis resistance).
│
└─ Radio ──────────── BLE GATT. One SK service UUID + mesh characteristic (write + notify).
                       Every device is BOTH peripheral (advertise+accept) AND central
                       (scan+connect) — the dual role forms the mesh.
```

## 4. Wire format — `MeshPacket`

SK-native analog of Bitchat's `BitchatPacket`. Binary, little-endian.

| Field | Bytes | Notes |
|---|---|---|
| `version` | 1 | protocol version (start at `1`) |
| `type` | 1 | see packet types below |
| `ttl` | 1 | hop budget; relay decrements; drop at 0. **Default 7.** |
| `flags` | 1 | bit0 = has-signature, bit1 = fragmented, bit2 = encrypted (Noise) |
| `timestamp` | 8 | UInt64 ms (sender clock; used for ordering + replay window) |
| `msg_id` | 8 | random per original message; **dedup key** for the bloom filter |
| `sender_id` | 8 | first 8 bytes of SHA-256(sender fqid) |
| `recipient_id` | 8 | first 8 bytes of SHA-256(recipient fqid); **all-`0xFF` = broadcast** |
| `payload_len` | 2 | UInt16 |
| `payload` | var | Noise-ciphertext (private) or signed plaintext (broadcast) |
| `signature` | 0 or 64 | Ed25519 over header+payload when flags.has-signature |

After assembly the whole packet is **PKCS#7-padded** to the next block size in
{256, 512, 1024, 2048} to obscure true length. A BLE MTU is ~185–512B, so packets
larger than the negotiated MTU are split with the fragment types below.

**Packet types:** `ANNOUNCE` (presence beacon: fqid-hash + Noise static pubkey +
Ed25519 pubkey), `MESSAGE` (chat payload), `ACK` (delivery ack for
store-and-forward), `FRAGMENT_START` / `FRAGMENT_CONTINUE` / `FRAGMENT_END`,
`NOISE_HANDSHAKE` (XX handshake messages), `LEAVE` (graceful departure).

## 5. Identity binding — the sovereign heart

We stay SK-native instead of becoming Bitchat:

- **capauth/fqid stays authoritative** — who you *are*.
- Each identity derives a bound **BLE keypair**: Ed25519 (signing) + Curve25519
  (Noise static). Stored alongside the agent's existing keys.
- **fingerprint = SHA-256(Noise static pubkey)** — the canonical out-of-band id,
  same shape Bitchat uses, same shape `pairing.py` already TOFU-verifies.
- **Extend the `skp://` pairing bundle** (`PairingBundle` in `pairing.py`) with a
  `noise_static_pubkey` field. It already carries `fqid`, `fingerprint`, and an
  optional armored `pubkey`. Scanning a QR therefore: TOFU-binds
  `fingerprint ↔ fqid ↔ noise_static_pubkey` in one shot → the peer can now open a
  Noise_XX session and chat over BLE. **This completes the "scan with others, then
  comm over Bluetooth" flow** using machinery that already exists.

## 6. Routing & the Nostr fallback (reuse, don't rebuild)

Bitchat uses Nostr for exactly one job: deliver a *private* message when the peer
has left BLE range. skcomms **already has a `nostr` transport**, so this is not
new code — it's the fallback leg of the router:

1. Peer's `ANNOUNCE` seen recently (in proximity) → route over **BLE mesh**.
2. Else, peer known-reachable over **Tailscale** → route there.
3. Else → **Nostr** (out-of-proximity internet bridge), same signed envelope.
4. Undeliverable now → **store-and-forward** cache + retry (Bitchat
   `MessageRetryService` analog); flush on next `ANNOUNCE` or `ACK`.

One envelope, one identity, many pipes — the existing router gains a
reachability check; nothing about the message model changes.

## 7. Component / file structure

New package `src/skcomms/transports/ble/`:

| File | Responsibility |
|---|---|
| `protocol.py` | `MeshPacket` encode/decode, packet types, TTL, fragmentation, PKCS#7 padding |
| `gatt.py` | BLE GATT service + characteristic **UUID constants** and the shared radio profile (one source of truth for Python *and* Flutter) |
| `relay.py` | Gossip relay engine: bloom-filter dedup, TTL decrement, rebroadcast |
| `noise.py` | Noise_XX handshake + transport encrypt/decrypt (wraps a vetted lib: `dissononce` or `noiseprotocol`) |
| `identity.py` | Bind capauth/fqid ↔ BLE keypair; fingerprint derivation; pairing-bundle extension helpers |
| `transport.py` | `BleMeshTransport(Transport)`, `category=OFFLINE`; `bleak` peripheral+central driver; radio abstraction seam (see §8) |
| `store.py` | Store-and-forward cache + retry/backoff |

Touched existing files: `pairing.py` (+`noise_static_pubkey` on `PairingBundle`),
the router (reachability selection + Nostr fallback), `registry.py`/`config.py`
(register the transport; **opt-in**, sovereign-offline-friendly).

## 8. Testing — closed-loop, radio-optional

The radio abstraction seam is the key to testability: `transport.py` talks to a
`Radio` interface (scan / advertise / connect / send / on-receive), with two
implementations.

1. **`FakeRadio` (in-memory bus, NO Bluetooth)** — simulates N nodes and a
   **who-can-hear-whom topology**. This proves the entire mesh: multi-hop relay,
   TTL expiry, bloom dedup, fragmentation reassembly, Noise handshake, and
   store-and-forward — deterministically, in CI, with zero hardware. **This is the
   primary conformance harness.**
2. **`BleakRadio` (real BLE)** — hardware integration test across **two BLE Linux
   endpoints**: the laptop (`.41`, has Bluetooth) + the **GMKtec NUC's Bluetooth
   passed through to a VM**. Confirms the driver + real MTU/fragmentation against
   actual radios. (Setup is its own harness task in the plan.)
3. **Flutter phase** — 2 physical phones (Chef has them) running the
   `flutter_blue_plus` implementation against the same spec.

Unit tests per module are pure-logic and radio-free (protocol codec, TTL, bloom,
Noise vectors, fragmentation, store-forward).

## 9. Phasing

| Phase | Deliverable |
|---|---|
| **P0** | This spec. |
| **P1** | Python **core**: `protocol` + `relay` + `noise` + `identity` + `gatt` constants + **`FakeRadio`** test harness. No hardware. Conformance reference. |
| **P2** | Python **`BleakRadio`** transport (real radio) + the 2-Linux-endpoint hardware harness (laptop + NUC BT passthrough). |
| **P3** | **Routing**: reachability selection + **Nostr fallback** + store-and-forward wiring. |
| **P4** | **Flutter** `flutter_blue_plus` implementation against the spec; 2-phone proximity test; align with the app's existing QR pairing. |
| **P5** | **Bitchat wire-compat bridge** (first-class goal): speak `BitchatPacket` + Noise_XX on Bitchat's GATT UUID; bridge SK ↔ Bitchat peers, marking Bitchat peers **untrusted/unverified** in the UI. |

## 10. Security & honesty notes

- **In our net:** every peer is a capauth/fqid identity, TOFU-paired by
  fingerprint, Noise_XX forward-secret sessions, Ed25519-signed packets.
- **On the Bitchat bridge (P5):** those peers are *their* identity model, not
  capauth-bound. Cross-net chats are "insecure by our standard" **by design and
  clearly labelled** — you always know when you've stepped outside the sovereign
  net onto the open mesh.
- **Traffic-analysis resistance:** fixed-block padding + (future) optional cover
  traffic, per Bitchat. Noted, not all in P1.
- **DoS:** Noise handshake rate-limiting (Bitchat `NoiseRateLimiter` analog) and
  the existing skcomms `ratelimit.py` per transport+peer.

## 11. Open items folded into the plan (not blockers)

- Pick the Noise lib (`dissononce` vs `noiseprotocol`) — decided in P1 task 1.
- Confirm the NUC actually exposes a BT controller to passthrough — verified in P2
  setup; FakeRadio means P1 doesn't depend on it.
- Bitchat protocol version tracking — pinned at bridge-build time in P5.
