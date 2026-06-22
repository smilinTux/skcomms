# TAK vs SKFed — head-to-head + what to liberate (2026-06-22)

Source: *"Technology THEY Don't Want You to Own"* (Prepared Citizen, youtu.be/PZZCIl0T3So).
Their "comms bridge" stack (≈14:00–19:00) = the civilian-tactical **TAK** stack: **ATAK/iTAK**
(offline map, team tracking, mission packages/waypoints) + **TAK Server on a Raspberry Pi** (private
data hub) + **LoRa** off-grid mesh + **Starlink** backhaul + **Signal** chat crypto + drone/camera
**video to handhelds**. Same architecture the US military runs (iTAK + their own servers).

## Capability map — theirs vs ours

| Capability | TAK stack | SKFed / skcomms / skchat / skos | Verdict |
|---|---|---|---|
| **Identity / trust** | Shared **data packages** = a zip of certs/PSK every team member holds; compromise one device → whole net. No per-user crypto identity. | **capauth** per-agent PGP/ed25519 FQID, **per-message signed** envelopes, **TOFU**-pinned peer keys, `TrustPolicy` (FULL/SUBSCRIBE/DENY), realm-qualified. | **Ours, decisively.** Sovereign cryptographic identity vs a shared key. |
| **Transport** | TCP/UDP to a TAK Server; LoRa is a bolt-on (ATAK-forwarder / Meshtastic plugin); one path at a time. | **Rail-agnostic router**: http-s2s, Nostr, **LoRa**, **BLE**, Telegram, file — same canonical signed envelope on every rail, ordered fallback, **store-and-forward** when offline. | **Ours.** Multi-rail with automatic fallback; their mesh is single-bolt-on. |
| **Topology** | **Central TAK Server** (the Pi) — clients fan in. Federation exists (TAKServer↔TAKServer) but server-centric. | **Owner-centric federation** — each node hosts its own; peers join via **signed cross-realm S2S** + **Nostr auto-discovery**; no central server required. | **Ours.** No single point of failure / capture. |
| **Discovery** | Manual (import data package / type server IP). | **Nostr directory** auto-publish + TOFU resolve (`agent@node→inbox_url+pubkey`); zero-config peer add. | **Ours.** |
| **Video (drone/cam → handheld)** | Pi server relays feeds to ATAK; usable but ad-hoc. | **LiveKit SFU** per node + **federated signed cross-realm tokens** + conf/Spaces; screenshare; agent-joinable. | **Ours** (proper SFU + federation) — same outcome, better plumbing. |
| **Geospatial / map / waypoints** | **ATAK's killer feature** — battle-tested offline map, CoT markers, mission packages, team positions, nav. | **We don't have a map surface yet.** | **Theirs — the one real gap.** (Steal it.) |
| **Client maturity / ecosystem** | ATAK is mature, plugin-rich, field-proven on real hardware. | Flutter app (chat/calls/spaces/cluster/files), newer. | **Theirs on maturity.** (Absorb via CoT bridge.) |
| **AI / autonomy** | None. A human stares at a laptop. | **Lumina/Jarvis** are native participants in the fabric; RAG + tools; can watch/triage/act on the net. | **Ours — no contest.** They have no agent layer. |
| **Knowledge / memory** | None (it's a map + chat). | **skmem-pg** (pgvector + AGE graph + BM25) + **skos** file plane = node-qualified RAG over the whole corpus. | **Ours — no contest.** |
| **Backhaul** | Starlink (+ generator). | Tailscale/Funnel overlay (Starlink/any-WAN agnostic) + LoRa/BLE for no-WAN. | Parity (we're WAN-agnostic too). |

**Bottom line:** TAK is the **2010s military stack** the preppers liberated. SKFed is a **generation
past it on the backend** — sovereign per-agent crypto identity (vs shared PSK), transport-agnostic
federation with fallback + store-forward (vs single-server + LoRa bolt-on), native AI agents, and a
knowledge/RAG plane TAK has nothing close to. Their one genuine edge is **ATAK's mature offline map +
CoT ecosystem**. So we don't compete with that — **we speak its protocol and swallow it.**

## What to liberate (steal/leverage) — ranked
1. **CoT bridge (the big one) — a `cot` rail/adapter + TAK-Server-compatible endpoint.** CoT
   (Cursor-on-Target, XML/protobuf) is TAK's wire format. Add a skcomms CoT adapter that (a) ingests
   CoT events (positions/markers/chat) into the canonical envelope and (b) emits CoT so **any ATAK/iTAK
   device joins our sovereign mesh** and a FreeTAKServer/TAK client talks to us. Result: we inherit
   ATAK's mature client + the entire TAK ecosystem **for free**, on our superior backend (capauth
   identity, multi-rail, federation, agents). This is the highest-leverage move.
2. **Geospatial plane ("skmap")** — a position/marker/waypoint surface in the Flutter app + a `geo`
   envelope kind (lat/lon/track/mission-package). Team positions, drone tracks, nav. Our agents +
   RAG can annotate the map (TAK can't). Interops with CoT (#1).
3. **Meshtastic/LoRa turnkey** — our LoRa rail exists in skcomms; make it plug-and-play with Meshtastic
   hardware (the de-facto cheap LoRa mesh radios) so off-grid is one device away, carrying the same
   signed envelope (so it's *authenticated* mesh, unlike raw Meshtastic).
4. **Mission packages** — structured shareable bundles (a `kind` + the skos file plane) — but
   cryptographically signed + owner-scoped, not a shared-cert zip.
5. **Video feed surface** — package the existing LiveKit conf/Spaces as a "live feed" (drone/cam→agents
   +handhelds), agent-watchable.

## Why they'd weep
They liberated a **shared-key, server-centric, human-only, map+chat** kit. We built a **per-agent
sovereign-crypto, owner-federated, multi-rail (incl. LoRa/BLE), AI-native, knowledge-graph** fabric —
and with the CoT bridge we can **wear their best client as a skin** while running our backend. Their
"level playing field with the military" is our floor.
