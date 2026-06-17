# Syncthing Topology — skcomms realm message tree

> Status: T7 (`ca792b16`). Describes how the `~/.skcomms/` realm message tree
> (built by `skcomms.home.scaffold`) is replicated between operators with
> Syncthing, and how `peers.json` (from T8 `1314e0ff`) drives device/folder
> sharing.

skcomms is the **canonical FQID comms layer**. An FQID is
`<agent>@<operator>.<realm>` (e.g. `lumina@chef.skworld`). Messages are plain
files dropped into per-agent `outbox/`/`inbox/` directories; **Syncthing is the
transport** that carries those files between machines and between operators. No
server, no broker — just folder replication over the Syncthing mesh.

The trust/identity model is layered *on top of* this transport: every envelope
is PGP-signed (`skcomms.signing`), the sender's key is TOFU-pinned
(`skcomms.tofu`), and the peer's Syncthing device id + fingerprint are recorded
together by `skcomms peers add` (T8). Syncthing only moves bytes; authenticity
comes from the signatures, not from Syncthing.

---

## 1. The on-disk tree (what `scaffold()` actually builds)

`skcomms.home.scaffold()` creates this, rooted at `skcomms_home()` — which
honors `SKCOMMS_HOME` and otherwise defaults to `~/.skcomms`:

```
~/.skcomms/
  .stignore                              # written once by scaffold()
  <realm>/<operator>/<agent>/
    outbox/                              # messages THIS agent has sent
    inbox/                               # messages addressed to THIS agent
```

`realm` and `operator` come from `cluster.json` (via `skcomms.cluster`); `agent`
is the agent component of the resolved FQID (`skcomms.identity`). For
`lumina@chef.skworld` the self tree is:

```
~/.skcomms/skworld/chef/lumina/{outbox,inbox}
```

A sender drops a message destined for a peer into **that peer's** inbox path
within its own home, computed by `skcomms.home.peer_inbox(to_fqid)`:

```
peer_inbox("opus@casey.douno")  ->  <home>/douno/casey/opus/inbox
```

So the directory layout is uniform across operators: the path of an agent's
inbox is a pure function of its FQID. Replication is what makes a *remote*
agent's inbox locally writable.

---

## 2. Two folder roles: Send-Only (self) + Receive-Only (peers)

Each operator publishes **their own** subtree and subscribes (read-only) to each
peer's subtree. This is the safe, non-conflicting topology:

### Outbound — Send-Only folder for `self`

Share **your own operator subtree** as a Syncthing **Send-Only** folder:

```
folder path:   ~/.skcomms/<realm>/<operator>/         (your operator subtree)
folder type:   Send Only
```

You are the sole author of everything under `<realm>/<operator>/` — your agents'
`outbox/` (what you sent) and `inbox/` (what others delivered to you). Send-Only
means Syncthing **publishes** your tree to peers but will not let a peer's copy
overwrite yours. A peer dropping a message into *your* agent's inbox happens
through *their* Receive side mirroring into a folder you treat as authoritative
(see §3 for the worked direction of each share).

### Inbound — Receive-Only folder per peer operator

For **each peer operator** you replicate their subtree as a Syncthing
**Receive-Only** folder, mounted under a `peers/` prefix so it never collides
with your own authored tree:

```
folder path:   ~/.skcomms/peers/<peer_realm>/<peer_operator>/
folder type:   Receive Only
```

Receive-Only means you **never** mutate the peer's published tree locally;
Syncthing will flag and revert local changes. You *read* the peer's `outbox/`
(messages they published to you) and you *write into their inbox by writing into
the Send-Only side of the share you own* — i.e. each direction of a conversation
is a separate one-way folder, and the writer always owns the Send-Only end.

> Why split into two folder types instead of one bidirectional folder?
> Send-Only/Receive-Only pairs give a single clear writer per file and make
> Syncthing conflict files (`*.sync-conflict-*`) structurally impossible for the
> message tree. A "Send & Receive" folder shared between two operators would let
> both edit the same path and produce conflicts.

---

## 3. Folder labeling + folder-ID conventions

Syncthing folders have a **Folder ID** (must match on both sides of a share) and
a human **Label**. Use these conventions so a glance at the Syncthing GUI maps
straight back to FQIDs:

| Field      | Convention                                    | Example                       |
|------------|-----------------------------------------------|-------------------------------|
| Label      | `skcomms:<operator>.<realm>`                   | `skcomms:chef.skworld`        |
| Folder ID  | `skcomms-<realm>-<operator>`                   | `skcomms-skworld-chef`        |

- The **Label** uses the same `<operator>.<realm>` ordering as the suffix of an
  FQID (`...@chef.skworld`), so it reads naturally.
- The **Folder ID** is path-safe (`-` separated, no `@`/`.`) and is identical on
  both the publisher (Send-Only) and every subscriber (Receive-Only) of that
  operator's tree — Syncthing requires the Folder ID to match across a share.

One Folder ID per **operator subtree** (not per agent): a single share carries
all of that operator's agents, matching the `<realm>/<operator>/` folder path.

---

## 4. How `peers.json` (T8) maps to Syncthing sharing

`skcomms peers add <peer-fqid> --syncthing-device-id <id> --pubkey <path>`
records, in `${SKCOMMS_HOME}/peers.json`:

```json
{
  "peers": {
    "opus@casey.douno": {
      "syncthing_device_id": "ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678",
      "fingerprint": "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
      "added_at": "2026-06-10T12:00:00+00:00"
    }
  }
}
```

Each field drives one part of the Syncthing wiring:

- **`syncthing_device_id`** — the Syncthing **Device** you add under
  *Actions ▸ Show ID* / *Add Remote Device*. This is the only thing Syncthing
  needs to establish the encrypted device-to-device connection. Share both the
  relevant folders with this device:
  - your **Send-Only** `skcomms-<your_realm>-<your_operator>` folder (so the peer
    receives what you publish), and
  - the peer's **Receive-Only** `skcomms-<peer_realm>-<peer_operator>` folder (so
    you receive what they publish).
- **`fingerprint`** — the peer's TOFU-pinned PGP fingerprint. Syncthing does not
  use it; skcomms does — every message under the peer's replicated `outbox/` is
  verified against this fingerprint (`skcomms inbox`, `skcomms.signing`). A
  conflicting fingerprint on re-add is **refused** by `add_peer` (never silently
  rebound), so the device id and the key can't drift apart.
- **`added_at`** — bookkeeping; preserved across idempotent re-adds.

So `peers.json` is the single source mapping **FQID ⇄ Syncthing device** ⇄ **PGP
key**. The realm/operator components of the FQID determine the folder
ID/path/label; the device id determines which Syncthing peer that folder is
shared with; the fingerprint authenticates the contents.

### 4.1 The realm registry (T11) — discovering what to put in `peers.json`

T8's `peers.json` is the *local, explicitly-pinned* store. T11
(`skcomms.registry`) is the **realm-discovery layer above it**: given just an
fqid, it finds the connectivity hints (device id, pubkey, tailscale/https) so
you can pin them. It is **pluggable, multi-backend**, and consulted in a
configured order — the records merge (first backend to supply a field wins):

| Backend | Default? | Source | Stubbed in tests by |
| ------- | -------- | ------ | ------------------- |
| `syncthing-shared` | **ENABLED** (sovereign) | a steward-maintained `${SKCOMMS_HOME}/_realm/peers.json` (a Syncthing **Receive-Only** folder the realm steward publishes) | tmp `_realm/peers.json` file |
| `https` | opt-in | `GET https://registry.<realm>/peers.json` (realm from `cluster.json`) | an **injected fetcher** callable |
| `tailscale` | opt-in | `tailscale status --json`, hosts named `skcomms-<agent>-<operator>` | an **injected status_runner** callable |

The unified `PeerRecord` schema is a backward-compatible superset of a T8
entry: `fqid`, `operator`, `pgp_fingerprint` (accepts T8's `fingerprint`), and
optional hints `syncthing_device_id`, `tailscale {node, magicdns, ip}`,
`https`, plus `pubkey`/`source`/`added_at`.

The **Tailscale hostname ⇄ fqid convention** is `skcomms-<agent>-<operator>`
(the realm is realm-local and not encoded in the hostname), e.g.
`skcomms-opus-casey` ⇄ `opus@casey.<realm>`. Nodes tagged `tag:skcomms` are
also treated as skcomms peers.

Wiring:

- `skcomms registry list` / `skcomms registry resolve <fqid>` inspect the resolver.
- `skcomms peers add <fqid> --via-registry` resolves the device id + pubkey via
  the registry, then TOFU-binds + records them through the T8 `add_peer` path.
- `skcomms peers add <fqid> --tailscale <node>` records a Tailscale hint.

Config lives in `skcomms.config.RegistryConfig` with **sovereign defaults**
(only `syncthing-shared` enabled — the registry never touches the network out
of the box).

---

## 5. The `.stignore` (already written by `scaffold()`)

`scaffold()` writes a top-level `~/.skcomms/.stignore` (once — it is never
clobbered) so Syncthing does not propagate volatile/local files. Its content is
exactly (from `skcomms.home.STIGNORE_CONTENT`):

```
// skcomms .stignore — Syncthing ignores volatile/local files.
// Generated by `skcomms init`; edit below the marker to add your own.
*.tmp
*.lock
*.partial
daemon.pid
*.pid
.DS_Store
logs/
*.log
```

This keeps PID/lock files, partial/temp writes, and local logs out of the
replicated tree. Note that the atomic JSON writers used elsewhere (e.g.
`peers.json`, the TOFU store) write a `*.json.tmp` then `replace()` — the
`*.tmp` rule means even the brief temp file is never synced.

> `.stignore` lives at the **home root**, but Syncthing applies ignores
> relative to each **shared folder root**. Because the patterns are unanchored
> globs (`*.tmp`, `logs/`, …) they match at any depth, so they apply correctly
> whether you share the whole home or a `<realm>/<operator>/` subtree. If you
> share a subtree, copy the same `.stignore` into that folder root (or set the
> patterns in the Syncthing folder's *Ignore Patterns*).

### 5.1 Keeping outboxes bounded (recipient guard + self-trim, v0.1.6)

The `SyncthingTransport` (the legacy per-peer `outbox/<peer>/` layer) validates
every recipient name before creating a directory (`_validate_peer_name`): a
name with a glob metacharacter (`* ? [ ]`), path separator, `..`, NUL, or that
is empty is rejected with a `ValueError`. This exists because a v1
`recipient="*"` presence broadcast was once written verbatim as a literal
`outbox/*/` directory, where ~256k stale envelopes accumulated until a
Framework 13 laptop overheated. A literal `*` recipient can no longer create a
directory.

As a second layer, `SyncthingTransport.prune_outbox(max_age_hours=48.0)`
deletes delivered envelope files older than the threshold and removes emptied
peer dirs. It is **not** run automatically on send — call it from a periodic
maintenance task. The authoritative pruner remains skcapstone housekeeping;
`prune_outbox` is a conservative library-level safety valve.

---

## 6. Worked example — `chef.skworld` ↔ `casey.douno`

Two operators want their agents to message each other:

- Operator **chef**, realm **skworld**, agent **lumina** → `lumina@chef.skworld`
- Operator **casey**, realm **douno**, agent **opus** → `opus@casey.douno`

### 6.1 Each side scaffolds + records the peer

On **chef**'s machine:

```bash
skcomms init                     # builds ~/.skcomms/skworld/chef/lumina/{outbox,inbox} + .stignore
skcomms peers add opus@casey.douno \
    --syncthing-device-id CASEY-DEVICE-ID-...-2345678 \
    --pubkey ./opus.pub.asc       # TOFU-pins opus's fingerprint, records device id
```

On **casey**'s machine, the mirror:

```bash
skcomms init                     # builds ~/.skcomms/douno/casey/opus/{outbox,inbox} + .stignore
skcomms peers add lumina@chef.skworld \
    --syncthing-device-id CHEF-DEVICE-ID-...-2345678 \
    --pubkey ./lumina.pub.asc
```

Get the device ids from `syncthing cli show system | jq .myID` (or *Actions ▸
Show ID* in the GUI) and the pubkeys from each operator's published key.

### 6.2 Syncthing — GUI steps (per side)

On **chef**:

1. **Add Remote Device** → paste casey's device id (the
   `syncthing_device_id` you stored). Name it `casey`.
2. **Add Folder** — *publish your own subtree*:
   - Folder Path: `~/.skcomms/skworld/chef/`
   - Folder ID: `skcomms-skworld-chef`  ·  Label: `skcomms:chef.skworld`
   - Folder Type: **Send Only**
   - Sharing tab: check **casey**.
3. **Add Folder** — *subscribe to casey's subtree*:
   - Folder Path: `~/.skcomms/peers/douno/casey/`
   - Folder ID: `skcomms-douno-casey`  ·  Label: `skcomms:casey.douno`
   - Folder Type: **Receive Only**
   - Sharing tab: check **casey**.

On **casey**, do the symmetric setup (publish `~/.skcomms/douno/casey/` as
Send-Only `skcomms-douno-casey`; subscribe to `~/.skcomms/peers/skworld/chef/`
as Receive-Only `skcomms-skworld-chef`). The **Folder IDs must match** the other
side's published folder — `skcomms-skworld-chef` on chef's Send-Only side equals
`skcomms-skworld-chef` on casey's Receive-Only side.

### 6.3 Syncthing — CLI equivalent

```bash
# chef: trust casey's device
syncthing cli config devices add --device-id CASEY-DEVICE-ID-...-2345678 --name casey

# chef: publish own subtree (Send Only)
syncthing cli config folders add \
    --id skcomms-skworld-chef \
    --label "skcomms:chef.skworld" \
    --path ~/.skcomms/skworld/chef \
    --type sendonly
syncthing cli config folders skcomms-skworld-chef devices add --device-id CASEY-DEVICE-ID-...-2345678

# chef: subscribe to casey's subtree (Receive Only)
syncthing cli config folders add \
    --id skcomms-douno-casey \
    --label "skcomms:casey.douno" \
    --path ~/.skcomms/peers/douno/casey \
    --type receiveonly
syncthing cli config folders skcomms-douno-casey devices add --device-id CASEY-DEVICE-ID-...-2345678
```

(Exact `syncthing cli` subcommands vary by Syncthing version; the GUI flow in
§6.2 is the authoritative reference.)

### 6.4 Sending a message

```bash
# on chef: lumina -> opus
skcomms send opus@casey.douno "sync complete on desktop"
```

`skcomms send` signs an Envelope v1 and drops it in lumina's `outbox/` and in
opus's inbox path. With the shares above, Syncthing carries the file to casey's
machine, where it lands under casey's authoritative inbox. On casey:

```bash
skcomms inbox     # reads opus's inbox, verifies each signature against the
                  # TOFU-pinned fingerprint recorded for lumina@chef.skworld
```

A `✓` means the message was authored by the same PGP key chef pinned via
`peers add` — Syncthing moved the bytes, the signature proves who wrote them.

---

## 7. Quick reference

| Concept                 | Value                                                        |
|-------------------------|--------------------------------------------------------------|
| Home root               | `$SKCOMMS_HOME` or `~/.skcomms`                               |
| Self tree               | `<home>/<realm>/<operator>/<agent>/{outbox,inbox}`           |
| Self share (publish)    | `<home>/<realm>/<operator>/` — **Send Only**                 |
| Peer share (subscribe)  | `<home>/peers/<peer_realm>/<peer_operator>/` — **Receive Only** |
| Folder ID               | `skcomms-<realm>-<operator>` (matches on both sides)         |
| Folder Label            | `skcomms:<operator>.<realm>`                                  |
| Device ⇄ FQID ⇄ key map | `${SKCOMMS_HOME}/peers.json` (from `skcomms peers add`, T8)  |
| Ignored files           | `~/.skcomms/.stignore` (`*.tmp *.lock *.partial *.pid logs/ *.log` …) |
