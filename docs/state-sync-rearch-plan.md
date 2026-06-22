# State-Sync Re-architecture Plan — [skfed][P5]

> Status: DESIGN (2026-06-22). Target topology + migration runbook for narrowing
> Syncthing off the monolithic `~/.skcapstone` mirror. Companion script:
> `scripts/skfed-sync-rearch.sh` (dry-run by default; `--apply` gates real REST
> changes). Implements decisions in
> `docs/federation-data-comms-architecture.md` §2, §5, §7, §7b, §9 (P5 REFINED).
>
> **MAINTENANCE MODE / SUPERVISED.** This document and the script DO NOT execute
> live Syncthing changes or restart services. The operator runs the apply steps
> supervised. `.41` is shared with **jarvis**; `.158` is **live**.

---

## 0. TL;DR

Today **one** Syncthing folder (`skcapstone-sync`) bidirectionally mirrors the
**entire** `~/.skcapstone` (~114.6k global files / 2.5 GB) between three devices.
That tree contains every agent's memory, sessions, soul, identity, trust, and
secrets — mirrored to nodes that don't even run those agents. It is the cause of
the **910 `*.sync-conflict-*` files** currently on disk (893 of them under
`agents/`), the recurring high-CPU/thermal incidents, and a data-leakage surface.

The fix (Chef-locked, §9):

1. **Memory stops syncing entirely** — it is already a **hub service**
   (`skmem-pg` Postgres on .158:5432, live `Up 5 days`). Spokes read+write
   **through** the skmemory MCP/API over Tailscale. Single writer-of-record ⇒
   the 893 `agents/*/memory` conflicts become structurally impossible.
2. **Per-agent homes sync only to that agent's own instances** — not cross-agent,
   not to nodes that don't run the agent. (Lumina/Opus home on .158; Jarvis on
   .41. No agent's mind lands on a node that doesn't run it.)
3. **One tiny SHARED folder** carries only the federation directory: peer
   registry, `federation-trust.json`, pinned pubkeys, `cluster.json`.
4. The big `skcapstone-sync` folder is **retired** (paused first, deleted after a
   bake-in).

---

## 1. Current topology (observed 2026-06-22)

### Devices in the mesh (Syncthing IDs are authoritative; names can be stale)

| Syncthing ID (short) | Syncthing name | Real host | Tailnet | Role |
|---|---|---|---|---|
| `CIHSBZ4…6V6P5AC` | `norap2027` (stale label) | **noroc2027 = .158** (THIS box) | 100.108.59.57 | hub; runs **lumina**, **opus**; `skmem-pg` :5432 |
| `4U3J4V6…5QAD3A7` | `jarvis-laptop` | **cbrd21-laptop12thgenintelcore = .41** | 100.86.156.5 | runs **jarvis**; SHARED with Chef's laptop use |
| `S5G63MA…UBRWUAN` | `ollama-gpu` | **.100** (GPU/embed box) | — | embed/LLM server; **should NOT hold agent minds** |

> ⚠️ The Syncthing *device name* `norap2027` on this node is a stale label; the
> myID `CIHSBZ4…` is this host (noroc2027/.158). Always reason from the ID.

### Folders today

| Folder ID | Path | Type | Shared with | Notes |
|---|---|---|---|---|
| `skcapstone-sync` | `~/.skcapstone` | sendreceive | .158 + .100 + **.41** | **THE PROBLEM.** 114,592 files / 2.5 GB. |
| `noroc2027-laptop…-shared` | `~/noroc2027-laptop…-shared` | sendreceive | .158 + .41 | unrelated |
| `r3zrq-9xmrl` (etc-sync) | `~/etc-sync` | sendreceive | .158 + .41 | unrelated |
| `default` | `~/Sync` | sendreceive | .158 only | unrelated |

`config.xml` is **per-node and does NOT sync** — folder/device settings must be
set on each host. `.stignore` *is* a file inside the folder and **does** sync.

### What's in `~/.skcapstone` — classification

| Bucket | Examples | Today | Target |
|---|---|---|---|
| **Memory (hub)** | `agents/*/memory/**`, `memory/**`, `index.db`, `chroma/` | synced (badly) | **STOP — hub service (skmem-pg)** |
| **Per-agent mind** | `agents/<a>/{soul,identity,seeds,journal*,trust,secrets,cloud9,fortress,wallet,capauth,config,profile.yaml,anchor.json,mood.json}` | synced cross-agent to all nodes | **per-agent folder → only that agent's own instances** |
| **Sessions** | `agents/*/sessions` (symlink → `~/.hermes/sessions`) | symlink synced | **node-local; never sync** (runtime path) |
| **Ephemeral/runtime** | `heartbeats/`, `sync/`, `pubsub/`, `metrics/daily`, `logs/`, `**/daemon.log`, `retry_queue.jsonl`, `*.tmp`, `*.session`, `shutdown_state.json`, `fallbacks.json`, `mood.json` | synced (conflict-prone) | **node-local; never sync** |
| **Shared federation directory** | `cluster.json`, `peers/`, `registry/`, `trust/trust.json` (federation-trust + pinned pubkeys) | synced inside the monolith | **tiny SHARED folder** |
| **Secrets / keys** | `*.key`, `*.pem`, `**/private.*`, `vault/`, `secure/`, `agents/*/secrets`, `agents/*/wallet` | already `.stignore`'d for keys; secrets still ride along | **per-agent only (NEVER to non-owning nodes / .100)** |

### Conflict damage today

```
910  total *.sync-conflict-*
893    agents/        ← memory & per-agent mind multi-writer churn
  4    skcomms/  4 coordination/  2 trust/  2 registry/  2 config/
  3    root (shutdown_state ×2, fallbacks ×1)
```

These are the literal symptom of the wrong topology: the same logical file
written by daemons on .158 **and** .41 (and indexed on .100). The re-arch makes
almost all of them structurally impossible (single writer per file/plane).

---

## 2. Target topology

Three classes of folder + the memory hub (no folder at all).

```
PLANE          TRANSPORT                       REPLICATION
─────          ─────────                       ───────────
memory         skmem-pg @ .158:5432            HUB SERVICE — no file sync
               via skmemory MCP/API (Tailscale)  (spokes read+write through hub)

per-agent mind Syncthing per-agent folder      ONLY that agent's own instances
                                                 (lumina/opus: .158-only today;
                                                  jarvis: .41-only today)

shared dir     Syncthing one tiny folder       all participating nodes (.158+.41)
               (federation directory)            (small, low-churn, single-purpose)

ephemeral      (none)                          NODE-LOCAL — never sync
```

### 2.1 Folder set (target)

| Folder ID | Path | Type | Shared with | Contents |
|---|---|---|---|---|
| `skfed-shared` | `~/.skcapstone/_shared` | **sendreceive** | .158 + .41 | `cluster.json`, `peers/`, `registry/`, `federation-trust.json`, pinned pubkeys. Tiny, low-churn. |
| `skagent-lumina` | `~/.skcapstone/agents/lumina` | sendreceive | **lumina's instances only** (today: .158; add a 2nd lumina node when one exists) | lumina's mind (soul/identity/seeds/journal/trust/config/profile). Memory + ephemeral `.stignore`'d. |
| `skagent-opus` | `~/.skcapstone/agents/opus` | sendreceive | **opus's instances only** (today: .158) | opus's mind. |
| `skagent-jarvis` | `~/.skcapstone/agents/jarvis` | sendreceive | **jarvis's instances only** (today: .41) | jarvis's mind (authored on .41). |
| *(retired)* `skcapstone-sync` | `~/.skcapstone` | — | — | **PAUSED then removed.** |

> **Per-agent folder = only that agent's own instances.** Each agent has exactly
> one home node today, so most per-agent folders are single-node (no peer) until
> a second instance of that agent exists. The folder is created now (single-node)
> so adding a second instance later is "share with one more device", not a
> re-architecture. `_shared` is the only multi-node folder besides legitimate
> 2-instance agents.

> **`_shared` path choice.** `~/.skcapstone/_shared` keeps the federation
> directory inside the sovereign root (so tools find it) but in its own folder so
> it syncs independently and the monolith can be retired. Migration moves
> `cluster.json` + `peers/` + `registry/` + the federation-trust/pubkey files
> into it (symlinks left behind for back-compat — see §4.4).

### 2.2 What STOPS syncing

- **All memory** — `agents/*/memory/**`, top-level `memory/**`, `index.db*`,
  `chroma/`. Served by `skmem-pg` (hub). **893 conflicts gone.**
- **Sessions** — `agents/*/sessions` (a symlink to `~/.hermes/sessions`, a
  runtime path) — node-local.
- **Ephemeral/runtime** — `heartbeats/`, `sync/`, `pubsub/`, `metrics/daily`,
  `logs/`, `**/daemon.log`, `**/*.log`, `retry_queue.jsonl`, `*.tmp`,
  `**/*.session` (Telegram), `shutdown_state.json`, `fallbacks.json`,
  `mood.json`, `unhinged.log`, `daemon.pid`, `*.pid`, `activity.jsonl*`,
  `audit.jsonl`.
- **Cross-agent mirroring** — no agent's home lands on a node that doesn't run it
  (kills the .100/.41 leakage of lumina/opus minds).
- **Secrets/keys to non-owning nodes** — secrets ride only the owning agent's
  per-agent folder, never `_shared`, never `.100`.

### 2.3 `.stignore` per folder

Each per-agent folder gets a `.stignore` (synced inside it) that ignores memory +
ephemeral, so even though the folder root is the agent home, only the durable mind
replicates:

```gitignore
# skfed per-agent .stignore — durable mind only; memory=hub, runtime=local
# Memory plane is the hub service (skmem-pg) — never file-synced
memory
/index.db
**/*.db-wal
**/*.db-shm
# Sessions = runtime symlink (host-local)
sessions
# Ephemeral / runtime (per-host, conflict-prone)
logs
**/daemon.log
**/*.log
daemon.pid
*.pid
*.tmp
*.temp
*~
heartbeats
metrics/daily
**/skwhisper/state.json
retry_queue.jsonl
**/retry_queue.jsonl
**/*.session
shutdown_state.json
fallbacks.json
mood.json
activity.jsonl
activity.jsonl.lock
audit.jsonl
unhinged.log
archive
**/memory/archive
# venv / caches
/venv
venv
__pycache__
*.pyc
*.pyo
# OS / IDE / conflict cruft
.DS_Store
Thumbs.db
.idea/
.vscode/
.stversions/
**/*.sync-conflict-*
```

`_shared` gets a minimal `.stignore`:

```gitignore
# skfed shared folder .stignore — tiny federation directory only
*.tmp
*.lock
*.pid
**/*.sync-conflict-*
.DS_Store
```

---

## 3. Migration order (supervised; operator runs)

> Run the script first in **dry-run** (default) on each node and read the plan.
> Apply **one node at a time**, starting with the hub (.158).

1. **PRE-FLIGHT (read-only, both nodes).**
   - `scripts/skfed-sync-rearch.sh` (dry-run) — prints the diff/plan.
   - Confirm `skmem-pg` is `Up` on .158 and reachable from .41 over Tailscale
     (`psql postgresql://…@100.108.59.57:5432/skmemory -c 'select 1'` once exposed,
     or via skmemory MCP). **Memory hub must be proven before stopping memory sync.**
   - Snapshot: `cp -a ~/.skcapstone ~/.skcapstone.pre-skfed-$(date +%Y%m%d)` on
     BOTH nodes (this is the rollback safety net — see §5).

2. **CLEAN CONFLICTS (both nodes, see §6).** Resolve/remove the 910
   `*.sync-conflict-*` files so they don't get carried into the new folders.

3. **PAUSE the monolith (both nodes).** Pause `skcapstone-sync` (don't delete
   yet). The agents keep running on local files; nothing replicates. This freezes
   the conflict generator immediately.

4. **CREATE `_shared` (hub .158 first, then .41).**
   - Move `cluster.json`, `peers/`, `registry/`, federation-trust + pubkeys into
     `~/.skcapstone/_shared/` (leave back-compat symlinks, §4.4).
   - Add folder `skfed-shared` (sendreceive), write its `.stignore`, share with
     the **other agent node** only (.158↔.41). **Do NOT share with .100.**

5. **CREATE per-agent folders.**
   - On **.158**: `skagent-lumina` (path `agents/lumina`), `skagent-opus`
     (path `agents/opus`), each with the per-agent `.stignore`. No peer device
     yet (single instance) — or share with a 2nd lumina/opus node if/when added.
   - On **.41**: `skagent-jarvis` (path `agents/jarvis`) with the `.stignore`.
   - Each agent folder is shared **only** with that agent's own instances.

6. **VERIFY (both nodes).** `_shared` reaches `idle` and matches on both nodes;
   per-agent folders scan to `idle`; **zero new conflicts** appear over a
   bake-in window (24 h recommended). Memory reads/writes go through the hub
   (skmemory MCP) on both nodes.

7. **RETIRE the monolith.** After the bake-in with no regressions, **remove** the
   `skcapstone-sync` folder definition on all three nodes (.158, .41, .100). The
   on-disk `~/.skcapstone` stays; only the Syncthing folder mapping is removed.
   On **.100**, this is the step that purges the leaked agent minds from that box
   (then delete the now-orphaned copies on .100 manually if desired).

> The script (`--apply`) automates steps 4–5 (create folders + .stignore + share)
> and can pause the monolith (step 3). It deliberately does **not** delete the
> monolith folder (step 7) or move files (step 4 file moves) — those are flagged
> as **manual supervised** actions in its output, so an automated run can never
> drop data.

---

## 4. Details

### 4.1 Memory hub readiness (confirmed)

- `skmem-pg` container: `Up 5 days`, `0.0.0.0:5432->5432/tcp` on .158.
- `~/.config/skmemory/pg.env`: `SKMEMORY_VECTOR_BACKEND=pgvector`,
  DSN `postgresql://postgres:***@localhost:5432/skmemory`, embed via .100:11434
  (mxbai). skmemory CLI present at `~/.skenv/bin/skmemory`.
- ⇒ **Memory is already a service.** Stopping memory file-sync loses nothing;
  the flat-file memory dirs remain on each node as a local cache and source for a
  one-time re-index if ever needed, but the authoritative store is the hub.
- Spoke access (other nodes / dev tools): skmemory MCP/API over Tailscale
  (access plane, P7). For .41 today, point its skmemory at the hub DSN over the
  tailnet (`…@100.108.59.57:5432`) instead of file-syncing.

### 4.2 Per-agent home = own instances only

`agents/<a>/` is shared with exactly the Syncthing devices that run a *second
copy of that same agent*. Today every agent is single-instance, so:
`skagent-lumina`/`skagent-opus` live on .158 with no peer; `skagent-jarvis` on
.41 with no peer. The folders exist so that adding a second instance later is a
one-line share, not a redesign. **Never** share lumina's folder with a node that
runs jarvis, etc.

### 4.3 `.100` (ollama-gpu) holds NO minds

`.100` is an embed/LLM box. It currently receives the whole `~/.skcapstone` via
`skcapstone-sync` — i.e. every agent's secrets sit on the GPU box. After re-arch,
`.100` is in **none** of the new folders. Step 7 removes its `skcapstone-sync`
mapping; then its local `~/.skcapstone` copy can be deleted.

### 4.4 Back-compat symlinks for moved shared files

Code reads `~/.skcapstone/cluster.json`, `~/.skcapstone/peers/`, etc. After
moving them into `_shared/`, leave symlinks:
`~/.skcapstone/cluster.json -> _shared/cluster.json`, `peers -> _shared/peers`,
`registry -> _shared/registry`. (Syncthing follows the symlink target's folder;
the `_shared` folder is the one that syncs them.) Verify each consumer resolves
the symlink before retiring the monolith.

---

## 5. Rollback

The monolith is **paused, not deleted**, through steps 3–6, and a full
`~/.skcapstone.pre-skfed-*` snapshot exists on both nodes (step 1). To roll back
at any point before step 7:

1. Remove the new folders (`skfed-shared`, `skagent-*`) via REST
   (`DELETE /rest/config/folders/<id>`) — this removes the *mapping*, not files.
2. Un-pause `skcapstone-sync` (`PATCH …/folders/skcapstone-sync {paused:false}`).
3. If files were moved into `_shared` (step 4) and symlinks misbehaved, restore
   from the snapshot: `rsync -a --delete ~/.skcapstone.pre-skfed-DATE/ ~/.skcapstone/`.
4. Restart Syncthing on each node.

After step 7 (monolith removed), rollback = re-add the `skcapstone-sync` folder
definition (path `~/.skcapstone`, sendreceive, share .158+.41+.100) — but only do
this if the hub-spoke memory proves unworkable, which it should not (it's live).

---

## 6. The existing config sync-conflicts — how to clean

910 `*.sync-conflict-*` files exist. They fall in two groups:

**A. Memory / runtime conflicts (the 893 under `agents/` + the root
`shutdown_state`/`fallbacks`/`mood`).** These are *expected garbage* from
multi-writer churn on data that **will stop syncing**. The new `.stignore`
already ignores `**/*.sync-conflict-*`. Resolution = **delete** them; the
source-of-truth is the hub (memory) or the live local file (runtime):

```bash
# DRY: list & count first
find ~/.skcapstone -name '*.sync-conflict-*' | wc -l
# Remove (run on each node AFTER snapshotting in step 1):
find ~/.skcapstone -name '*.sync-conflict-*' -delete
```

**B. Genuine config conflicts that need a human pick** (a handful):
`skcomms/config.yml`, `config/consciousness.yaml`, `trust/trust.json`,
`registry/skgateway.json`, `coordination/gtd/*.json`,
`agents/lumina/journal.md` (the journal conflict is **2.7 MB** vs the live
1.8 MB — do **not** blind-delete; the conflict copy may hold unique entries).
For each, diff the conflict against the live file and keep the union/newer:

```bash
for f in $(find ~/.skcapstone -name '*.sync-conflict-*' \
            \( -name '*.yml' -o -name '*.yaml' -o -name 'trust.json' \
               -o -name 'skgateway.json' -o -name 'journal*.md' \
               -o -path '*coordination/gtd*' \)); do
  orig="$(echo "$f" | sed -E 's/\.sync-conflict-[0-9-]+-[A-Z0-9]+//')"
  echo "=== $orig ==="; diff -u "$orig" "$f" | head -40
done
```

Resolve those by hand (keep the correct/merged version), THEN run the bulk
delete in (A). After re-arch these stop regenerating because each file has a
single writer (per-agent folder) or is hub-served (memory) or node-local
(runtime).

> Prevention: the per-agent + `_shared` split gives every remaining synced file
> exactly one writer, so genuine conflicts (group B) should not recur.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| **Data loss** moving shared files / deleting conflicts | Full `~/.skcapstone.pre-skfed-*` snapshot on BOTH nodes (step 1) before any change; conflicts deleted only after snapshot; group-B configs hand-merged, not blind-deleted. |
| **Memory unavailable after stopping sync** | Hub (`skmem-pg`) confirmed live & is the authoritative store; flat files remain as local cache for one-time re-index. Prove hub reachability from .41 over Tailscale in pre-flight before pausing. |
| **`.41` is shared with Jarvis / Chef** | `.41` only ever gets `skagent-jarvis` (its own agent) + `_shared` (tiny). Lumina/Opus minds leave .41. Don't touch Jarvis's home except to wrap it in its own folder; snapshot .41 too. |
| **`.100` still holds minds** | Explicit step 7 removes its monolith mapping; then delete its local copy. Until then it's no worse than today. |
| **`config.xml` per-node** | Script applies to whichever node it runs on; run on each node. It reads that node's apikey from `config.xml`. |
| **Symlinks for moved shared files break a consumer** | Leave back-compat symlinks (§4.4); verify each consumer resolves before retiring monolith; rollback via snapshot. |
| **Hand-editing `config.xml` while running** | Script uses the **REST API** (`PATCH/POST /rest/config/...`), never hand-edits `config.xml`, avoiding the shutdown-overwrite race. |
| **Sessions symlink** (`agents/*/sessions → ~/.hermes/sessions`) | `.stignore`'d (`sessions`); never synced — runtime path is host-specific. |

---

## 8. Quick reference — target

| Concept | Value |
|---|---|
| Memory | **hub service** `skmem-pg` @ .158:5432 via skmemory MCP/API (Tailscale). No file sync. |
| Per-agent mind | `~/.skcapstone/agents/<a>` → folder `skagent-<a>`, shared **only** with that agent's own instances. |
| Shared dir | `~/.skcapstone/_shared` → folder `skfed-shared` (cluster.json, peers/, registry/, federation-trust, pubkeys), .158↔.41. |
| Ephemeral/runtime/sessions | node-local, `.stignore`'d, never synced. |
| Retired | folder `skcapstone-sync` (whole `~/.skcapstone`) — paused then removed (incl. on .100). |
| Script | `scripts/skfed-sync-rearch.sh` — DRY-RUN default; `--apply` gates REST changes; never deletes the monolith or moves files. |
