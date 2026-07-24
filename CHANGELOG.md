# Changelog

## [Unreleased]

### Fixed
- **Broadcast heartbeats no longer persisted to the durable outbox.**
  `FileTransport.send()` wrote EVERY envelope, including `to_fqid="*"` broadcast
  presence heartbeats, to the flat durable outbox
  (`~/.skcapstone/agents/<agent>/comms/outbox/<id>.skc.json`), capped at 1000 and
  oldest-evicted. A `*` broadcast has no single recipient inbox on the file rail,
  so ~1 ping/min/agent piled up undeliverable and churned; across agents ~3000
  files, which bloated Syncthing (2.4GB index, high CPU, 2.1GB RSS on the
  operator laptop). Now a `recipient == "*"` send is fire-and-forget
  (`success=True`, `queued=False`, no disk write) since presence is already
  published to `sync/heartbeats/<node>.json`; directed messages still persist
  durably. Was the last un-fixed broadcast writer (the PersistentOutbox hold and
  the SyncthingTransport `*` rejection were already fixed).
- **Nonce replay caches are now NODE-LOCAL, outside the Syncthing tree.**
  `nonce_cache.db` (federation inbox) and `access_nonce_cache.db` (sk-access)
  used to default under `skcomms_home()/state/`; on live fleets that home is
  inside a Syncthing-shared tree rooted ABOVE the home, where the home's own
  `.stignore` has no effect, so two nodes synced one live WAL SQLite (conflict
  copies observed, corruption risk, defeated durable-replay guarantee). Both
  caches now resolve to `SKCOMMS_NONCE_CACHE_DIR` >
  `$XDG_STATE_HOME/skcomms/` > `~/.local/state/skcomms/`. Exact-file overrides
  `SKCOMMS_NONCE_DB` / `SKCOMMS_ACCESS_NONCE_DB` still win. A healthy legacy DB
  is migrated once (SQLite backup API); a corrupt one is skipped with a warning
  and the cache starts fresh (safe: replay exposure bounded by the ~5 min
  envelope freshness window). The legacy `.stignore` healing stays so any
  leftover `state/` DB stops syncing until ops delete it.

### Added
- **Durable nonce replay cache** (coord 11e295a3): `federation.DurableNonceCache`,
  a SQLite-backed drop-in for the in-memory `NonceCache`. The S2S inbox replay
  guard now survives daemon restarts (no replay window on the Funnel-exposed
  inbox after a crash or deploy). Default store `skcomms_home()/state/nonce_cache.db`,
  path override `SKCOMMS_NONCE_DB`, explicit in-memory opt-out
  `SKCOMMS_NONCE_CACHE=memory`. Fails closed if the store cannot be opened.
  Entries expire with the nonce TTL so the file stays bounded. `state/` added
  to the generated `.stignore` (per-node, never synced).
- **Restart watchdog hardening**: `contrib/systemd/skcomms-api.service` gains
  `StartLimitIntervalSec=0` so systemd never parks a crash loop in a permanent
  failed state; combined with `Restart=always` the rail always comes back.
- **SOP.md**: "Crash recovery and the second-node story" section documents what
  survives a restart, what a second instance shares, and what stays per-node.
- **Bounded queues + outbound send throttling** (coord 74d7b799):
  - `PersistentOutbox` now enforces a configurable `max_pending` bound
    (default 5000; `outbox.max_pending` in config). Enqueueing past the bound
    raises `OutboxFullError`, an `outbox_full` sk-alert fires, and the HTTP
    API maps it to a 429 so local callers get explicit backpressure instead
    of a silently unbounded on-disk queue. Rewrites of an existing entry and
    supersede-key replacements never grow the queue, so they stay exempt.
  - Retry sweeps drain in bounded, paced batches (`outbox.sweep_batch`,
    default 50 delivery attempts per sweep; the remainder is deferred to the
    next sweep) so a backlog flush can no longer flood a recovering rail or a
    receiving node's inbox rate limiter.
  - The router now passes every send attempt (route/route_bytes/route_signed,
    retries, broadcasts, store-and-forward) through an outbound
    `RateLimiter` (config `ratelimit:` section, enabled by default with
    generous token-bucket limits per rail and per peer). Throttled attempts
    fail fast with a `throttled:` error, never reach the transport, never arm
    the cooldown, and are counted separately
    (`skcomms_transport_throttled_total` in /metrics).
  - `FileTransport` and `SyncthingTransport` cap outbox depth at send time
    with oldest-eviction (`max_outbox_depth`, default 1000; per peer for
    syncthing), bounding COUNT the same way the TTL pruners bound AGE.

### Changed
- **Behavior change (per-agent path scoping, coord 119b49f1):**
  `config.load_config` now raises `ValueError` at startup when the selected
  agent name (`SKAGENT` / `SKCAPSTONE_AGENT`) is path-unsafe (contains a
  separator, traversal token, or NUL). Previously such a value was used
  silently. Fail closed: fix the env var rather than letting storage scope
  into a rogue tree.
- **Behavior change:** the `inbox_path` / `outbox_path` transport settings
  and `daemon.log_file` produced by `load_config` are now absolute expanded
  paths instead of `~`-prefixed strings. Equivalent after `expanduser`, but
  visible to anything that displays or persists the config.
- The `SKCOMMS_OUTBOX_DIR` env override now also drives a default-constructed
  `PersistentOutbox()` (via `paths.retry_outbox_dir`), not only the CLI-passed
  root. Explicit env override wins over per-agent scoping, keeping
  `outbox.default_outbox_dir()` and `PersistentOutbox().root` in agreement.
- Peer-trace discovery (`discovery.discover_file_transport`) defaults now
  resolve through `skcomms.paths` (per-agent comms inbox/outbox when an
  agent is resolvable) instead of the node-shared `SKCOMMS_HOME`
  inbox/outbox, so discovery keeps seeing envelopes on agent-scoped nodes.

### Fixed
- **Queue adoption pair-split race:** two agent daemons adopting the same
  legacy node-shared queue concurrently could split an envelope/meta file
  pair across their trees, silently stranding the message (drain and purge
  glob only meta files). Adoption now claims by meta rename first
  (`paths.adopt_legacy_pairs`); only the claim winner moves the matching
  envelope, so a pair always lands whole in exactly one agent's tree.
- In-flight resumable transfer state at the legacy shared location is now
  adopted into the per-agent transfers dir on first use, matching the queue
  and retry-outbox upgrade contract: `resume_file` keeps finding pre-upgrade
  state instead of restarting transfers. Adoption stays within the current
  `skcomms_home()`; a deployment relocated onto a custom `SKCOMMS_HOME`
  migrates any state left at the fixed `~/.skcapstone/transfers` /
  `~/.skcapstone/skcomms/outbox` locations by hand (those stores never
  honored `SKCOMMS_HOME`, so reaching into the fixed path from a custom home
  is deliberately avoided).

## [0.2.0] - 2026-07-03

### Changed
- Release.

All notable changes to `skcomms` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.7] — 2026-06-17

### Added
- **AdapterRegistry instantiated in the daemon lifespan** (U14 keystone):
  the daemon now builds its registry from config via
  `build_registry_from_config(...)` and drives `AdapterRegistry.start()` /
  `AdapterRegistry.stop()` from the lifespan begin/teardown. Backward
  compatible — with no `adapters` block in config the registry is built
  empty and the daemon behaves exactly as before. The accompanying factory
  (`build_registry_from_config`) and `AdapterRegistry` live in
  `src/skcomms/adapters/registry.py`.

### Fixed
- **Per-agent wire identity in `load_config`** (`src/skcomms/config.py`):
  the transmit identity is now overridden from `SKAGENT` (primary), falling
  back to `SKCAPSTONE_AGENT`, instead of always resolving to `lumina`. This
  closes the identity collision where non-lumina agents (e.g. `opus`)
  transmitted on the wire as `lumina`. `SKAGENT` matches the skcapstone
  agent-resolution selector; `SKCAPSTONE_AGENT` is the documented fallback.

---

## [0.1.6] — 2026-06-16

### Added
- **Recipient-name validation in the Syncthing transport** (`_validate_peer_name`):
  recipient/peer names are validated at the boundary where the
  `outbox/<peer>/` (and `inbox/<peer>/`) directory is actually created.
  Names that are empty/whitespace-only, contain glob metacharacters
  (`* ? [ ]`), path separators (`/` `\`), path traversal (`..`), or a NUL
  byte are rejected with a `ValueError` naming the offending value. A literal
  `*` recipient can no longer create an `outbox/*/` directory.
- **Optional `SyncthingTransport.prune_outbox(max_age_hours=48.0)`** self-trim
  safety valve: deletes `*.skc.json` files older than the threshold from
  `outbox/<peer>/`, removes emptied peer dirs, and returns the count. Never
  called automatically on send — the authoritative pruner remains skcapstone
  housekeeping; this is a conservative library-level guard.
- `receive()` now skips invalid peer subdirectories (e.g. a stray `*` dir left
  over from a v1 broadcast bug) as defense in depth.

### Fixed
- Defends against the v1 broadcast-directory incident: a presence broadcast
  (`recipient="*"`) was written verbatim as a literal `outbox/*/` directory,
  accumulating ~256k stale envelopes until a Framework 13 laptop overheated
  churning the filesystem. The transport now makes this class of bug
  impossible and keeps outboxes self-bounding.

---

## [0.0.1] — 2026-04-26

### Added
- Initial scaffold (T0 — coord task `893d26dc`).
- Package skeleton: `cluster`, `envelope`, `identity`, `realm` stub modules.
- Smoke test confirming `import skcomms` and `__version__ = "0.0.1"`.
- Dependency on `skcomms>=0.1.2` (transport library).
- GPL-3.0-or-later license, matching the rest of the smilinTux ecosystem.

### Fixed
- LICENSE file now contains the full GPL-3.0 text (an earlier draft of
  this commit-set had it as MIT; CHANGELOG and pyproject license
  classifier are now consistent across all artifacts).

### Decision (T0)
This repository is intentionally **separate from `skcomms`** (the singular
transport library). `skcomms` carries bytes between operators; `skcomms`
defines the *protocol* (three-tier identity, signed envelopes,
realm-namespaced routing). Different abstraction layers, independent
release cadences, cleaner dep graph. `skcomms` imports `skcomms`.

See `README.md` and the design doc at
`~/clawd/gtd/next/SKCOMMS_REALM_DESIGN.md`.
