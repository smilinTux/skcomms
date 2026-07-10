# skcomms Bulletproof Deployment Plan

Status: PLANNED (2026-07-09)
Repo: `~/clawd/skcapstone-repos/skcomms` (main, v0.2.0)
Scope: make skcomms deployable from scratch on a cold machine, with no
secrets in git, no single point of failure, CI gates, observability,
self-recovery, and documentation good enough to stand it up blind.

## 1. Current State (short, honest)

skcomms v0.2.0 is a strong protocol library with a weak production wiring
layer. The good: 1,381 test functions across ~120 files, real CI (pytest on
3.10/3.11/3.12 with coverage, black+ruff, build+twine check), genuinely clean
secrets hygiene (tokens via env/config placeholders, no committed secrets
found), fail-closed crypto on the send path, a defense-in-depth federation
receive gate (size cap, per-sender token bucket, TOFU signature verify,
nonce replay cache), atomic tmp-then-rename file writes everywhere, and a
sound multi-rail failover topology that structurally satisfies the "get two"
mantra.

The bad: two structural defects that caused the .41 freeze are both still on
main.

First, the permanent https-s2s 422. The plain send path (`SKComms.send`,
`src/skcomms/core.py:566`, used by `POST /api/v1/send` at
`src/skcomms/api.py:696` and the presence-heartbeat broadcast at
`api.py:2658`) serializes a legacy unsigned `MessageEnvelope`, but the
router's federation chain (`src/skcomms/router.py:39`) puts `https-s2s`
first and the receiving gate `POST /api/v1/inbox` (`api.py:1035`) parses
ONLY `SignedEnvelope`. Every plain send 422s on the primary rail, forever,
then falls to the file rail. PR #7 (388a804) correctly stopped 4xx from
arming the cooldown, which means the doomed rail is re-attempted (up to a
10s timeout each) on every single message.

Second, the outbox leak. `FileTransport.send` (`transports/file.py:188`)
and `SyncthingTransport.send` (`transports/syncthing.py:257`) write
`{id}.skc.json` and report success on write. The router counts that as
delivered, the durable `PersistentOutbox` never engages, and nothing ever
deletes the sender-side files. `SyncthingTransport.prune_outbox`
(`syncthing.py:550`), written for exactly this incident, has ZERO callers.
That is the 140k-file Syncthing-pegging freeze. The hourly purge stopgap
lives only on the .41 host, not in this repo: a fresh deploy has no purge
at all.

Also missing from the repo: any systemd unit, install script, or manifest
(SOP.md section 5 describes the unit but nothing ships), pinned
dependencies, a metrics endpoint, and any alerting on queue depth.

## 2. Target: what bulletproof means for THIS repo

1. **Reproducible from scratch.** `git clone` + one bootstrap script gives a
   running daemon on a cold machine: venv with pinned deps, `skcomms init`
   scaffolding, systemd user unit with `Restart=always`, housekeeping timer,
   documented Funnel mount. The Dockerfile healthcheck path matches what the
   app actually serves.
2. **Secrets never in git.** Already true (env/config placeholders, CapAuth
   profile keys, .gitignore covers .env). Keep it true: the bootstrap script
   references secret locations, never values, and CI gets a secret-scan gate.
3. **HA, no SPOF.** Multi-rail failover already exists; make it honest.
   Delivery means "receiver acknowledged persistence", not "wrote a local
   file". File rail success means queued, not delivered. Nonce replay cache
   survives restart. Daemon restarts itself. A second-node story is
   documented.
4. **CI-gated.** Existing gates stay green, plus a wire-contract test that
   POSTs exactly what each send path emits into the real inbox handler, so
   the 422 class of bug can never ship silently again.
5. **Observable.** Outbox depth, dead-letter depth, and per-transport failure
   counters are exported and thresholded through sk-alert. The failure mode
   that froze .41 pages someone instead of reporting delivered=true.
6. **Self-recovering.** Bounded queues with backpressure, outbound throttle
   so a backlog flush cannot DoS a peer, pruning and retention on every
   unbounded directory, dead-letter requeue tooling with an operator surface.
7. **Documented.** SOP.md gains the runbook sections that currently live in
   operator memory: cold-machine standup, outbox triage, dead-letter review.

## 3. Gap Analysis (severity-ordered)

| # | Sev | Gap | Where |
|---|-----|-----|-------|
| 1 | critical | https-s2s 422: plain send emits legacy `MessageEnvelope`, inbox gate parses only `SignedEnvelope`; every plain send perm-fails the primary rail and burns a round-trip per message | core.py:566, router.py:39, api.py:1035, http_s2s.py:131 |
| 2 | critical | Outbox lifecycle: file/syncthing rails report success on local write, nothing prunes sender outboxes (`prune_outbox` has zero callers, FileTransport has no pruner), archive dirs grow unbounded; the 140k-file freeze | file.py:188, syncthing.py:257 and 550, mailbox.py:289 |
| 3 | high | Retry-store sprawl: four overlapping queues; core.RetryQueue and Router retry write INCOMPATIBLE schemas to the SAME file `~/.skcapstone/retry_queue.jsonl`; router sweeper drops core entries, core sweeper can truncate-then-lose a batch; plain send double-enqueues | core.py:89, router.py:62, outbox.py:12-28 |
| 4 | high | No queue bounds, no outbound throttle: presence broadcast loops all peers unconditionally; a backlog flush after fixing #1 could DoS a peer's rate limiter | outbox.py, api.py:2658, ratelimit.py (inbound only) |
| 5 | high | No observability on the failure mode: `pending_outbox` is exposed but nothing thresholds it; sk-alert fires only on encryption_failed/delivery_failed, and file-rail "success" means delivery_failed never fires; no /metrics, no 422 counters, no dead-letter alarm | file.py:280, integration.py, router.py:105 |
| 6 | high | No deploy artifacts in repo: no .service, no timer, no install script; Dockerfile healthcheck path (/health) mismatches the SKStacks descriptor (/healthz); cold machine cannot stand this up from the repo alone | SOP.md section 5, Dockerfile |
| 7 | high | False-positive delivery: file write terminates failover as "delivered"; S2S counts ANY 2xx as delivered without checking the `{"ok": true}` body (the opus-delivery incident) | file.py:217, http_s2s.py:171, docs/HANDOFF-skfed-s2s-opus-delivery.md |
| 8 | medium | 422 conflates unparseable (permanent) with StaleError (retryable); transport perm-fails both | api.py:1038 and 1060, http_s2s.py:363 |
| 9 | medium | CORS `allow_origins=["*"]` on the Funnel-exposed app that also carries loopback-gated consent and MCP endpoints; any web page can drive the local API cross-origin | api.py:186, api.py:516, api.py:1112 |
| 10 | medium | No wire-contract tests between send paths and the inbox gate; the transport tests mock HTTP with a fake blob that is neither envelope format | tests/test_http_s2s_transport.py |
| 11 | medium | Per-node SPOF details: in-memory nonce replay cache and rate limiter reset on restart (replay window on the public inbox); no shipped Restart= policy | api.py:798-815 |
| 12 | medium | Per-user vs per-agent path mixing: shared retry JSONL and transfers are per-user; fed inbox write uses a hardcoded path template that bypasses SKCOMMS_HOME | core.py:89, file.py:312, api.py:987 vs 859 |
| 13 | medium | No lockfile: `pip install -e .[dev]` resolves fresh, so a new machine can get different deps than CI validated | pyproject.toml |
| 14 | low | Dead-letter queue has no alerting, no documented CLI triage verb, no retention on dead/ and archive/ | outbox.py:284 and 332, SOP.md |

## 4. Remediation Roadmap

Phases are ordered by deploy-criticality. Items marked [P] are
parallelizable within their phase.

### Phase 0: Stop the bleeding (the two live bugs)

Dependencies: none. These are the reason skcomms is "most urgent" in the
initiative.

1. **Fix the https-s2s 422** by unifying the wire format: plain send signs
   and routes `SignedEnvelope` like `send_federated` does (sign-at-send on
   every rail). If a legacy consumer truly needs `MessageEnvelope`, gate it
   behind an explicit local-only rail; `https-s2s` must locally perm-fail
   (no network round-trip) any bytes that do not classify as `signed` via
   `classify_envelope_json`.
2. **Wire the outbox lifecycle** [P with 1]: call `prune_outbox` from the
   daemon housekeeping loop, add the FileTransport equivalent, put TTL
   retention on receiver archive dirs and mailbox outbox records. This makes
   a fresh deploy safe even before delivery semantics are fixed.

### Phase 1: Honest delivery and a single queue of record

Depends on Phase 0 item 1 (wire format unified).

3. **Fix delivery semantics**: file/syncthing send returns "queued", not
   delivered; router keeps the durable outbox entry until an ACK (connect
   `AckTracker` to outbox cleanup); https-s2s verifies the `{"ok": true}`
   response body, not just 2xx.
4. **Consolidate retry stores** [P with 3]: `PersistentOutbox` becomes the
   single queue of record; delete core.RetryQueue and the router JSONL path;
   kill the double-enqueue in plain send; migrate any existing JSONL entries
   with the outbox_migrate tooling.
5. **Wire-contract regression tests**: SKComms.send and send_federated,
   captured wire bytes, FastAPI TestClient POST /api/v1/inbox, assert 200
   plus inbox file written. Lands after 1 so it lands green, then guards it
   forever.

### Phase 2: Bounded, throttled, observed

Depends on Phase 1 item 4 (one queue to bound).

6. **Queue bounds + outbound throttle**: max pending-entry counts with
   backpressure (429 to local callers), per-peer file-outbox depth cap,
   outbound RateLimiter in the router, paced backlog flush so fixing the 422
   does not DoS peers.
7. **Observability** [P with 6]: outbox-depth and dead-letter-depth gauges
   thresholded through sk-alert, per-transport failure counters exported
   (router already tracks them in memory), optional Prometheus /metrics.
8. **Stale vs schema 422 split** [P with 6, 7]: distinct status/detail for
   StaleError so the transport retries it instead of perm-failing.

### Phase 3: Ship the deploy path

Depends on Phase 0 item 2 (housekeeping verbs exist for the timer to call).

9. **contrib/systemd + bootstrap script**: skcomms-api.service
   (Restart=always), housekeeping timer (prune + outbox sweep), idempotent
   install script (venv, pinned deps, skcomms init, unit install), reconcile
   the /health vs /healthz mismatch, SOP.md cold-machine runbook.
10. **Pin dependencies** [P with 9]: lockfile or constraints file, CI
    installs from it, deploy uses exactly what CI validated.

### Phase 4: Hardening (parallel, independent)

11. **CORS lockdown** [P]: scope origins or drop the middleware and require
    a token on non-loopback surfaces.
12. **Durable nonce cache + watchdog** [P]: persist the replay cache across
    restarts (needs the unit from Phase 3 for the watchdog half), document
    the second-node story.
13. **Per-agent path unification** [P]: derive retry/transfer/inbox paths
    from SKCOMMS_HOME and agent config, delete the hardcoded template.
14. **Dead-letter operator surface** [P]: CLI triage verb, retention policy
    on dead/ and archive/, alert on dead_count growth (builds on Phase 2
    observability).

## 5. Task List

The authoritative task set returned to the orchestrator. Titles are exact;
depends_on references are by title.

| Task | Priority | Depends on |
|------|----------|-----------|
| skcomms: fix https-s2s 422 wire-format mismatch (sign-at-send everywhere) | critical | none |
| skcomms: wire outbox pruning and archive retention into the daemon | critical | none |
| skcomms: honest delivery semantics (file rail = queued, S2S verifies ok body, ACK-tied outbox cleanup) | high | 422 fix |
| skcomms: consolidate retry stores onto PersistentOutbox | high | 422 fix |
| skcomms: wire-contract tests from send paths into POST /api/v1/inbox | high | 422 fix |
| skcomms: bound all queues and add outbound send throttling | high | retry consolidation |
| skcomms: outbox and dead-letter observability through sk-alert plus metrics | high | none |
| skcomms: ship systemd unit, housekeeping timer, and bootstrap install script | high | outbox pruning |
| skcomms: pin dependencies for reproducible installs | medium | none |
| skcomms: split stale-envelope rejection from schema 422 and make it retryable | medium | none |
| skcomms: lock down CORS on the Funnel-exposed API | medium | none |
| skcomms: durable nonce replay cache and restart watchdog | medium | systemd unit |
| skcomms: unify per-agent path scoping for queues, transfers, and fed inbox | medium | retry consolidation |
| skcomms: dead-letter operator surface and retention policy | low | observability task |

Definition of done for the initiative: a cold machine runs the bootstrap
script and gets a green /health, the contract tests gate CI, the .41 hourly
purge stopgap is deleted because the repo owns housekeeping, and an outbox
depth over threshold pages sk-alert instead of freezing a laptop.
