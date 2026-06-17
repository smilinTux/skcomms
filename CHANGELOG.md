# Changelog

All notable changes to `skcomms` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
