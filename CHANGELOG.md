# Changelog

All notable changes to `skcomms` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.1] — 2026-04-26

### Added
- Initial scaffold (T0 — coord task `893d26dc`).
- Package skeleton: `cluster`, `envelope`, `realm` stub modules.
- Smoke test confirming `import skcomms` and `__version__ = "0.0.1"`.
- Dependency on `skcomm>=0.1.2` (transport library).
- GPL-3.0-or-later license, matching the rest of the smilinTux ecosystem.

### Decision (T0)
This repository is intentionally **separate from `skcomm`** (the singular
transport library). `skcomm` carries bytes between operators; `skcomms`
defines the *protocol* (three-tier identity, signed envelopes,
realm-namespaced routing). Different abstraction layers, independent
release cadences, cleaner dep graph. `skcomms` imports `skcomm`.

See `README.md` and the design doc at
`~/clawd/gtd/next/SKCOMMS_REALM_DESIGN.md`.
