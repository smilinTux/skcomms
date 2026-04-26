# skcomms

**Realm-scoped routing protocol for sovereign AI agents.**

`skcomms` (plural) is the **protocol layer** for cross-cluster
agent communication:

- **Three-tier identity** — `<agent>@<operator>.<realm>` (e.g.
  `lumina@chef.skworld`), with PGP fingerprint as the canonical
  disambiguator.
- **Signed envelopes** — every outgoing message carries a detached
  PGP signature; unsigned envelopes are silently rejected.
- **Realm-namespaced routing** — message tree at `~/.skcomms/`
  with strict directionality (you write to your own outbox, you
  read from peer outboxes, never the reverse).
- **Sovereign-local memory** — `~/.skcapstone/agents/` *never* crosses
  realms. Only `~/.skcomms/` traverses Syncthing.

`skcomms` depends on [`skcomm`](https://github.com/smilinTux/skcomm)
(singular) for the underlying transport plumbing
(Syncthing/IMAP/file/etc).

---

## skcomm vs skcomms — the split

| Concern | Repo | Layer |
|---|---|---|
| Carrying bytes between operators (Syncthing, IMAP, file, WebRTC, …) | [`skcomm`](https://github.com/smilinTux/skcomm) | Transport |
| Defining what a message *is* (envelope schema, identity, signing, routing semantics) | `skcomms` (this repo) | Protocol |

The two layers were kept together briefly during early prototyping;
on 2026-04-26 they were split into separate repos so each can move
at its own cadence and so the dependency graph stays acyclic
(`skcomms` → `skcomm`, never the reverse).

See the design doc at `~/clawd/gtd/next/SKCOMMS_REALM_DESIGN.md`
for the full architecture rationale, including the "two `jarvis`'s
on the same realm" collision problem this fixes.

---

## Status

**Pre-alpha.** The scaffold landed 2026-04-26 (coord task `893d26dc`).
Implementation is tracked across coord tasks T1–T13, tagged
`skcomms` on the SKCapstone coordination board:

```bash
skcapstone coord status
# or filter:
ls ~/.skcapstone/coordination/tasks/ | grep skcomms
```

Phase map:

| Phase | Tasks | What lands |
|---|---|---|
| 1 — Identity bootstrap | T1, T2, T3 | `cluster.json`, fqid in `identity.json`, PGP TOFU |
| 2 — Comms scaffold | T4, T5, T6 | `~/.skcomms/` tree, envelope sign/verify, CLI |
| 3 — Syncthing wiring | T7, T8 | Topology doc, `skcomms peers add` |
| 4 — Vector namespacing | T9, T10 | recall_collections prefix + consent tokens |
| 5 — Discovery | T11 | Realm peer registry |
| 6 — Rollout + docs | T12, T13 | Bootstrap chef.skworld, full doc rollup |

---

## Install (once T1+ has shipped)

```bash
# Lives in the shared SK* venv:
~/.skenv/bin/pip install -e ".[cli,crypto]"
```

The CLI entrypoint is `skcomms`. See `skcomms --help`.

---

## License

MIT — see `LICENSE`. (`skcomm`, the transport library, is GPL-3.0-or-later;
the protocol layer is MIT to keep downstream integration unencumbered.)
