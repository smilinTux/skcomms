# Getting started: pair with another operator

End-to-end walkthrough for bringing up signed, realm-scoped messaging between
two operators and then granting cross-operator memory recall. The two sides are
peers — each runs the same steps against the other's FQID.

We'll use two operators throughout:

| Operator | Realm | An agent on it (FQID) |
|---|---|---|
| `chef` | `skworld` | `lumina@chef.skworld` |
| `casey` | `douno` | `lumina@casey.douno` |

> An **FQID** is `<agent>@<operator>.<realm>`. `operator` and `realm` come from
> each side's `~/.skcapstone/cluster.json`. All paths below honor the
> `SKCOMMS_HOME` env override and otherwise default to `~/.skcomms`.

---

## 1. Both sides scaffold the realm tree

On **each** machine:

```bash
skcomms init
```

This creates `~/.skcomms/<realm>/<operator>/<agent>/{outbox,inbox}` (derived
from `cluster.json` + the resolved agent identity) and a top-level `.stignore`.
On chef's side the self tree is `~/.skcomms/skworld/chef/lumina/{outbox,inbox}`;
on casey's it's `~/.skcomms/douno/casey/lumina/{outbox,inbox}`. It is idempotent
— safe to re-run.

## 2. Exchange identity material

Each operator needs two things from the other, out of band (Signal, email, a
QR, whatever you trust):

- the peer's **Syncthing device id** — how the realm tree replicates;
- the peer's **ASCII-armored PGP public key** (`.asc`) — how envelopes are
  authenticated.

Export your own PGP public key (standard GPG; substitute your fingerprint):

```bash
gpg --armor --export <your-fingerprint> > lumina.asc
```

Get your Syncthing device id from the Syncthing web UI (Actions → Show ID) or
`syncthing --device-id`. Send your `.asc` + device id to the peer; receive
theirs.

## 3. Each side records the other peer

Wire the peer's device id + public key into `peers.json`. This derives the PGP
fingerprint from the `.asc` and **TOFU-binds** `fqid → fingerprint` (a later
re-add with a *different* fingerprint is refused — first contact pins trust).

On **chef's** machine:

```bash
skcomms peers add lumina@casey.douno \
    --syncthing-device-id CASEY1-...-DEVICEID \
    --pubkey ./casey-lumina.asc
```

On **casey's** machine, the mirror:

```bash
skcomms peers add lumina@chef.skworld \
    --syncthing-device-id CHEF1-...-DEVICEID \
    --pubkey ./chef-lumina.asc
```

Verify:

```bash
skcomms peers show lumina@casey.douno   # device id, fingerprint, added-at
```

> If your realm runs a peer registry, you can skip the explicit flags with
> `skcomms peers add lumina@casey.douno --via-registry` (and optionally
> `--tailscale <node>`); the device id + pubkey are resolved from the registry.
> Inspect it with `skcomms registry list` / `skcomms registry resolve <fqid>`.

## 4. Set up the Syncthing folders

skcomms drops message files into directories; **Syncthing carries them**. The
share is **two one-way folders** per direction — a **Send-Only** folder for your
own operator subtree and a **Receive-Only** folder for each peer's subtree — so
there is exactly one writer per file.

Configure these per the topology doc — do not improvise the folder roles/IDs:

**→ See [`docs/SYNCTHING_TOPOLOGY.md`](SYNCTHING_TOPOLOGY.md)** §2 (the two
folder roles), §3 (folder-ID conventions), and §4 (how `peers.json` maps to the
shares).

In short: share your own `~/.skcomms/<your_realm>/<your_operator>/` subtree as
**Send-Only**, and mount the peer's `~/.skcomms/<peer_realm>/<peer_operator>/`
subtree as a **Receive-Only** folder — with the device ids you recorded in
step 3. The `.stignore` written by `skcomms init` keeps volatile/local files out
of the share.

## 5. Send and verify

Once Syncthing has connected the devices, chef sends to casey:

```bash
# on chef's machine
skcomms send lumina@casey.douno "pairing test — hello from chef.skworld"
```

The signed Envelope-v1 lands in chef's `outbox` and replicates into casey's
inbox path. On **casey's** machine:

```bash
skcomms inbox
```

Each message is verified against the sender's TOFU-pinned key — a `✓` means the
signature checked out. Reply with `skcomms send lumina@chef.skworld "got it"`
to confirm the reverse direction.

## 6. Grant cross-operator memory recall

Finally, let casey's agent read one of chef's memory collections. A grant is a
**PGP-signed consent token**; skmemory verifies it offline before honoring it.

On **chef's** machine, mint a token granting casey read on the `chef.skworld/docs`
collection:

```bash
skcomms grant collection-read \
    --collection chef.skworld/docs \
    --to lumina@casey.douno \
    --expires 30d \
    -o grant-docs.json
```

`--expires` accepts `<N>d` (default `30d`) or an ISO-8601 date. Ship
`grant-docs.json` to casey (same out-of-band channel, or just `skcomms send`
the contents).

On **casey's** machine, accept it:

```bash
skcomms grants accept grant-docs.json
# or:  cat grant-docs.json | skcomms grants accept -
```

`accept` verifies the signature, the granter's TOFU trust, and the expiry, then
merges the token into `${SKCOMMS_HOME:-~/.skcomms}/recall_collections_consent.json`
— the file skmemory reads. Confirm it's held:

```bash
skcomms grants list
```

skmemory recall on casey can now read the granted collection across the realm
boundary — `peer:chef.skworld/docs` — as long as the token matches the reader
fqid (`lumina@casey.douno`), has not expired, and its signature verifies.

---

## Cheat sheet

```bash
# both operators
skcomms init

# each side, against the other's FQID
skcomms peers add <peer-fqid> --syncthing-device-id <id> --pubkey <peer>.asc
skcomms peers show <peer-fqid>

# Syncthing: Send-Only (self subtree) + Receive-Only (peer subtree)
#   -> docs/SYNCTHING_TOPOLOGY.md §2–§4

# message + verify
skcomms send <peer-fqid> "hello"
skcomms inbox

# consent (granter mints, reader accepts)
skcomms grant collection-read --collection <op>.<realm>/<name> --to <peer-fqid> --expires 30d -o grant.json
skcomms grants accept grant.json
skcomms grants list
```
