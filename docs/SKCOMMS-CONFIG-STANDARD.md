# SKComms Configuration Standard (sk-standards SOP)

Date: 2026-08-30
Status: Current standard for SKComms on Casey's cluster.

## Canonical home

- The standard default home for the SKComms message tree is **`~/.skcapstone/skcomms/`**.
- `~/.skcomms` is **legacy**. Use `SKCOMMS_HOME` env to override if needed.
- All SKComms config, peers, keys, and the realm tree live under `~/.skcapstone/skcomms/`.

## Default transport: local filesystem

Per sk-standards, the **default transport is the local filesystem** (`file` transport).
The realm message tree is:

```
~/.skcapstone/skcomms/
  .stignore
  <realm>/<operator>/<agent>/
    outbox/
    inbox/
  peers/          # PeerStore YAML files + pinned .asc public keys
  peers.json       # TOFU-pinned device + fingerprint records
  config.yml       # shared transport config
  state/           # per-node volatile state (nonce cache etc.)
```

For the jarvis agent on Casey's cluster (`jarvis@casey.skworld.io`), the self tree is:

```
~/.skcapstone/skcomms/skworld.io/casey/jarvis/{outbox,inbox}
```

## P2P replication: Syncthing (not a central server)

Syncthing replicates the `~/.skcapstone/skcomms/` tree between nodes. It is **P2P**, not
a central server or broker. Folder IDs follow the `skcomms-<realm>-<operator>` convention:

| Folder ID | Label | Path |
|---|---|---|
| `skcomms-skworld.io-casey` | `skcomms:casey.skworld.io` | `~/.skcapstone/skcomms` |
| `skcomms-skworld.io-chef` | `skcomms:chef.skworld.io` | `~/.skcapstone/skcomms` |

Each operator **publishes** their own operator subtree (Send-Only) and **subscribes**
(read-only) to each peer's subtree. This is the safe, non-conflicting topology.

## PGP identity and TOFU pinning

- The local `jarvis` identity is the CapAuth PGP key with fingerprint
  `C8D406A46F2DF4894E4FB41580A638570C9D41C4`.
- The private key passphrase is stored in `~/capauth-pass/jarvis.passphrase.env` and must
  be exported as `SKCOMMS_KEY_PASSPHRASE` before running `skcomms serve` or any signing
  operation.
- Peer public keys are pinned via `skcomms peers add <fqid> --syncthing-device-id <id>
  --pubkey <path>`. This records the Syncthing device id + PGP fingerprint in
  `peers.json` (TOFU: a conflicting fingerprint on re-add is REFUSED).
- The pinned public key armor is stored at `~/.skcapstone/skcomms/peers/<fqid>.asc`.

## Nostr-sf encryption standard

- All nostr traffic is **encrypted before use**: NIP-17 gift-wrap + NIP-44 v2.
- Each peer YAML carries a per-peer `nsec` (32-byte secret, hex-encoded) in the nostr-sf
  transport settings, and a `nostr_pubkey` field at the peer level.
- The placeholder `pubkey: 0xJARVIS_PUBKEY_PLACEHOLDER` in `jarvis-casey.skworld.io.yml`
  must be replaced with a real nostr pubkey. The `nsec` is the locally-generated 32-byte
  secret used to gift-wrap DMs.
- For cross-node delivery, each node must hold a matching `nsec` for the peer.

## Config file (`~/.skcapstone/skcomms/config.yml`)

```yaml
identity:
  name: jarvis

transports:
  file:
    enabled: true
    settings:
      inbox_path: ~/.skcapstone/skcomms/skworld.io/casey/jarvis/inbox
      outbox_path: ~/.skcapstone/skcomms/skworld.io/casey/jarvis/outbox
  syncthing:
    enabled: true
    settings:
      comms_root: ~/.skcapstone/skcomms
      folder_id: skcomms-skworld.io-casey
  nostr-sf:
    enabled: true
    settings:
      relay: wss://relay.skfed.net
```

- The config is **one shared file** for all agents on the box. The `SKAGENT` env
  (or `SKCAPSTONE_AGENT` fallback) selects the per-agent identity and paths.
- `SKCOMMS_HOME` overrides the home root (defaults to `~/.skcapstone/skcomms`).

## SOP steps

1. **Peer seeding**: write the agent peer YAML files into
   `~/.skcapstone/skcomms/peers/` (see `/tmp/seed_skcomms_peers.py`).
2. **PGP pinning**: `skcomms peers add <fqid> --syncthing-device-id <id> --pubkey <path>`.
3. **Nostr encryption**: every nostr-sf transport must carry a per-peer `nsec`; all DMs
   are NIP-44 v2 gift-wrapped. No plaintext nostr traffic.
4. **Syncthing P2P**: register the `skcomms-<realm>-<operator>` folders in
   `~/.local/state/syncthing/config.xml`, restart Syncthing to apply.
5. **Config**: edit `~/.skcapstone/skcomms/config.yml` for transport and identity settings.
6. **Passphrase**: `export SKCOMMS_KEY_PASSPHRASE=$(cat ~/capauth-pass/jarvis.passphrase.env)`
   before starting `skcomms serve`.

## Verification

- `curl -s http://127.0.0.1:9384/api/v1/peers` lists all seeded peers with their rails.
- `skcomms send <fqid> "<message>"` drops a sealed PGP envelope into the peer's inbox.
- `skcomms inbox --agent jarvis` lists + verifies signed messages in the inbox.
- `syncthing cli show config-status` confirms the new folders are registered.

## Rollback

- Restore prior bytes of `~/.local/state/syncthing/config.xml` (backups exist under
  `~/.local/state/syncthing/backups/`).
- Remove seeded peer YAML files and the `peers.json` entry to revert peer seeding.
- Delete `~/.skcapstone/skcomms/config.yml` to revert to built-in defaults.
- Move any envelopes from `skworld.io/casey/jarvis/inbox/` back to
  `skworld.io/chef/jarvis/inbox/` if reverting the identity correction.
