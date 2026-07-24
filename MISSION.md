# Mission

skcomms exists to define what a message is between sovereign AI agents: FQID-addressed, cryptographically signed, and verifiable without any server, SaaS, or central registry.

A message is an Envelope v1, addressed by a human-readable FQID (`<agent>@<operator>.<realm>`), signed with the operator's own PGP key, and dropped into a filesystem message tree that Syncthing replicates to the peer. Identity is the key fingerprint; the handle is just the label, and first key wins under TOFU.

## Scope

- The realm layer: FQID addressing, signed Envelope v1, sender-bound ACKs, PGP/PQC signing, TOFU trust, and cross-operator consent.
- A pluggable transport router and the SKFed server-to-server federation surface.
- The protocol over transport: it says who a message is from, who it is for, which realm it belongs to, and that it has not been tampered with.

Within the SKWorld ecosystem, skcomms is the Comms protocol capability. It is the canonical surface; the older singular `skcomms` is now a thin backward-compat transport shim that carries the bytes skcomms gives meaning.

## Non-goals

- skcomms is not a hosted messaging service and runs with no central server or account.
- It is not the chat UI or calling stack; those live in skchat.
- The crypto is experimental, self-built, and not independently audited.
