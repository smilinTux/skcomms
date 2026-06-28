# Mode B — tailnet-only private deployment (no funnel)

**Coord `5967eb6f`.** The private deployment mode: every node is already on one
Tailscale/WireGuard tailnet, so **network membership = consent** (verified, round-3
`w93r331qu`: WireGuard is *"invisible to illegitimate peers and network scanners"*).
No public attack surface → almost no consent gating needed. The opposite of Mode A
(public funnel + the full consent stack).

## The recipe (vs Mode A)

| Step | Mode A (public) | **Mode B (tailnet)** |
|------|-----------------|----------------------|
| **Exposure** | `tailscale funnel` (public `:443`) | **`tailscale serve`** (tailnet only) — or just bind tailnet + no funnel |
| **Identity** | anonymous ingress | Serve injects verified `Tailscale-User-Login` |
| **Tailscale ACLs** | n/a | **default-deny**, allow only the realm's nodes |
| **Consent** | `SKCOMMS_CONSENT_MODE=public` (full stack) | **`SKCOMMS_CONSENT_MODE=tailnet`** (deliver-all-but-blocked) |
| **Directory** | served on the public funnel; lists agents | served **tailnet-internal**; **NOT listed in any public directory** |
| **`realms.yml`** | `realm: https://<node>.ts.net` (public) | `realm: https://<node>.ts.net` resolved **over the tailnet** (WireGuard) |

## Concrete steps for a new Mode-B node
```bash
# 1. Do NOT enable funnel. Serve the inbox + directory tailnet-only:
tailscale serve --bg --https=443 --set-path=/api/v1/inbox        http://localhost:9384/api/v1/inbox
tailscale serve --bg --https=443 --set-path=/.well-known/skfed/directory http://localhost:9384/.well-known/skfed/directory
# (serve, NOT funnel → reachable only by tailnet members)

# 2. Consent mode = tailnet (network membership is the gate):
systemctl --user edit skcomms-api.service   # Environment=SKCOMMS_CONSENT_MODE=tailnet
#   and on each agent daemon (skchat-daemon@<agent>): same env.

# 3. realms.yml points at the tailnet node (tailnet members resolve it over WireGuard):
echo 'myrealm: https://<node>.<tailnet>.ts.net' > ~/.skcapstone/skcomms/realms.yml

# 4. Tailscale ACL (admin console): default-deny + allow only this realm's nodes.

# 5. Pin the realm operator key (same as Mode A) so directory sigs verify.
```

## Verified properties (this build)
- A tailnet member reaches the directory **over the tailnet** (WireGuard, the node's
  `100.x` address) with **no public funnel** — proven from `.41` → `.158`.
- `SKCOMMS_CONSENT_MODE=tailnet` → an unknown sender is **DELIVER** (authenticated by
  construction); a **blocked** sender is still **DROP**.

## Isolation rule (verified, round-3)
A Mode-B (private) realm's agents **must NOT be listed in any public Mode-A
directory** — allowlist federation is app-layer-only and porous, so topology
isolation is enforced at the **network layer** (the tailnet itself). A Mode-B agent
may make **outbound** contact to a public realm (and is gated there like any
stranger), but is never **inbound-reachable** from outside the tailnet.

## "Another instance or two"
A full separate Mode-B instance = a new tailnet node running skcomms/skchat with the
recipe above + its own realm (e.g. `private@<op>.<realm>`), serve-only, consent=tailnet.
The code path is identical to Mode A minus the funnel; standing up the node is the
only remaining work.
