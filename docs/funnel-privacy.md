# SKFed funnel privacy — front the funnel with a neutral domain

> **Problem (coord `d9cc87ad`).** The live SKFed realm directory advertises each
> agent's `inbox_url` / `prekey_url` as a raw **Tailscale Funnel** URL, e.g.
> `https://cbrd21-laptop12thgenintelcore.tail204f0c.ts.net/api/v1/inbox`. That
> hostname is the operator's **machine name** — it leaks to every sender that
> fetches the directory, every Nostr mirror, every cached copy. The directory is
> public by design (anyone resolves a FQID with no pre-shared config), so the
> hostname is effectively public too.
>
> **Fix.** Advertise a **neutral custom domain** — `fed-<agent>.skworld.io` —
> that *fronts* the funnel. The machine hostname stops appearing in the directory;
> the neutral name resolves to the same backend. Two halves:
>
> 1. **Directory re-seed** (this repo) — rewrite the advertised URLs + re-sign:
>    `scripts/skfed-neutral-addresses.sh` → `python -m skcomms.skfed_readdr`.
> 2. **Ingress cutover** (this doc) — make `fed-<agent>.skworld.io` actually
>    resolve to the funnel, via Cloudflare.
>
> This builds on the **one public `:443`** model in
> `sk-standards/standards/UNIFIED_INGRESS_STANDARD.md` (wiki synthesis:
> `wiki/pages/synthesis/unified-sovereign-ingress.md`). Federation endpoints are
> public-by-design and self-authenticate at the **envelope** layer
> (`skcomms.signing.EnvelopeSigner`/`Verifier`) — so fronting them with a neutral
> CNAME changes only the *name*, not the trust model.

---

## What actually hides the hostname

Tailscale Funnel terminates TLS at the **`*.ts.net` SNI**. A plain DNS `CNAME
fed-lumina.skworld.io → <node>.tail204f0c.ts.net` makes the neutral name *work*,
but the browser/curl still sends `Host: <node>.ts.net` after following it and the
TLS cert is still `*.ts.net` — the machine name reappears on the wire and in the
directory's TLS chain. **A DNS-only CNAME does not hide it.** You need an
intermediary that re-terminates TLS under the neutral name. Two options:

| | **A. Cloudflare proxied CNAME / Origin Rule** | **B. Cloudflare Tunnel (`cloudflared`)** |
|---|---|---|
| Public name | `fed-<agent>.skworld.io` (orange-cloud) | `fed-<agent>.skworld.io` (orange-cloud) |
| TLS at edge | CF cert for `*.skworld.io` | CF cert for `*.skworld.io` |
| Path to backend | CF → funnel `*.ts.net` (Host rewritten) | CF connector → `127.0.0.1`/tailnet backend |
| Hostname leak | edge hides it; **but** CF→origin SNI is the `.ts.net` name | **fully hidden** — no `.ts.net` anywhere |
| Inbound ports opened | 0 | 0 (outbound connector) |
| Keeps the funnel | yes (origin) | no — replaces it |
| Sovereignty | partial (CF in path) | partial (CF in path) |
| Best when | you want to keep the Tailscale funnel as-is | you want zero `.ts.net` and CF-native host routing |

**Recommendation:** **Option B (Cloudflare Tunnel)** is the clean fix — the
funnel/`.ts.net` name disappears from the directory *and* from the network path,
because the `cloudflared` connector dials the backend directly (`127.0.0.1:<port>`
or a tailnet IP). Option A is the lighter-touch choice if you want to keep the
existing funnel and only need the directory to read neutrally. Both expose exactly
one public `:443` and open zero inbound ports (per `UNIFIED_INGRESS_STANDARD`).

---

## Option A — Cloudflare proxied CNAME + Origin Rule (keep the funnel)

Keeps `tailscale funnel` as the origin; CF re-terminates TLS under
`fed-<agent>.skworld.io` and rewrites the Host header to the funnel SNI so
Tailscale routes it.

Zone `skworld.io` = `8e77fcaf568c1d953db450861a9197a2` (from
`runbooks/sksso-cloudflared-setup.sh`). Funnel host below is illustrative —
substitute your node's actual `<node>.tail204f0c.ts.net`.

```bash
# --- prerequisites (operator runs these) ---
ZONE_ID=8e77fcaf568c1d953db450861a9197a2          # skworld.io
DNS_TOKEN="$(cat ~/.config/cloudflare/dns-token | tr -d '\n\r ')"
AGENT=lumina
NEUTRAL="fed-${AGENT}.skworld.io"
FUNNEL_HOST="cbrd21-laptop12thgenintelcore.tail204f0c.ts.net"   # <- your node's funnel SNI

# 1) Proxied CNAME: fed-<agent>.skworld.io -> funnel host (orange cloud = proxied:true)
curl -s -X POST -H "Authorization: Bearer $DNS_TOKEN" -H "Content-Type: application/json" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -d "{\"type\":\"CNAME\",\"name\":\"$NEUTRAL\",\"content\":\"$FUNNEL_HOST\",\"proxied\":true,\"ttl\":1}"

# 2) Origin Rule: rewrite the Host header CF sends to the funnel to the .ts.net SNI
#    (Tailscale Funnel only answers for its own SNI). Dashboard path:
#    skworld.io > Rules > Origin Rules > Create:
#      - When incoming requests match:  Hostname equals fed-<agent>.skworld.io
#      - Then:  Host Header -> Rewrite to:  <FUNNEL_HOST>
#               SNI        -> Rewrite to:  <FUNNEL_HOST>   (so CF->origin TLS matches *.ts.net)
#    (Origin Rules are not exposed on the DNS-edit token; create in the dashboard.)
```

Caveats (Option A):
- The CF→origin leg still uses the `.ts.net` SNI (it has to — that is the only
  cert the funnel presents). The hostname is hidden from *senders* and from the
  *directory*, but it is still the real origin name on the CF→Tailscale hop. If
  that residual exposure matters, use Option B.
- SSL/TLS mode for the zone must be **Full** (the origin presents a valid
  `*.ts.net` cert), not Flexible.

---

## Option B — Cloudflare Tunnel (drop the funnel, no `.ts.net` anywhere)

A `cloudflared` connector runs on the node and dials the skcomms backend directly,
so no `.ts.net` name exists in the directory **or** on the wire. Same shape as the
live `sksso` connector (`runbooks/sksso-cloudflared-setup.sh`,
`runbooks/sksso-tunnel-create.py`).

```bash
# --- one-time login (writes ~/.cloudflared/cert.pem) ---
cloudflared tunnel login          # pick the skworld.io zone

AGENT=lumina
NEUTRAL="fed-${AGENT}.skworld.io"
BACKEND="http://127.0.0.1:9384"   # skcomms API local base (mirrors mode-b-setup LOCAL_PORT)

# 1) Create (or reuse) the tunnel
cloudflared tunnel create "skfed-${AGENT}" || true
TID="$(cloudflared tunnel list --output json \
  | python3 -c "import sys,json;print(next(t['id'] for t in json.load(sys.stdin) if t['name']=='skfed-${AGENT}'))")"

# 2) DNS route (proxied CNAME fed-<agent>.skworld.io -> <TID>.cfargotunnel.com)
cloudflared tunnel route dns "skfed-${AGENT}" "$NEUTRAL"

# 3) Config — only expose the public-by-design federation paths; 404 everything else
mkdir -p ~/.cloudflared
cat > ~/.cloudflared/skfed-${AGENT}.yml <<YAML
tunnel: ${TID}
credentials-file: ${HOME}/.cloudflared/${TID}.json
no-autoupdate: true
ingress:
  - hostname: ${NEUTRAL}
    path: /api/v1/inbox
    service: ${BACKEND}
  - hostname: ${NEUTRAL}
    path: /api/v1/prekey
    service: ${BACKEND}
  - hostname: ${NEUTRAL}
    path: /.well-known/skfed/*
    service: ${BACKEND}
  - service: http_status:404
YAML

# 4) Run it (foreground to verify; then install as a service)
cloudflared tunnel --config ~/.cloudflared/skfed-${AGENT}.yml run "skfed-${AGENT}"
# persist:  sudo cloudflared service install   (or a user systemd unit)
```

Caveats (Option B):
- Cloudflare is now in the request path (TLS terminates at the CF edge). That is
  the same partial-sovereignty tradeoff as the live `sksso` tunnel — acceptable for
  *public* federation endpoints (they are envelope-authenticated end to end, so CF
  cannot forge or read past the signature), but note it before adopting for
  anything beyond the public directory/inbox/prekey surface.
- Stop advertising the old funnel once the tunnel is live: either `tailscale funnel
  off` for those paths, or leave the funnel as a tailnet-only `tailscale serve`
  fallback (Mode-B style, `docs/mode-b-tailnet-deploy.md`).

---

## Cutover order (so there is no gap)

1. **Stand up ingress first** (Option A or B) and confirm the neutral name serves
   the backend:
   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' https://fed-lumina.skworld.io/api/v1/prekey
   ```
2. **Dry-run the re-seed** — confirm the before/after is exactly what you expect,
   nothing written:
   ```bash
   scripts/skfed-neutral-addresses.sh           # dry-run (default)
   ```
3. **Apply the re-seed** — rewrite + re-sign + persist the directory:
   ```bash
   scripts/skfed-neutral-addresses.sh --apply
   ```
4. **Verify** the directory is neutral and still signature-valid (no `ts.net`):
   ```bash
   python -m skcomms.skfed_readdr            # idempotent: shows "nothing to do"
   curl -sS https://fed-lumina.skworld.io/.well-known/skfed/directory | grep -c ts.net   # -> 0
   ```
5. **Re-publish** if you mirror the directory to Nostr (replaceable event) so the
   neutral copy supersedes the leaky one.

Doing ingress (step 1) *before* the re-seed (step 3) means the advertised neutral
URL resolves the moment it is signed — senders never see a dangling address.

## See also

- `sk-standards/standards/UNIFIED_INGRESS_STANDARD.md` — the one-`:443` standard.
- `wiki/pages/synthesis/unified-sovereign-ingress.md` — synthesis + tunnel adapter
  comparison (Funnel vs CF-Tunnel, reverse-proxy choice, capauth-gate).
- `docs/mode-b-tailnet-deploy.md` + `scripts/mode-b-setup.sh` — the *other*
  privacy posture: tailnet-only (NO funnel), network membership as the consent gate.
- `scripts/skfed-dns.sh` — print the `_skfed._tcp.<realm>` SRV/TXT so the neutral
  realm resolves with no local config.
- `scripts/skfed-neutral-addresses.sh` + `src/skcomms/skfed_readdr.py` — the re-seed.
