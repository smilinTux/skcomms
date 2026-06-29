#!/usr/bin/env bash
# skfed-dns.sh — GENERATE the DNS records that publish a realm's skfed directory.
#
# A node resolves `<agent>@<operator>.<realm>` to live endpoints by first finding
# the realm's signed-directory host. skcomms.skfed_resolve.resolve_realm_directory
# looks it up via DNS in this order:
#     1. SRV   `_skfed._tcp.<realm>`   -> (host, port)  ->  https://host[:port]
#     2. TXT   `_skfed.<realm>`        -> "url=https://..."
# This script PRINTS the exact SRV + TXT records to add at your DNS provider so a
# realm becomes resolvable with NO local config on the sender side.
#
# IT ONLY PRINTS. It never edits DNS (that stays a human/console step) — so it is
# inherently safe; `--dry-run` is accepted as an explicit no-op for symmetry.
#
# Usage:
#   scripts/skfed-dns.sh --realm <realm> --host <directory-host> \
#       [--port 443] [--url https://...] [--ttl 300] [--format zone|tab|bind] [--dry-run]
#
# Examples:
#   scripts/skfed-dns.sh --realm skworld --host dir.skworld.io
#   scripts/skfed-dns.sh --realm skworld --host node1.tailXYZ.ts.net --port 8443 --format tab
#
set -euo pipefail

REALM=""
HOST=""
PORT="443"
URL=""
TTL="300"
FORMAT="zone"
DRY_RUN=0

usage() { sed -n '2,23p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --realm)   REALM="${2:-}"; shift ;;
    --host)    HOST="${2:-}"; shift ;;
    --port)    PORT="${2:-}"; shift ;;
    --url)     URL="${2:-}"; shift ;;
    --ttl)     TTL="${2:-}"; shift ;;
    --format)  FORMAT="${2:-}"; shift ;;
    --dry-run) DRY_RUN=1 ;;       # no-op: this script never edits DNS anyway
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
  shift
done

missing=""
[ -n "$REALM" ] || missing="$missing --realm"
[ -n "$HOST" ]  || missing="$missing --host"
if [ -n "$missing" ]; then
  echo "ERROR: missing required arg(s):$missing" >&2
  usage 2
fi

case "$FORMAT" in
  zone|tab|bind) ;;
  *) echo "ERROR: --format must be one of: zone tab bind" >&2; exit 2 ;;
esac

# Derive the directory URL if not given (drop :443 — it's the https default).
if [ -z "$URL" ]; then
  if [ "$PORT" = "443" ]; then
    URL="https://${HOST}"
  else
    URL="https://${HOST}:${PORT}"
  fi
fi

SRV_NAME="_skfed._tcp.${REALM}"
TXT_NAME="_skfed.${REALM}"
# SRV target must be a FQDN (trailing dot) for most zone formats.
SRV_TARGET="${HOST%.}."

emit_zone() {
  printf '; --- skfed discovery records for realm "%s" ---\n' "$REALM"
  printf '; add these at the authoritative DNS for "%s" (do NOT need to edit anything else)\n' "$REALM"
  printf '%s.\t%s\tIN\tSRV\t0 0 %s %s\n' "$SRV_NAME" "$TTL" "$PORT" "$SRV_TARGET"
  printf '%s.\t%s\tIN\tTXT\t"url=%s"\n' "$TXT_NAME" "$TTL" "$URL"
}

emit_bind() {
  # BIND-style with explicit $TTL line; names without trailing dot are
  # origin-relative — most operators paste these under the zone's $ORIGIN.
  printf '$TTL %s\n' "$TTL"
  printf '%s.\tIN\tSRV\t0 0 %s %s\n' "$SRV_NAME" "$PORT" "$SRV_TARGET"
  printf '%s.\tIN\tTXT\t"url=%s"\n' "$TXT_NAME" "$URL"
}

emit_tab() {
  # Provider-console friendly columns: TYPE  NAME  TTL  VALUE
  printf '%s\t%s\t%s\t%s\n' "TYPE" "NAME" "TTL" "VALUE"
  printf '%s\t%s\t%s\t%s\n' "SRV" "$SRV_NAME" "$TTL" "0 0 ${PORT} ${SRV_TARGET}"
  printf '%s\t%s\t%s\t%s\n' "TXT" "$TXT_NAME" "$TTL" "url=${URL}"
}

case "$FORMAT" in
  zone) emit_zone ;;
  bind) emit_bind ;;
  tab)  emit_tab ;;
esac

# Footer guidance (to stderr so stdout stays pasteable / parseable).
{
  echo ""
  echo "NOTE: this only PRINTS records — add them at your DNS provider yourself."
  echo "      Verify after propagation:"
  echo "        dig +short SRV ${SRV_NAME}"
  echo "        dig +short TXT ${TXT_NAME}"
  echo "      Then any node resolves the realm with no local config:"
  echo "        python -c \"from skcomms.skfed_resolve import resolve_realm_directory as r; print(r('${REALM}'))\""
  if [ "$DRY_RUN" = 1 ]; then
    echo "      (--dry-run given: no-op — this script never edits DNS regardless.)"
  fi
} >&2
