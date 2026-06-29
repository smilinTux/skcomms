#!/usr/bin/env bash
# Smoke test for scripts/skfed-dns.sh — the realm DNS-record generator. Asserts
# it PRINTS correct SRV + TXT records (and never claims to edit DNS). Hermetic:
# needs no DNS / network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../scripts/skfed-dns.sh"
fail=0
ok()  { printf '  ok   %s\n' "$*"; }
bad() { printf '  FAIL %s\n' "$*"; fail=1; }
has() { case "$OUT" in *"$2"*) ok "$1";; *) bad "$1 (missing: $2)";; esac; }
hasnt() { case "$OUT" in *"$2"*) bad "$1 (unexpected: $2)";; *) ok "$1";; esac; }

[ -x "$SCRIPT" ] || { echo "FAIL: $SCRIPT not executable / missing"; exit 1; }

REALM="skworld"
HOST="dir.skworld.io"

echo "== default (zone) format, port 443 =="
# stdout only (records are pasteable); guidance goes to stderr.
if OUT="$("$SCRIPT" --realm "$REALM" --host "$HOST" 2>/dev/null)"; then
  ok "exit 0"
else
  bad "nonzero exit"; OUT=""
fi
has   "SRV record name"              "_skfed._tcp.${REALM}."
has   "SRV points at host:443"       "IN	SRV	0 0 443 ${HOST}."
has   "TXT record name"              "_skfed.${REALM}."
has   "TXT carries url= (no :443)"   "\"url=https://${HOST}\""
hasnt "no :443 in derived url"       "https://${HOST}:443"

echo "== custom port => host:port in url + SRV =="
OUT="$("$SCRIPT" --realm "$REALM" --host node1.tail.ts.net --port 8443 2>/dev/null)"
has "SRV uses custom port"           "0 0 8443 node1.tail.ts.net."
has "url carries :8443"              "\"url=https://node1.tail.ts.net:8443\""

echo "== explicit --url overrides derivation =="
OUT="$("$SCRIPT" --realm "$REALM" --host h --url https://override.example/dir 2>/dev/null)"
has "explicit url used"              "\"url=https://override.example/dir\""

echo "== tab format =="
OUT="$("$SCRIPT" --realm "$REALM" --host "$HOST" --format tab 2>/dev/null)"
has "tab header"                     "TYPE	NAME	TTL	VALUE"
has "tab SRV row"                    "SRV	_skfed._tcp.${REALM}"
has "tab TXT row"                    "TXT	_skfed.${REALM}"

echo "== bind format =="
OUT="$("$SCRIPT" --realm "$REALM" --host "$HOST" --format bind 2>/dev/null)"
has "bind \$TTL line"                "\$TTL 300"

echo "== custom ttl =="
OUT="$("$SCRIPT" --realm "$REALM" --host "$HOST" --ttl 600 2>/dev/null)"
has "custom ttl applied"             "600"

echo "== honesty: never claims to edit DNS =="
ERR="$("$SCRIPT" --realm "$REALM" --host "$HOST" 2>&1 1>/dev/null)"
case "$ERR" in *"only PRINTS"*) ok "states print-only";; *) bad "missing print-only note";; esac
hasnt "stdout has no edit verbs" "Updating DNS"

echo "== --dry-run is an accepted no-op =="
if OUT="$("$SCRIPT" --realm "$REALM" --host "$HOST" --dry-run 2>/dev/null)"; then
  ok "--dry-run exit 0"
  has "dry-run still prints SRV" "_skfed._tcp.${REALM}."
else
  bad "--dry-run nonzero"
fi

echo "== arg validation =="
if "$SCRIPT" --host "$HOST" >/dev/null 2>&1; then bad "missing --realm should fail"; else ok "missing --realm exits nonzero"; fi
if "$SCRIPT" --realm "$REALM" >/dev/null 2>&1; then bad "missing --host should fail"; else ok "missing --host exits nonzero"; fi
if "$SCRIPT" --realm "$REALM" --host "$HOST" --format bogus >/dev/null 2>&1; then bad "bad --format should fail"; else ok "bad --format exits nonzero"; fi
if "$SCRIPT" --help >/dev/null 2>&1; then ok "--help exits 0"; else bad "--help should exit 0"; fi

echo
if [ "$fail" = 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi
