#!/usr/bin/env bash
# Smoke test for scripts/mode-b-setup.sh — the Mode-B (tailnet-only) realm
# stand-up script. Exercises the --dry-run PLAN path only: asserts every planned
# step is present AND that dry-run mutates NOTHING on disk. No tailscale / systemd
# / skcomms required (dry-run is hermetic).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../scripts/mode-b-setup.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail=0
ok()  { printf '  ok   %s\n' "$*"; }
bad() { printf '  FAIL %s\n' "$*"; fail=1; }
has() { # has "desc" "needle"  (against $OUT)
  case "$OUT" in *"$2"*) ok "$1";; *) bad "$1 (missing: $2)";; esac
}
hasnt() { # hasnt "desc" "needle"
  case "$OUT" in *"$2"*) bad "$1 (unexpected: $2)";; *) ok "$1";; esac
}

[ -x "$SCRIPT" ] || { echo "FAIL: $SCRIPT not executable / missing"; exit 1; }

REALM="testrealm"
AGENT="lumina"
HOST="node1.tail-abc.ts.net"
SKHOME="$TMP/skcomms-home"
SDDIR="$TMP/systemd-user"

run_dry() {
  SKCOMMS_HOME="$SKHOME" SYSTEMD_USER_DIR="$SDDIR" \
    "$SCRIPT" --realm "$REALM" --agent "$AGENT" --tailnet-host "$HOST" \
              --known "alice@op.realmA" --known "bob@op.realmB" \
              --operator-key "$TMP/operator.asc" --dry-run 2>&1
}

# A fake operator key so the pin step has a real source path to reference.
printf -- '-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----\n' > "$TMP/operator.asc"

echo "== --dry-run runs clean (exit 0) =="
if OUT="$(run_dry)"; then ok "dry-run exit 0"; else bad "dry-run nonzero exit"; OUT=""; fi

echo "== Step 1: tailscale serve (NOT funnel) =="
has   "uses tailscale serve"                 "tailscale serve"
hasnt "never runs tailscale funnel"          "tailscale funnel"
has   "serves /api/v1/inbox"                 "/api/v1/inbox"
has   "serves /.well-known/skfed/directory"  "/.well-known/skfed/directory"

echo "== Step 2: consent-mode systemd drop-ins =="
has "writes SKCOMMS_CONSENT_MODE=tailnet"    "SKCOMMS_CONSENT_MODE=tailnet"
has "skcomms-api drop-in path"               "skcomms-api.service.d"
has "agent daemon drop-in path"              "skchat-daemon@${AGENT}.service.d"

echo "== Step 3: realms.yml + operator pin =="
has "realms.yml path"                        "/realms.yml"
has "realm -> tailnet directory url"         "${REALM}: https://${HOST}"
has "operator pin path"                      "skfed/operators/${REALM}.asc"

echo "== Step 4: seed mutual known-contacts =="
has "seeds known contact alice"              "alice@op.realmA"
has "seeds known contact bob"                "bob@op.realmB"

echo "== Honesty: out-of-band steps flagged =="
has "flags tailscale ACL admin step"         "ACL"
has "marks itself dry-run"                   "DRY-RUN"

echo "== dry-run mutates NOTHING on disk =="
[ -e "$SKHOME/realms.yml" ] && bad "dry-run wrote realms.yml" || ok "no realms.yml written"
[ -e "$SKHOME/skfed/operators/${REALM}.asc" ] && bad "dry-run wrote operator pin" || ok "no operator pin written"
[ -e "$SDDIR" ] && bad "dry-run created systemd dir" || ok "no systemd dir created"

echo "== arg validation =="
if SKCOMMS_HOME="$SKHOME" "$SCRIPT" --agent "$AGENT" --dry-run >/dev/null 2>&1; then
  bad "missing --realm/--tailnet-host should fail"
else
  ok "missing required args exits nonzero"
fi
if "$SCRIPT" --help >/dev/null 2>&1; then ok "--help exits 0"; else bad "--help should exit 0"; fi

echo
if [ "$fail" = 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi
