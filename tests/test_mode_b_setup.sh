#!/usr/bin/env bash
# Smoke + idempotency test for scripts/mode-b-setup.sh — the Mode-B (tailnet-only)
# realm stand-up installer.
#
# Coverage:
#   A. --dry-run (and DEFAULT) PLAN path is hermetic: every step is planned AND
#      nothing is mutated on disk. No tailscale / systemd / skcomms needed.
#   B. Production hardening: preflight prerequisite checks, the post-apply
#      verification block, and the --apply confirmation gate are all present.
#   C. OFFLINE apply smoke (rule-5 safe): tailscale / systemctl / curl are SHIMMED
#      to no-ops on PATH so NO live infra is touched, then we assert --apply --yes
#      writes the drop-ins + realms.yml + operator pin AND that a second run
#      converges (idempotent: "already converged").
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

# A fake operator key so the pin step has a real source path to reference.
printf -- '-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----\n' > "$TMP/operator.asc"

run_dry() {
  SKCOMMS_HOME="$SKHOME" SYSTEMD_USER_DIR="$SDDIR" \
    "$SCRIPT" --realm "$REALM" --agent "$AGENT" --tailnet-host "$HOST" \
              --known "alice@op.realmA" --known "bob@op.realmB" \
              --operator-key "$TMP/operator.asc" --dry-run 2>&1
}
run_default() { # NO --dry-run / --apply flag — must default to dry-run (safe)
  SKCOMMS_HOME="$SKHOME" SYSTEMD_USER_DIR="$SDDIR" \
    "$SCRIPT" --realm "$REALM" --agent "$AGENT" --tailnet-host "$HOST" \
              --operator-key "$TMP/operator.asc" 2>&1
}

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

echo "== Preflight: prerequisite checks present =="
has "preflight section"                      "Preflight"
has "checks tailscale prerequisite"          "tailscale"
has "checks skcomms-api reachability"        "skcomms-api"
has "checks operator key present"            "operator key"

echo "== Post-apply verification block present =="
has "post-apply verification section"        "post-apply verification"
has "curls the tailnet directory"            "curl"
has "verifies consent env via systemctl show" "show -p Environment"
has "confirms consent=tailnet env"           "SKCOMMS_CONSENT_MODE=tailnet"

echo "== Honesty: out-of-band steps flagged =="
has "flags tailscale ACL admin step"         "ACL"
has "marks itself dry-run"                    "DRY-RUN"

echo "== dry-run mutates NOTHING on disk =="
[ -e "$SKHOME/realms.yml" ] && bad "dry-run wrote realms.yml" || ok "no realms.yml written"
[ -e "$SKHOME/skfed/operators/${REALM}.asc" ] && bad "dry-run wrote operator pin" || ok "no operator pin written"
[ -e "$SDDIR" ] && bad "dry-run created systemd dir" || ok "no systemd dir created"

echo "== DEFAULT (no flag) is dry-run / safe =="
if OUT="$(run_default)"; then ok "default-run exit 0"; else bad "default-run nonzero"; OUT=""; fi
has "default run announces DRY-RUN"          "DRY-RUN"
[ -e "$SKHOME/realms.yml" ] && bad "default run wrote realms.yml" || ok "default run made no changes"

echo "== --apply is GATED behind confirmation =="
# Pipe a non-confirming answer; must abort, exit nonzero, mutate nothing.
GATE_SKHOME="$TMP/gate-home"; GATE_SDDIR="$TMP/gate-sd"
if OUT="$(printf 'no\n' | SKCOMMS_HOME="$GATE_SKHOME" SYSTEMD_USER_DIR="$GATE_SDDIR" \
      "$SCRIPT" --realm "$REALM" --agent "$AGENT" --tailnet-host "$HOST" \
                --operator-key "$TMP/operator.asc" --apply 2>&1)"; then
  bad "--apply without confirmation should exit nonzero"
else
  ok "--apply without confirmation exits nonzero"
fi
has "gate prints abort notice"               "Abort"
has "gate mentions confirmation"             "apply"
[ -e "$GATE_SKHOME/realms.yml" ] && bad "gated apply wrote realms.yml" || ok "gated apply made no changes"
[ -e "$GATE_SDDIR" ] && bad "gated apply created systemd dir" || ok "gated apply touched no systemd dir"

echo "== OFFLINE --apply smoke (shimmed infra, rule-5 safe) =="
# Shim tailscale / systemctl / curl to no-ops so NO live infra is touched.
SHIMDIR="$TMP/shimbin"; mkdir -p "$SHIMDIR"
for tool in tailscale systemctl curl; do
  cat > "$SHIMDIR/$tool" <<SHIM
#!/usr/bin/env bash
# no-op shim for $tool — offline test, touches nothing real
exit 0
SHIM
  chmod +x "$SHIMDIR/$tool"
done
APPLY_SKHOME="$TMP/apply-home"; APPLY_SDDIR="$TMP/apply-sd"
run_apply() {
  PATH="$SHIMDIR:$PATH" SKCOMMS_HOME="$APPLY_SKHOME" SYSTEMD_USER_DIR="$APPLY_SDDIR" \
    "$SCRIPT" --realm "$REALM" --agent "$AGENT" --tailnet-host "$HOST" \
              --operator-key "$TMP/operator.asc" --apply --yes 2>&1
}
if OUT="$(run_apply)"; then ok "offline apply exit 0"; else bad "offline apply nonzero exit"; OUT=""; fi
[ -f "$APPLY_SDDIR/skcomms-api.service.d/10-consent-mode.conf" ] \
  && ok "apply wrote skcomms-api consent drop-in" || bad "no skcomms-api drop-in written"
[ -f "$APPLY_SDDIR/skchat-daemon@${AGENT}.service.d/10-consent-mode.conf" ] \
  && ok "apply wrote agent daemon consent drop-in" || bad "no agent daemon drop-in written"
if grep -q "SKCOMMS_CONSENT_MODE=tailnet" "$APPLY_SDDIR/skcomms-api.service.d/10-consent-mode.conf" 2>/dev/null; then
  ok "drop-in sets consent=tailnet"; else bad "drop-in missing consent=tailnet"; fi
if grep -qxF "${REALM}: https://${HOST}" "$APPLY_SKHOME/realms.yml" 2>/dev/null; then
  ok "apply wrote realms.yml realm->url"; else bad "realms.yml realm line missing"; fi
[ -f "$APPLY_SKHOME/skfed/operators/${REALM}.asc" ] \
  && ok "apply pinned operator key" || bad "operator key not pinned"

echo "== second apply CONVERGES (idempotent) =="
if OUT="$(run_apply)"; then ok "second apply exit 0"; else bad "second apply nonzero exit"; OUT=""; fi
has "drop-ins already converged"             "already converged"

echo "== arg validation =="
if SKCOMMS_HOME="$SKHOME" "$SCRIPT" --agent "$AGENT" --dry-run >/dev/null 2>&1; then
  bad "missing --realm/--tailnet-host should fail"
else
  ok "missing required args exits nonzero"
fi
if "$SCRIPT" --help >/dev/null 2>&1; then ok "--help exits 0"; else bad "--help should exit 0"; fi

echo
if [ "$fail" = 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi
