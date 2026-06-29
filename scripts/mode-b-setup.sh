#!/usr/bin/env bash
# mode-b-setup.sh — stand up a Mode-B (tailnet-only, NO funnel) skcomms realm on
# this node. Production-grade, IDEMPOTENT installer distilled from
# docs/mode-b-tailnet-deploy.md.
#
# WHAT IT DOES, all idempotent + additive + opt-in:
#   PREFLIGHT. Verify prerequisites (tailscale present + up, skcomms-api reachable,
#      operator key present). Read-only; reports PASS/WARN before any change.
#   1. `tailscale serve` (NOT funnel) the inbox + skfed directory → tailnet only.
#   2. Write SKCOMMS_CONSENT_MODE=tailnet into the agent's skcomms-api + daemon
#      systemd drop-ins (network membership becomes the consent gate).
#   3. Write/merge realms.yml so <realm> resolves to the tailnet node, and pin the
#      realm operator's public key so its signed directory verifies.
#   4. Seed the realm's mutual known-contacts (so accepted peers DELIVER even if
#      consent ever tightens past tailnet mode).
#   5. POST-APPLY VERIFY. Curl the (tailnet) directory + confirm the live
#      SKCOMMS_CONSENT_MODE=tailnet env on both units.
#
# SAFETY MODEL:
#   * DEFAULT is --dry-run: prints the exact PLAN and changes NOTHING (hermetic:
#     needs neither tailscale nor systemd nor the skcomms venv).
#   * --apply makes real changes and is GATED behind an interactive confirmation
#     (type "apply"); pass --yes/-y to confirm non-interactively (automation).
#   * Every step is guarded idempotently — re-running converges; matching state is
#     left alone ("already converged").
#   * Steps that need the tailscale CLI, an authed node, or admin-console ACLs are
#     OUT-OF-BAND and are flagged honestly — this script cannot do them for you.
#
# Companion doc: docs/mode-b-tailnet-deploy.md   (coord 5967eb6f)
#
# Usage:
#   # 1) Preview the plan (default, safe, changes nothing):
#   scripts/mode-b-setup.sh --realm myrealm --tailnet-host node1.tailXYZ.ts.net
#   # 2) Execute for real (interactive confirm, or add --yes for automation):
#   scripts/mode-b-setup.sh --realm myrealm --tailnet-host node1.tailXYZ.ts.net \
#       --agent lumina --operator-key /path/public.asc --apply
#
#   Flags: [--agent lumina] [--known alice@op.realmA] [--known bob@op.realmB]
#          [--operator-key /path/public.asc] [--local-port 9384]
#          [--daemon-unit skchat-daemon@lumina] [--apply] [--yes|-y] [--dry-run]
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config / args
# ---------------------------------------------------------------------------
HERE="$(cd "$(dirname "$0")" && pwd)"
TMPL_DIR="$HERE/templates"

SKCOMMS_HOME_DIR="${SKCOMMS_HOME:-$HOME/.skcapstone/skcomms}"   # mirrors home.skcomms_home()
SYSTEMD_USER_DIR="${SYSTEMD_USER_DIR:-$HOME/.config/systemd/user}"
PYBIN="${SKCOMMS_PY:-$HOME/.skenv/bin/python}"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3 || true)"

REALM=""
AGENT="${SKAGENT:-lumina}"
TAILNET_HOST=""
LOCAL_PORT="9384"
OPERATOR_KEY=""
DAEMON_UNIT=""
DRY_RUN=1            # SAFE DEFAULT: dry-run. --apply flips this to 0 (real changes).
ASSUME_YES=0        # --yes/-y bypasses the interactive apply confirmation.
KNOWN=()

usage() { sed -n '2,41p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --realm)        REALM="${2:-}"; shift ;;
    --agent)        AGENT="${2:-}"; shift ;;
    --tailnet-host) TAILNET_HOST="${2:-}"; shift ;;
    --local-port)   LOCAL_PORT="${2:-}"; shift ;;
    --operator-key) OPERATOR_KEY="${2:-}"; shift ;;
    --daemon-unit)  DAEMON_UNIT="${2:-}"; shift ;;
    --known)        KNOWN+=("${2:-}"); shift ;;
    --apply)        DRY_RUN=0 ;;
    --dry-run)      DRY_RUN=1 ;;
    --yes|-y)       ASSUME_YES=1 ;;
    -h|--help)      usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
  shift
done

# Required args.
missing=""
[ -n "$REALM" ]        || missing="$missing --realm"
[ -n "$TAILNET_HOST" ] || missing="$missing --tailnet-host"
[ -n "$AGENT" ]        || missing="$missing --agent"
if [ -n "$missing" ]; then
  echo "ERROR: missing required arg(s):$missing" >&2
  usage 2
fi

[ -n "$DAEMON_UNIT" ] || DAEMON_UNIT="skchat-daemon@${AGENT}"

LOCAL_BASE="http://localhost:${LOCAL_PORT}"
DIRECTORY_URL="https://${TAILNET_HOST}"
REALMS_FILE="$SKCOMMS_HOME_DIR/realms.yml"
OPERATOR_PIN="$SKCOMMS_HOME_DIR/skfed/operators/${REALM}.asc"
API_DROPIN_DIR="$SYSTEMD_USER_DIR/skcomms-api.service.d"
API_DROPIN="$API_DROPIN_DIR/10-consent-mode.conf"
DAEMON_DROPIN_DIR="$SYSTEMD_USER_DIR/${DAEMON_UNIT}.service.d"
DAEMON_DROPIN="$DAEMON_DROPIN_DIR/10-consent-mode.conf"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
section() { printf '\n=== %s ===\n' "$*"; }
plan()    { printf '  PLAN  %s\n' "$*"; }     # what WOULD happen (dry-run + apply preview)
did()     { printf '  done  %s\n' "$*"; }
skip()    { printf '  skip  %s (already converged)\n' "$*"; }
note()    { printf '  NOTE  %s\n' "$*"; }     # honest out-of-band / manual step

# render_tmpl <file> KEY VAL [KEY VAL ...]  -> substituted content on stdout
render_tmpl() {
  local f="$1"; shift
  local c; c="$(cat "$f")"
  while [ $# -gt 0 ]; do
    local k="$1" v="$2"; shift 2
    c="${c//$k/$v}"
  done
  printf '%s\n' "$c"
}

# write_if_changed <path> <content>  -> writes only when missing/differing (idempotent)
write_if_changed() {
  local path="$1" content="$2"
  if [ -f "$path" ] && [ "$(cat "$path")" = "$content" ]; then
    skip "$path"
    return 0
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s' "$content" > "$path"
  did "wrote $path"
}

# http_code <url>  -> prints the HTTP status (or 000 if unreachable); never fails.
http_code() {
  command -v curl >/dev/null 2>&1 || { printf '000'; return 0; }
  curl -s -o /dev/null -m 4 -w '%{http_code}' "$1" 2>/dev/null || printf '000'
}

if [ "$DRY_RUN" = 1 ]; then
  printf '\n*** DRY-RUN (default) — printing the plan; NO changes will be made. Re-run with --apply to execute. ***\n'
else
  printf '\n*** APPLY — real, idempotent changes will be made to this node. ***\n'
fi
printf 'realm=%s  agent=%s  tailnet-host=%s  local=%s\n' \
  "$REALM" "$AGENT" "$TAILNET_HOST" "$LOCAL_BASE"

# ---------------------------------------------------------------------------
# Preflight — verify prerequisites (read-only; runs in BOTH modes)
# ---------------------------------------------------------------------------
section "Preflight: prerequisites"
pf_pass() { printf '  PASS  %s\n' "$*"; }
pf_warn() { printf '  WARN  %s\n' "$*"; }

# tailscale present + up
if command -v tailscale >/dev/null 2>&1; then
  if tailscale status >/dev/null 2>&1; then
    pf_pass "tailscale present and up"
  else
    pf_warn "tailscale present but not 'up' — run: tailscale up   (serve step needs an authed node)"
  fi
else
  pf_warn "tailscale not on PATH — Step 1 (serve) will be skipped; run the PLAN lines by hand"
fi

# skcomms-api reachable (any HTTP response = up; 000 = could not connect)
PF_API_CODE="$(http_code "$LOCAL_BASE/.well-known/skfed/directory")"
if [ "$PF_API_CODE" = "000" ]; then
  pf_warn "skcomms-api NOT reachable at $LOCAL_BASE — start it before serving / verifying"
else
  pf_pass "skcomms-api reachable at $LOCAL_BASE (HTTP $PF_API_CODE)"
fi

# operator key present (source given, or already pinned)
if [ -n "$OPERATOR_KEY" ] && [ -f "$OPERATOR_KEY" ]; then
  pf_pass "operator key source present: $OPERATOR_KEY"
elif [ -f "$OPERATOR_PIN" ]; then
  pf_pass "operator key already pinned: $OPERATOR_PIN"
else
  pf_warn "operator key NOT present — skfed directory verification FAILS CLOSED until pinned"
fi

# ---------------------------------------------------------------------------
# Confirmation gate — APPLY makes real changes; require explicit consent.
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" = 0 ] && [ "$ASSUME_YES" = 0 ]; then
  printf '\n*** APPLY MODE — this writes systemd drop-ins + realms.yml + serve state\n'
  printf '    and restarts skcomms-api + %s. ***\n' "${DAEMON_UNIT}.service"
  printf 'Type "apply" to proceed (anything else aborts): '
  IFS= read -r _confirm || _confirm=""
  if [ "$_confirm" != "apply" ]; then
    printf '\nAborted — confirmation not given; NO changes made. (use --apply --yes for non-interactive.)\n'
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Step 1 — tailscale serve (tailnet-only, NOT funnel)
# ---------------------------------------------------------------------------
section "Step 1/5: tailscale serve (tailnet-only, NOT funnel)"
SERVE_INBOX="tailscale serve --bg --https=443 --set-path=/api/v1/inbox $LOCAL_BASE/api/v1/inbox"
SERVE_DIR="tailscale serve --bg --https=443 --set-path=/.well-known/skfed/directory $LOCAL_BASE/.well-known/skfed/directory"
plan "$SERVE_INBOX"
plan "$SERVE_DIR"
note "out-of-band: tailscale CLI must be installed and this node 'tailscale up' + authed."
note "out-of-band: set a default-deny tailnet ACL in the admin console; allow ONLY this realm's nodes."
note "Mode-B isolation: this agent must NOT be listed in any public (Mode-A) directory."

serve_has_path() { # idempotency probe: is this path already served?
  command -v tailscale >/dev/null 2>&1 || return 1
  tailscale serve status 2>/dev/null | grep -q -- "$1"
}

if [ "$DRY_RUN" = 0 ]; then
  if ! command -v tailscale >/dev/null 2>&1; then
    note "tailscale not found on PATH — skipping serve; run the two PLAN lines above by hand."
  else
    if serve_has_path "/api/v1/inbox"; then skip "serve /api/v1/inbox"; else eval "$SERVE_INBOX" && did "served /api/v1/inbox"; fi
    if serve_has_path "/.well-known/skfed/directory"; then skip "serve /.well-known/skfed/directory"; else eval "$SERVE_DIR" && did "served /.well-known/skfed/directory"; fi
  fi
fi

# ---------------------------------------------------------------------------
# Step 2 — consent-mode systemd drop-ins (SKCOMMS_CONSENT_MODE=tailnet)
# ---------------------------------------------------------------------------
section "Step 2/5: consent-mode systemd drop-ins (SKCOMMS_CONSENT_MODE=tailnet)"
DROPIN_CONTENT="$(render_tmpl "$TMPL_DIR/consent-mode.conf.tmpl" \
  __REALM__ "$REALM" __AGENT__ "$AGENT" __CONSENT_MODE__ "tailnet")"
plan "write $API_DROPIN  (Environment=SKCOMMS_CONSENT_MODE=tailnet)"
plan "write $DAEMON_DROPIN  (Environment=SKCOMMS_CONSENT_MODE=tailnet)"
plan "systemctl --user daemon-reload && restart skcomms-api.service ${DAEMON_UNIT}.service"
note "consent stays OFF until this env is present (additive + opt-in)."

if [ "$DRY_RUN" = 0 ]; then
  write_if_changed "$API_DROPIN" "$DROPIN_CONTENT"
  write_if_changed "$DAEMON_DROPIN" "$DROPIN_CONTENT"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload 2>/dev/null && did "daemon-reload"
    systemctl --user restart skcomms-api.service 2>/dev/null && did "restart skcomms-api.service" \
      || note "could not restart skcomms-api.service — restart it manually to pick up the env."
    systemctl --user restart "${DAEMON_UNIT}.service" 2>/dev/null && did "restart ${DAEMON_UNIT}.service" \
      || note "could not restart ${DAEMON_UNIT}.service — restart it manually to pick up the env."
  else
    note "systemctl not found — reload + restart the two units by hand."
  fi
fi

# ---------------------------------------------------------------------------
# Step 3 — realms.yml + operator-key pin
# ---------------------------------------------------------------------------
section "Step 3/5: realms.yml + operator-key pin"
plan "set in $REALMS_FILE :  ${REALM}: ${DIRECTORY_URL}"
plan "pin operator key -> $OPERATOR_PIN"

if [ -n "$OPERATOR_KEY" ]; then
  plan "source operator key: $OPERATOR_KEY"
else
  note "no --operator-key given: copy the realm operator's public.asc to $OPERATOR_PIN out-of-band."
  note "skfed verification FAILS CLOSED until that pin exists — an unpinned realm is never trusted."
fi

if [ "$DRY_RUN" = 0 ]; then
  # realms.yml: merge the single realm->url key without disturbing other realms.
  mkdir -p "$SKCOMMS_HOME_DIR"
  if [ -f "$REALMS_FILE" ] && grep -qE "^${REALM}:[[:space:]]" "$REALMS_FILE"; then
    if grep -qxF "${REALM}: ${DIRECTORY_URL}" "$REALMS_FILE"; then
      skip "realms.yml ${REALM}"
    else
      tmp="$(mktemp)"; grep -vE "^${REALM}:[[:space:]]" "$REALMS_FILE" > "$tmp"
      printf '%s: %s\n' "$REALM" "$DIRECTORY_URL" >> "$tmp"
      mv "$tmp" "$REALMS_FILE"; did "updated realms.yml ${REALM}"
    fi
  elif [ -f "$REALMS_FILE" ]; then
    printf '%s: %s\n' "$REALM" "$DIRECTORY_URL" >> "$REALMS_FILE"; did "appended realms.yml ${REALM}"
  else
    render_tmpl "$TMPL_DIR/realms.yml.tmpl" __REALM__ "$REALM" __DIRECTORY_URL__ "$DIRECTORY_URL" > "$REALMS_FILE"
    did "created realms.yml"
  fi

  # operator pin (copy if provided + differing).
  if [ -n "$OPERATOR_KEY" ]; then
    if [ ! -f "$OPERATOR_KEY" ]; then
      note "--operator-key $OPERATOR_KEY not found — pin SKIPPED (verification stays fail-closed)."
    elif [ -f "$OPERATOR_PIN" ] && cmp -s "$OPERATOR_KEY" "$OPERATOR_PIN"; then
      skip "operator pin ${REALM}.asc"
    else
      mkdir -p "$(dirname "$OPERATOR_PIN")"; cp "$OPERATOR_KEY" "$OPERATOR_PIN"; did "pinned operator key -> $OPERATOR_PIN"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Step 4 — seed mutual known-contacts
# ---------------------------------------------------------------------------
section "Step 4/5: seed mutual known-contacts (agent=${AGENT})"
if [ "${#KNOWN[@]}" -eq 0 ]; then
  note "no --known contacts given — nothing to seed (tailnet mode delivers all non-blocked anyway)."
fi
for c in "${KNOWN[@]:-}"; do
  [ -n "$c" ] || continue
  plan "mark known contact: $c  (skcomms.consent.ContactStore('${AGENT}').accept)"
done

if [ "$DRY_RUN" = 0 ] && [ "${#KNOWN[@]}" -gt 0 ]; then
  if [ -z "$PYBIN" ]; then
    note "no python found — seed contacts by hand: skcomms consent accept <fqid> (per contact)."
  else
    for c in "${KNOWN[@]}"; do
      [ -n "$c" ] || continue
      if SKCOMMS_HOME="$SKCOMMS_HOME_DIR" "$PYBIN" - "$AGENT" "$c" <<'PY'
import sys
from skcomms.consent import ContactStore
agent, fqid = sys.argv[1], sys.argv[2]
s = ContactStore(agent)
if s.is_known(fqid):
    print("known")          # idempotent
else:
    s.accept(fqid)
    print("accepted")
PY
      then did "seeded known contact $c"; else note "failed to seed $c — run: skcomms consent accept $c"; fi
    done
  fi
fi

# ---------------------------------------------------------------------------
# Step 5 — post-apply verification (curl the directory + confirm consent env)
# ---------------------------------------------------------------------------
section "Step 5/5: post-apply verification"
VERIFY_DIR_TAILNET="curl -fsS ${DIRECTORY_URL}/.well-known/skfed/directory"
VERIFY_ENV_API="systemctl --user show -p Environment skcomms-api.service"
VERIFY_ENV_DAEMON="systemctl --user show -p Environment ${DAEMON_UNIT}.service"
plan "tailnet directory reachable: $VERIFY_DIR_TAILNET   (tailnet members only)"
plan "local directory reachable:   curl -s $LOCAL_BASE/.well-known/skfed/directory"
plan "confirm consent env: $VERIFY_ENV_API | grep SKCOMMS_CONSENT_MODE=tailnet"
plan "confirm consent env: $VERIFY_ENV_DAEMON | grep SKCOMMS_CONSENT_MODE=tailnet"
note "the tailnet directory curl only succeeds FROM a tailnet member (expected to fail off-net)."

if [ "$DRY_RUN" = 0 ]; then
  # Local directory reachability (works without tailscale; proves the API serves it).
  LOCAL_CODE="$(http_code "$LOCAL_BASE/.well-known/skfed/directory")"
  case "$LOCAL_CODE" in
    000) note "local directory probe: skcomms-api not reachable at $LOCAL_BASE" ;;
    200) did "local directory serves HTTP 200" ;;
    404) note "local directory HTTP 404 — API up but no directory PUBLISHED yet (publish_self_to_realm_directory)" ;;
    *)   note "local directory probe HTTP $LOCAL_CODE (API up)" ;;
  esac
  # Tailnet directory (best-effort; off-net this is expected to fail — that's the isolation working).
  TAILNET_CODE="$(http_code "$DIRECTORY_URL/.well-known/skfed/directory")"
  if [ "$TAILNET_CODE" = "200" ]; then
    did "tailnet directory reachable at $DIRECTORY_URL (HTTP 200)"
  else
    note "tailnet directory not reachable from here (HTTP $TAILNET_CODE) — expected unless this host is a tailnet member"
  fi
  # Confirm the live consent env on both units.
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user show -p Environment skcomms-api.service 2>/dev/null | grep -q "SKCOMMS_CONSENT_MODE=tailnet"; then
      did "skcomms-api: SKCOMMS_CONSENT_MODE=tailnet confirmed"
    else
      note "skcomms-api: consent env NOT visible yet — ensure the restart picked up the drop-in"
    fi
    if systemctl --user show -p Environment "${DAEMON_UNIT}.service" 2>/dev/null | grep -q "SKCOMMS_CONSENT_MODE=tailnet"; then
      did "${DAEMON_UNIT}: SKCOMMS_CONSENT_MODE=tailnet confirmed"
    else
      note "${DAEMON_UNIT}: consent env NOT visible yet — ensure the restart picked up the drop-in"
    fi
  else
    note "systemctl not found — verify by hand: $VERIFY_ENV_API"
  fi
fi

# ---------------------------------------------------------------------------
section "Summary"
if [ "$DRY_RUN" = 1 ]; then
  echo "  DRY-RUN complete — no changes made. Re-run with --apply to execute."
else
  echo "  Apply complete. Verify: tailscale serve status ; $VERIFY_ENV_API"
fi
note "Reminder (out-of-band, admin console): default-deny tailnet ACL + allow only this realm's nodes."
