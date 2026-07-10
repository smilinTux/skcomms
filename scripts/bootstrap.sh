#!/usr/bin/env bash
#
# bootstrap.sh: stand up SKComms on a cold machine, idempotently.
#
# Creates a venv, installs skcomms (from constraints.txt if the lockfile is
# present, plain otherwise), scaffolds the realm message tree, installs and
# enables the systemd user units (API + housekeeping timer), and prints the
# Tailscale Funnel mount commands. Re-running is safe: every step is a no-op or
# an in-place update if it has already run.
#
# Usage:
#   scripts/bootstrap.sh                 # full standup
#   SKCOMMS_VENV=~/.skenv scripts/bootstrap.sh
#   scripts/bootstrap.sh --no-service    # env + install + init only (no units)
#
# Secrets: NONE are written by this script. The units read an optional
# EnvironmentFile at ~/.config/skcomms/skcomms.env holding per-host overrides and
# secret PATHS (never secret values). Signing keys come from the agent's CapAuth
# profile, not from here. See SOP.md section 10.

set -euo pipefail

# --------------------------------------------------------------------------
# Config (override via env)
# --------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKCOMMS_VENV="${SKCOMMS_VENV:-$HOME/.skenv}"
API_HOST="${SKCOMMS_API_HOST:-127.0.0.1}"
API_PORT="${SKCOMMS_API_PORT:-9384}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
UNIT_SRC="$REPO_ROOT/contrib/systemd"
UNIT_DST="$HOME/.config/systemd/user"
ENV_DIR="$HOME/.config/skcomms"

INSTALL_UNITS=1
for arg in "$@"; do
    case "$arg" in
        --no-service) INSTALL_UNITS=0 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '  \033[1;36m==>\033[0m %s\n' "$*"; }

# --------------------------------------------------------------------------
# 1. Virtualenv (idempotent: only create if missing)
# --------------------------------------------------------------------------
if [ ! -x "$SKCOMMS_VENV/bin/python" ]; then
    log "Creating venv at $SKCOMMS_VENV"
    "$PYTHON_BIN" -m venv "$SKCOMMS_VENV"
else
    log "Venv already present at $SKCOMMS_VENV"
fi
"$SKCOMMS_VENV/bin/pip" install --quiet --upgrade pip

# --------------------------------------------------------------------------
# 2. Install skcomms (constraints lockfile if present, plain fallback)
# --------------------------------------------------------------------------
# The api + cli + crypto extras cover the serve command, the `skcomms` CLI, and
# PGP-signed envelopes. Another worker may ship constraints.txt (a pinned
# lockfile); use it when present, otherwise plain resolution.
CONSTRAINTS="$REPO_ROOT/constraints.txt"
if [ -f "$CONSTRAINTS" ]; then
    log "Installing skcomms with constraints from $CONSTRAINTS"
    "$SKCOMMS_VENV/bin/pip" install -c "$CONSTRAINTS" -e "$REPO_ROOT[api,cli,crypto]"
else
    log "constraints.txt not found; installing skcomms without pins"
    "$SKCOMMS_VENV/bin/pip" install -e "$REPO_ROOT[api,cli,crypto]"
fi

# --------------------------------------------------------------------------
# 3. Scaffold the realm message tree (idempotent by design)
# --------------------------------------------------------------------------
log "Initializing skcomms realm tree (skcomms init)"
"$SKCOMMS_VENV/bin/skcomms" init

# --------------------------------------------------------------------------
# 4. Identity gate: restore BEFORE first service start (coord 7d5344f2)
# --------------------------------------------------------------------------
# A cold machine must have its CapAuth private key and trust state RESTORED
# from backup before the daemon ever starts. Regenerating the key instead
# TOFU-conflicts on every remote peer and bricks federation fleet-wide.
# Restore with: skcomms identity restore <archive>   (see SOP.md section 11)
# Set SKCOMMS_ALLOW_NO_IDENTITY=1 only for keyless dev/test standups.
if ! "$SKCOMMS_VENV/bin/skcomms" identity check --strict; then
    if [ "${SKCOMMS_ALLOW_NO_IDENTITY:-0}" = "1" ]; then
        log "WARNING: no CapAuth private key; continuing because SKCOMMS_ALLOW_NO_IDENTITY=1"
    else
        echo "" >&2
        echo "  FATAL: no CapAuth private key found. Restore the identity backup" >&2
        echo "  BEFORE starting services:" >&2
        echo "      $SKCOMMS_VENV/bin/skcomms identity restore <archive>" >&2
        echo "  (SOP.md section 11). Set SKCOMMS_ALLOW_NO_IDENTITY=1 to override" >&2
        echo "  for a keyless dev standup." >&2
        exit 1
    fi
fi

# --------------------------------------------------------------------------
# 5. Systemd user units (install + enable)
# --------------------------------------------------------------------------
if [ "$INSTALL_UNITS" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        log "Installing systemd user units into $UNIT_DST"
        mkdir -p "$UNIT_DST" "$ENV_DIR"
        install -m 0644 "$UNIT_SRC/skcomms-api.service"       "$UNIT_DST/"
        install -m 0644 "$UNIT_SRC/skcomms-housekeep.service" "$UNIT_DST/"
        install -m 0644 "$UNIT_SRC/skcomms-housekeep.timer"   "$UNIT_DST/"

        # Optional per-host override file. Created empty (0600) if absent so the
        # operator can drop in PATHS to secrets; never populated with values here.
        if [ ! -f "$ENV_DIR/skcomms.env" ]; then
            umask 077
            cat > "$ENV_DIR/skcomms.env" <<EOF
# SKComms per-host overrides. PATHS only, never secret values.
# Signing keys resolve from the agent's CapAuth profile, not from this file.
SKCOMMS_API_HOST=$API_HOST
SKCOMMS_API_PORT=$API_PORT
EOF
            log "Wrote default $ENV_DIR/skcomms.env (edit for per-host paths)"
        fi

        systemctl --user daemon-reload
        systemctl --user enable --now skcomms-api.service
        systemctl --user enable --now skcomms-housekeep.timer
        log "Units enabled. Check: systemctl --user status skcomms-api.service"
    else
        log "systemctl not available; skipping unit install (use --no-service to silence)"
        INSTALL_UNITS=0
    fi
fi

# --------------------------------------------------------------------------
# 6. Tailscale Funnel mounts (documented, not executed)
# --------------------------------------------------------------------------
# The loopback API (127.0.0.1:$API_PORT) is exposed to the internet ONLY via a
# Tailscale Funnel :443 path-route. Every request self-authenticates at the
# envelope layer. Run these once, on the node that should be internet-reachable:
cat <<EOF

  ------------------------------------------------------------------
  Tailscale Funnel mounts (run manually on the public node):

    tailscale funnel --bg --set-path /api/v1/inbox            http://127.0.0.1:$API_PORT/api/v1/inbox
    tailscale funnel --bg --set-path /api/v1/prekey           http://127.0.0.1:$API_PORT/api/v1/prekey
    tailscale funnel --bg --set-path /.well-known/skfed/directory http://127.0.0.1:$API_PORT/.well-known/skfed/directory
    tailscale funnel --bg --set-path /api/v1/skfed/announce   http://127.0.0.1:$API_PORT/api/v1/skfed/announce

  Verify locally first:
    curl -fsS http://$API_HOST:$API_PORT/health && echo ' OK'
  ------------------------------------------------------------------

EOF

log "Bootstrap complete."
