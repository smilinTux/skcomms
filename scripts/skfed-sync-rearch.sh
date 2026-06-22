#!/usr/bin/env bash
# skfed-sync-rearch.sh — [skfed][P5] state-sync re-architecture.
#
# Narrows Syncthing off the monolithic ~/.skcapstone mirror onto:
#   - a tiny SHARED folder (_shared: cluster.json, peers/, registry/, fed-trust)
#   - per-agent home folders (skagent-<a>) shared ONLY with that agent's instances
#   - memory STOPS syncing (hub service: skmem-pg on .158)
#
# SAFETY MODEL:
#   * DRY-RUN BY DEFAULT. It prints exactly what it WOULD change and touches
#     nothing. Real changes require --apply.
#   * IDEMPOTENT. Re-running converges; folders/.stignore that already match the
#     target are left alone.
#   * It NEVER deletes the monolith folder, NEVER moves files, NEVER deletes
#     sync-conflict files, NEVER restarts services. Those are flagged as MANUAL
#     SUPERVISED steps in the output (see docs/state-sync-rearch-plan.md).
#   * Uses the Syncthing REST API (apikey read from config.xml) — never
#     hand-edits config.xml (avoids the shutdown-overwrite race).
#
# Companion design doc: docs/state-sync-rearch-plan.md
#
# Usage:
#   scripts/skfed-sync-rearch.sh                 # dry-run (default): print plan
#   scripts/skfed-sync-rearch.sh --apply         # create folders + .stignore + share
#   scripts/skfed-sync-rearch.sh --apply --pause-monolith   # also pause skcapstone-sync
#   scripts/skfed-sync-rearch.sh --node .41      # treat this run as the .41 node
#   scripts/skfed-sync-rearch.sh --help
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config (overridable via env)
# ---------------------------------------------------------------------------
SKROOT="${SKROOT:-$HOME/.skcapstone}"
ST_CONFIG="${ST_CONFIG:-$HOME/.local/state/syncthing/config.xml}"
[ -f "$ST_CONFIG" ] || ST_CONFIG="$HOME/.config/syncthing/config.xml"
ST_API="${ST_API:-http://127.0.0.1:8384/rest}"
MONOLITH_FOLDER_ID="skcapstone-sync"

# Syncthing device IDs (authoritative; names can be stale). Override via env.
DEV_158="${DEV_158:-CIHSBZ4-PS46AUX-VPE37BR-YGQDTUK-K3GESSD-4PVYZ63-M33WRKV-6V6P5AC}"  # noroc2027 / .158 (hub)
DEV_41="${DEV_41:-4U3J4V6-3E2LLJP-3VQR4NY-JFUL4Z4-BEIAG7X-E2Y2XET-2TGEHE6-5QAD3A7}"    # cbrd21-laptop / .41
DEV_100="${DEV_100:-S5G63MA-AUPSQGS-AKGFGRQ-2NDOIWH-IBG7CD7-LRL2R7R-MDZ3KIL-UBRWUAN}"  # ollama-gpu / .100 (NO minds)

APPLY=0
PAUSE_MONOLITH=0
NODE_HINT=""

# ---------------------------------------------------------------------------
# Agent -> instance-node mapping. Each per-agent folder is shared ONLY with the
# devices that run THAT agent. Today every agent is single-instance, so most
# lists are empty (single-node folder, no peer). Format: "agent:dev1,dev2".
# Add a device ID when a 2nd instance of an agent exists.
# ---------------------------------------------------------------------------
AGENT_NODES=(
  "lumina:"      # lumina home on .158 only (local folder, no peer yet)
  "opus:"        # opus   home on .158 only
  "jarvis:"      # jarvis home on .41 only
)
# Which node each agent's home is authored on (where the folder is CREATED).
AGENT_HOME_NODE=(
  "lumina:.158"
  "opus:.158"
  "jarvis:.41"
)

# ---------------------------------------------------------------------------
# Arg parse
# ---------------------------------------------------------------------------
usage() { sed -n '2,40p' "$0"; exit 0; }
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --pause-monolith) PAUSE_MONOLITH=1 ;;
    --node) NODE_HINT="${2:-}"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
c_bold=$'\033[1m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
[ -t 1 ] || { c_bold=; c_grn=; c_yel=; c_red=; c_dim=; c_rst=; }
say()    { printf '%s\n' "$*"; }
hdr()    { printf '\n%s== %s ==%s\n' "$c_bold" "$*" "$c_rst"; }
would()  { printf '  %sWOULD%s %s\n' "$c_yel" "$c_rst" "$*"; }
didit()  { printf '  %sAPPLIED%s %s\n' "$c_grn" "$c_rst" "$*"; }
skip()   { printf '  %sok%s %s\n' "$c_dim" "$c_rst" "$*"; }
warn()   { printf '  %s!%s %s\n' "$c_red" "$c_rst" "$*"; }
manual() { printf '  %sMANUAL%s %s\n' "$c_red" "$c_rst" "$*"; }
die()    { printf '%sERROR:%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Read apikey + GUI address from config.xml (no hand-editing — read only)
# ---------------------------------------------------------------------------
load_api() {
  [ -f "$ST_CONFIG" ] || die "Syncthing config not found: $ST_CONFIG"
  APIKEY="$(parse_xml_apikey "$ST_CONFIG")"
  [ -n "$APIKEY" ] || die "could not read <apikey> from $ST_CONFIG"
  local gui; gui="$(parse_xml_gui "$ST_CONFIG")"
  [ -n "$gui" ] && ST_API="http://${gui}/rest"
}

# Tiny XML field extractors (python3 if present for robustness, else grep/sed).
parse_xml_apikey() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" <<'PY'
import sys,xml.etree.ElementTree as ET
r=ET.parse(sys.argv[1]).getroot()
g=r.find('gui'); print((g.findtext('apikey') or '').strip() if g is not None else '')
PY
  else
    grep -oE '<apikey>[^<]+</apikey>' "$1" | head -1 | sed -E 's,</?apikey>,,g'
  fi
}
parse_xml_gui() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" <<'PY'
import sys,xml.etree.ElementTree as ET
r=ET.parse(sys.argv[1]).getroot()
g=r.find('gui'); print((g.findtext('address') or '').strip() if g is not None else '')
PY
  else
    grep -oE '<address>[^<]+</address>' "$1" | head -1 | sed -E 's,</?address>,,g'
  fi
}

api() { # api METHOD PATH [json-body]
  local m="$1" p="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -fsS -X "$m" -H "X-API-Key: $APIKEY" -H "Content-Type: application/json" \
      --data "$body" "$ST_API$p"
  else
    curl -fsS -X "$m" -H "X-API-Key: $APIKEY" "$ST_API$p"
  fi
}

folder_exists() { # folder_exists ID  -> 0 if present
  api GET "/config/folders/$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# .stignore content (kept in sync with docs/state-sync-rearch-plan.md §2.3)
# ---------------------------------------------------------------------------
per_agent_stignore() {
cat <<'IGN'
# skfed per-agent .stignore — durable mind only; memory=hub, runtime=local
memory
/index.db
**/*.db-wal
**/*.db-shm
sessions
logs
**/daemon.log
**/*.log
daemon.pid
*.pid
*.tmp
*.temp
*~
heartbeats
metrics/daily
**/skwhisper/state.json
retry_queue.jsonl
**/retry_queue.jsonl
**/*.session
shutdown_state.json
fallbacks.json
mood.json
activity.jsonl
activity.jsonl.lock
audit.jsonl
unhinged.log
archive
**/memory/archive
/venv
venv
__pycache__
*.pyc
*.pyo
.DS_Store
Thumbs.db
.idea/
.vscode/
.stversions/
**/*.sync-conflict-*
IGN
}
shared_stignore() {
cat <<'IGN'
# skfed shared folder .stignore — tiny federation directory only
*.tmp
*.lock
*.pid
**/*.sync-conflict-*
.DS_Store
IGN
}

# Write a .stignore at $1/.stignore from generator $2; idempotent.
ensure_stignore() {
  local dir="$1" gen="$2" target current
  target="$($gen)"
  local f="$dir/.stignore"
  if [ -f "$f" ] && current="$(cat "$f")" && [ "$current" = "$target" ]; then
    skip ".stignore already correct: $f"
    return
  fi
  if [ "$APPLY" = 1 ]; then
    mkdir -p "$dir"
    printf '%s\n' "$target" > "$f"
    didit "wrote .stignore: $f"
  else
    would "write .stignore: $f"
  fi
}

# Build the folder-create JSON body (Syncthing config schema).
folder_body() { # folder_body ID LABEL PATH "dev1 dev2 ..."
  local id="$1" label="$2" path="$3" devs="$4" dev_json="" d
  for d in $devs; do dev_json="$dev_json{\"deviceID\":\"$d\"},"; done
  dev_json="${dev_json%,}"
  printf '{"id":"%s","label":"%s","path":"%s","type":"sendreceive","fsWatcherEnabled":true,"rescanIntervalS":3600,"devices":[%s]}' \
    "$id" "$label" "$path" "$dev_json"
}

# Ensure a folder exists with the given devices (idempotent).
ensure_folder() { # ensure_folder ID LABEL PATH "dev1 dev2 ..."
  local id="$1" label="$2" path="$3" devs="$4"
  if folder_exists "$id"; then
    skip "folder exists: $id ($path)"
    # NOTE: device-list reconciliation on an existing folder is left to the
    # operator (sharing changes are sensitive); we only report.
    return
  fi
  local body; body="$(folder_body "$id" "$label" "$path" "$devs")"
  if [ "$APPLY" = 1 ]; then
    api PUT "/config/folders/$id" "$body" >/dev/null
    didit "created folder $id  path=$path  devices=[${devs:-<none>}]"
  else
    would "create folder $id  path=$path  devices=[${devs:-<none>}]  type=sendreceive"
  fi
}

# Look up helpers over the agent maps.
agent_devs() { local a="$1" e; for e in "${AGENT_NODES[@]}"; do [ "${e%%:*}" = "$a" ] && { echo "${e#*:}" | tr ',' ' '; return; }; done; }
agent_home() { local a="$1" e; for e in "${AGENT_HOME_NODE[@]}"; do [ "${e%%:*}" = "$a" ] && { echo "${e#*:}"; return; }; done; }

# Which node are we on? Resolve from --node, else from myID vs DEV_*.
detect_node() {
  if [ -n "$NODE_HINT" ]; then echo "$NODE_HINT"; return; fi
  local myid=""
  myid="$(api GET /system/status 2>/dev/null | sed -n 's/.*"myID": *"\([^"]*\)".*/\1/p' | head -1)" || true
  case "$myid" in
    "$DEV_158") echo ".158" ;;
    "$DEV_41")  echo ".41" ;;
    "$DEV_100") echo ".100" ;;
    *) echo "?" ;;
  esac
}

# ===========================================================================
# MAIN
# ===========================================================================
main() {
  hdr "skfed-sync-rearch — $([ "$APPLY" = 1 ] && echo "${c_grn}APPLY MODE${c_rst}" || echo "${c_yel}DRY-RUN (default)${c_rst}")"
  say "  Syncthing config : $ST_CONFIG"
  load_api
  say "  REST API         : $ST_API"
  # Reachability check (read-only).
  if ! api GET /system/ping >/dev/null 2>&1; then
    warn "Syncthing REST not reachable at $ST_API — is syncthing running?"
    [ "$APPLY" = 1 ] && die "cannot apply without REST access"
  fi
  local node; node="$(detect_node)"
  say "  This node        : $node"
  [ "$node" = "?" ] && warn "could not match this node to a known device ID; pass --node .158|.41"

  # --- 1. SHARED folder ---------------------------------------------------
  hdr "1. Shared federation folder (skfed-shared)"
  local shared_dir="$SKROOT/_shared"
  manual "move into $shared_dir (supervised, leaves back-compat symlinks): cluster.json, peers/, registry/, federation-trust.json + pinned pubkeys"
  ensure_stignore "$shared_dir" shared_stignore
  # _shared is shared between the two AGENT nodes (.158 <-> .41). NEVER .100.
  ensure_folder "skfed-shared" "skfed:shared" "$shared_dir" "$DEV_158 $DEV_41"

  # --- 2. Per-agent home folders -----------------------------------------
  hdr "2. Per-agent home folders (skagent-<a>) — own instances only"
  local e a home devs id path
  for e in "${AGENT_HOME_NODE[@]}"; do
    a="${e%%:*}"; home="${e#*:}"
    path="$SKROOT/agents/$a"
    id="skagent-$a"
    devs="$(agent_devs "$a")"   # extra instances; empty = single-node
    if [ ! -d "$path" ]; then
      skip "agent home absent on this node (not created here): $path"
      continue
    fi
    # Only create the folder on the agent's home node (where it's authored).
    if [ "$node" != "?" ] && [ "$node" != "$home" ]; then
      skip "$id authored on $home, not on $node — skipping on this node"
      continue
    fi
    say "  ${c_bold}$a${c_rst} (home=$home)"
    ensure_stignore "$path" per_agent_stignore
    ensure_folder "$id" "skagent:$a" "$path" "$devs"
  done

  # --- 3. Monolith handling ----------------------------------------------
  hdr "3. Retire the monolith ($MONOLITH_FOLDER_ID = whole ~/.skcapstone)"
  if folder_exists "$MONOLITH_FOLDER_ID"; then
    if [ "$PAUSE_MONOLITH" = 1 ]; then
      if [ "$APPLY" = 1 ]; then
        api PATCH "/config/folders/$MONOLITH_FOLDER_ID" '{"paused":true}' >/dev/null
        didit "paused folder $MONOLITH_FOLDER_ID (NOT deleted)"
      else
        would "pause folder $MONOLITH_FOLDER_ID (with --pause-monolith)"
      fi
    else
      skip "$MONOLITH_FOLDER_ID present — pass --pause-monolith to pause it (still not deleted)"
    fi
    manual "DELETE the $MONOLITH_FOLDER_ID folder definition on ALL nodes (.158/.41/.100) only AFTER bake-in — this script never deletes it"
    manual "on .100: after deletion, remove its orphaned ~/.skcapstone copy (leaked minds purge)"
  else
    skip "$MONOLITH_FOLDER_ID not present on this node"
  fi

  # --- 4. Conflicts -------------------------------------------------------
  hdr "4. Existing sync-conflict files"
  local nconf; nconf="$(find "$SKROOT" -name '*.sync-conflict-*' 2>/dev/null | wc -l | tr -d ' ')"
  say "  found $nconf *.sync-conflict-* under $SKROOT"
  if [ "$nconf" != "0" ]; then
    manual "snapshot first: cp -a $SKROOT ${SKROOT}.pre-skfed-\$(date +%Y%m%d)"
    manual "hand-merge the few genuine config conflicts (yml/yaml/trust.json/skgateway.json/journal*.md/gtd) — see plan §6"
    manual "then bulk-delete the rest: find $SKROOT -name '*.sync-conflict-*' -delete"
    say "  ${c_dim}(this script does NOT delete conflict files)${c_rst}"
  fi

  # --- Summary ------------------------------------------------------------
  hdr "Summary"
  if [ "$APPLY" = 1 ]; then
    say "  ${c_grn}Applied folder/.stignore changes above.${c_rst} Restart NOT performed."
    manual "operator: verify folders reach idle + zero new conflicts over a 24h bake-in, THEN do step 7 (delete monolith)."
  else
    say "  ${c_yel}DRY-RUN — nothing changed.${c_rst} Re-run with --apply to create folders + .stignore."
    say "  Full procedure + rollback: docs/state-sync-rearch-plan.md"
  fi
}

main "$@"
