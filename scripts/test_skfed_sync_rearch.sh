#!/usr/bin/env bash
# Unit tests for skfed-sync-rearch.sh helpers (load-bearing parsing + body gen).
# Sources the script with a guard so main() does not run, then exercises the
# pure functions. No Syncthing/REST/filesystem mutation.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/skfed-sync-rearch.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail=0
ok()   { printf '  ok   %s\n' "$*"; }
bad()  { printf '  FAIL %s\n' "$*"; fail=1; }
chk()  { # chk "desc" expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected [$2] got [$3])"; fi
}

# Extract just the helper functions we want to test (avoid running main()).
# We grep the function bodies out so `set -e`/main never fires.
eval "$(sed -n '/^parse_xml_apikey()/,/^}/p'  "$SCRIPT")"
eval "$(sed -n '/^parse_xml_gui()/,/^}/p'      "$SCRIPT")"
eval "$(sed -n '/^folder_body()/,/^}/p'        "$SCRIPT")"
eval "$(sed -n '/^per_agent_stignore()/,/^}/p' "$SCRIPT")"
eval "$(sed -n '/^shared_stignore()/,/^}/p'    "$SCRIPT")"

echo "== parse_xml_apikey / parse_xml_gui =="
cat > "$TMP/config.xml" <<'XML'
<configuration version="37">
  <folder id="x" path="/p"></folder>
  <gui enabled="true">
    <address>127.0.0.1:8384</address>
    <apikey>ABC123testKEY</apikey>
  </gui>
</configuration>
XML
chk "apikey parsed" "ABC123testKEY" "$(parse_xml_apikey "$TMP/config.xml")"
chk "gui address parsed" "127.0.0.1:8384" "$(parse_xml_gui "$TMP/config.xml")"

# Different GUI port + an inner non-gui <address> must NOT be picked.
cat > "$TMP/config2.xml" <<'XML'
<configuration version="37">
  <device id="D"><address>tcp://10.0.0.1:22000</address></device>
  <gui><address>0.0.0.0:9999</address><apikey>k2</apikey></gui>
</configuration>
XML
chk "gui address (not device address)" "0.0.0.0:9999" "$(parse_xml_gui "$TMP/config2.xml")"
chk "apikey k2" "k2" "$(parse_xml_apikey "$TMP/config2.xml")"

echo "== folder_body JSON =="
body="$(folder_body skfed-shared "skfed:shared" "/home/u/.skcapstone/_shared" "DEV1 DEV2")"
# Validate it's well-formed JSON with the expected fields.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$body" <<'PY'
import sys,json
d=json.loads(sys.argv[1])
assert d["id"]=="skfed-shared", d
assert d["type"]=="sendreceive", d
assert d["path"]=="/home/u/.skcapstone/_shared", d
assert [x["deviceID"] for x in d["devices"]]==["DEV1","DEV2"], d
print("  ok   folder_body valid JSON w/ 2 devices")
PY
fi
# Single-node (no devices) folder body still valid JSON with empty devices.
body0="$(folder_body skagent-lumina "skagent:lumina" "/p/agents/lumina" "")"
if command -v python3 >/dev/null 2>&1; then
  python3 - "$body0" <<'PY'
import sys,json
d=json.loads(sys.argv[1])
assert d["devices"]==[], d
print("  ok   folder_body empty-devices valid JSON")
PY
fi

echo "== .stignore generators contain the load-bearing rules =="
ag="$(per_agent_stignore)"
case "$ag" in *"memory"*) ok "per-agent ignores memory (hub plane)";; *) bad "per-agent must ignore memory";; esac
case "$ag" in *"sessions"*) ok "per-agent ignores sessions";; *) bad "per-agent must ignore sessions";; esac
case "$ag" in *"*.session"*) ok "per-agent ignores telegram *.session";; *) bad "per-agent must ignore *.session";; esac
case "$ag" in *"sync-conflict"*) ok "per-agent ignores sync-conflict files";; *) bad "per-agent must ignore sync-conflict";; esac
sh="$(shared_stignore)"
case "$sh" in *"sync-conflict"*) ok "shared ignores sync-conflict files";; *) bad "shared must ignore sync-conflict";; esac
# Shared must NOT ignore the federation directory it's meant to carry.
case "$sh" in *"memory"*) bad "shared must NOT ignore memory dir name";; *) ok "shared does not over-ignore";; esac

echo
if [ "$fail" = 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi
