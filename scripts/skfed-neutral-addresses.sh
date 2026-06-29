#!/usr/bin/env bash
# skfed-neutral-addresses.sh — re-seed the live SKFed directory so it advertises
# a NEUTRAL custom domain (fed-<agent>.skworld.io) instead of leaky funnel FQDNs
# like  https://<machine-hostname>.tail204f0c.ts.net/api/v1/inbox  (coord d9cc87ad).
#
# WHAT IT DOES:
#   Thin, safe wrapper around `python -m skcomms.skfed_readdr`. It loads the
#   persisted signed directory, rewrites every leaky *.ts.net inbox_url/prekey_url
#   to fed-<agent>.<base-domain>, RE-SIGNS with the node key, and persists.
#     * idempotent — an entry already on the neutral domain is left alone.
#     * dry-run by default — prints the before/after and writes NOTHING.
#     * --apply rewrites + re-signs + persists.
#
# SAFETY MODEL:
#   * This script ONLY rewrites the *advertised* address in the local signed
#     directory file. It does NOT touch DNS, Cloudflare, or the funnel.
#   * The neutral name only improves privacy once it actually FRONTS the funnel —
#     run the Cloudflare cutover in docs/funnel-privacy.md FIRST (or in tandem),
#     so fed-<agent>.skworld.io resolves to the same backend. This script prints
#     those out-of-band steps as NOTEs; it never executes them.
#
# Companion doc: docs/funnel-privacy.md   (coord d9cc87ad)
#
# Usage:
#   scripts/skfed-neutral-addresses.sh [--base-domain skworld.io] [--prefix fed-] \
#       [--agent lumina] [--fqid lumina@chef.skworld]... [--all] [--apply]
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PYBIN="${SKCOMMS_PY:-$HOME/.skenv/bin/python}"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3 || true)"

APPLY=0
PASS=()   # args forwarded to the python module

usage() { sed -n '2,33p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --base-domain)  PASS+=(--base-domain "${2:-}"); shift ;;
    --prefix)       PASS+=(--prefix "${2:-}"); shift ;;
    --leaky-suffix) PASS+=(--leaky-suffix "${2:-}"); shift ;;
    --agent)        PASS+=(--agent "${2:-}"); shift ;;
    --fqid)         PASS+=(--fqid "${2:-}"); shift ;;
    --all)          PASS+=(--all) ;;
    --apply)        APPLY=1 ;;
    --dry-run)      APPLY=0 ;;   # explicit no-op for symmetry; dry-run is the default
    -h|--help)      usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
  shift
done

if [ -z "$PYBIN" ]; then
  echo "ERROR: no python found (set SKCOMMS_PY or install ~/.skenv/bin/python)" >&2
  exit 1
fi

[ "$APPLY" = 1 ] && PASS+=(--apply)

# Run the re-seed (dry-run unless --apply).
PYTHONPATH="$HERE/../src${PYTHONPATH:+:$PYTHONPATH}" "$PYBIN" -m skcomms.skfed_readdr "${PASS[@]:-}"

# Always remind the operator of the out-of-band ingress cutover.
cat <<'NOTE'

--- out-of-band (does NOT happen here) ---
  The neutral name only hides the hostname once it FRONTS the funnel. Before (or
  with) --apply, point fed-<agent>.skworld.io at the funnel — see:
      docs/funnel-privacy.md   (Cloudflare CNAME / origin-rule / CF-Tunnel)
  References sk-standards/standards/UNIFIED_INGRESS_STANDARD.md.
NOTE
