#!/usr/bin/env python3
"""Safely drain a stranded (orphaned) skcomms outbox (coord f07cf2de).

A misrouted send path spooled signed+encrypted envelopes into a home that
NOTHING drains (historically the bare ``~/.skcomms/outbox`` from the
pre-scaffold default). This tool re-homes those envelopes into the ACTIVE
outbox the live daemon drains, or -- for envelopes already past their routing
TTL -- parks them in an archive directory. It is READ-ONLY by default and
NEVER deletes: every action is a filesystem *move*, so no message is ever lost.

What it does, per envelope in the source outbox:

  * still live (age <= ttl)      -> MOVE to the active outbox for real delivery
  * TTL-expired (age  > ttl)     -> MOVE to the archive dir (kept, not deleted)
  * unparseable / corrupt        -> MOVE to the archive dir (kept for inspection)

Idempotent: a file whose name already exists at the destination is left in
place and reported as ``skip-exists`` (re-running never double-moves or
clobbers). Dry-run prints exactly what --apply would do.

Age is taken from the envelope's own timestamp
(``metadata.created_at`` / ``created_at`` / ``timestamp``), falling back to the
file mtime. TTL is ``routing.ttl`` / ``ttl`` seconds, default 86400 (24h).

USAGE
-----
  # Dry run (default): report only, touch nothing. Confirm the resolved
  # SOURCE / ACTIVE-OUTBOX / ARCHIVE paths printed in the header first.
  python scripts/drain_orphan_outbox.py

  # Point at a specific stranded outbox and preview:
  python scripts/drain_orphan_outbox.py --source ~/.skcomms/outbox

  # Actually move files (live drain). SKAGENT selects the active per-agent
  # outbox exactly as the daemon resolves it; pin it explicitly to be sure:
  SKAGENT=lumina python scripts/drain_orphan_outbox.py --apply

  # Fully explicit (recommended for a one-off recovery):
  python scripts/drain_orphan_outbox.py --apply \
      --source     ~/.skcomms/outbox \
      --dest-outbox ~/.skcapstone/skcomms/outbox \
      --archive-dir ~/.skcomms/outbox.archive-orphan-drain

Exit status is 0 on a clean pass (including dry-run), 1 if any envelope could
not be moved under --apply.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_TTL_SECONDS = 86400  # matches the skcomms routing default
ENVELOPE_GLOBS = ("*.json", "*.skc.json")


def _resolve_active_outbox() -> Path:
    """The outbox the live daemon actually drains.

    Prefers the in-tree resolver (honors SKAGENT / SKCOMMS_HOME / SKCOMMS_OUTBOX_DIR
    exactly as the daemon does). Falls back to the node default if skcomms is
    not importable from this interpreter.
    """
    try:
        from skcomms.paths import file_transport_outbox

        return file_transport_outbox()
    except Exception:  # noqa: BLE001 - script must run even outside the venv
        return Path("~/.skcapstone/skcomms/outbox").expanduser()


def _parse_dt(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _extract(env: dict) -> tuple[str, str, Optional[datetime], int]:
    """Return (envelope_id, sender, created_at|None, ttl_seconds) across the
    legacy MessageEnvelope, Envelope v1, and SignedEnvelope shapes."""
    inner = env.get("envelope") if isinstance(env.get("envelope"), dict) else {}
    meta = env.get("metadata") if isinstance(env.get("metadata"), dict) else {}
    routing = env.get("routing") if isinstance(env.get("routing"), dict) else {}

    env_id = (
        env.get("envelope_id")
        or inner.get("envelope_id")
        or env.get("id")
        or inner.get("id")
        or "?"
    )
    sender = (
        env.get("sender")
        or env.get("from_fqid")
        or inner.get("from_fqid")
        or "?"
    )
    created = (
        _parse_dt(meta.get("created_at"))
        or _parse_dt(env.get("created_at"))
        or _parse_dt(inner.get("created_at"))
        or _parse_dt(env.get("timestamp"))
        or _parse_dt(inner.get("timestamp"))
    )
    ttl_raw = routing.get("ttl", env.get("ttl", inner.get("ttl", DEFAULT_TTL_SECONDS)))
    try:
        ttl = int(ttl_raw)
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL_SECONDS
    return str(env_id), str(sender), created, ttl


def _iter_envelopes(source: Path):
    seen: set[Path] = set()
    for pattern in ENVELOPE_GLOBS:
        for path in sorted(source.glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                yield path


def _move(src: Path, dest_dir: Path, apply: bool) -> str:
    """Move *src* into *dest_dir*, never overwriting. Returns a status token."""
    target = dest_dir / src.name
    if target.exists():
        return "skip-exists"
    if not apply:
        return "would-move"
    dest_dir.mkdir(parents=True, exist_ok=True)
    # shutil.move is a rename on the same filesystem, a copy+unlink across
    # filesystems -- either way the source only disappears once the target
    # is fully written, so a crash mid-move never loses the envelope.
    shutil.move(str(src), str(target))
    return "moved"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Safely drain a stranded skcomms outbox.")
    ap.add_argument(
        "--source",
        type=Path,
        default=Path("~/.skcomms/outbox").expanduser(),
        help="Stranded outbox to drain (default: ~/.skcomms/outbox).",
    )
    ap.add_argument(
        "--dest-outbox",
        type=Path,
        default=None,
        help="Active outbox to re-home live envelopes into "
        "(default: the daemon's resolved outbox for the current SKAGENT).",
    )
    ap.add_argument(
        "--archive-dir",
        type=Path,
        default=None,
        help="Where TTL-expired / corrupt envelopes are parked "
        "(default: <source>/../<source-name>.archive-orphan-drain).",
    )
    ap.add_argument(
        "--ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help="Fallback TTL in seconds when an envelope carries none "
        f"(default: {DEFAULT_TTL_SECONDS}).",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Actually move files. Omitted = dry run (report only).",
    )
    args = ap.parse_args(argv)

    source: Path = args.source.expanduser()
    dest_outbox: Path = (args.dest_outbox or _resolve_active_outbox()).expanduser()
    archive_dir: Path = (
        args.archive_dir
        or source.parent / f"{source.name}.archive-orphan-drain"
    ).expanduser()

    now = datetime.now(timezone.utc)
    mode = "APPLY (moving files)" if args.apply else "DRY-RUN (no changes)"

    print(f"# drain_orphan_outbox  [{mode}]")
    print(f"#   source        : {source}")
    print(f"#   active outbox : {dest_outbox}")
    print(f"#   archive dir   : {archive_dir}")
    print(f"#   now (UTC)     : {now.isoformat()}")
    print("#")

    if not source.is_dir():
        print(f"# source outbox does not exist or is not a directory: {source}")
        return 0

    if args.apply and dest_outbox.resolve() == source.resolve():
        print("# refusing to re-home into the SAME directory as the source.")
        return 1

    counts = {"requeue": 0, "archive-expired": 0, "archive-corrupt": 0, "skip-exists": 0}
    errors = 0
    print(f"{'ENVELOPE_ID':36}  {'SENDER':28}  {'AGE':>10}  ACTION")
    print(f"{'-'*36}  {'-'*28}  {'-'*10}  {'-'*24}")

    for path in _iter_envelopes(source):
        try:
            env = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(env, dict):
                raise ValueError("not a JSON object")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            status = _move(path, archive_dir, args.apply)
            key = "skip-exists" if status == "skip-exists" else "archive-corrupt"
            counts[key] += 1
            errors += 1 if status not in ("moved", "would-move", "skip-exists") else 0
            print(f"{path.name:36}  {'(unparseable)':28}  {'?':>10}  archive-corrupt/{status}: {exc}")
            continue

        env_id, sender, created, ttl = _extract(env)
        if created is None:
            try:
                created = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                created = now
        age = (now - created).total_seconds()
        age_str = f"{age/3600:.1f}h" if age < 86400 * 2 else f"{age/86400:.1f}d"

        expired = ttl > 0 and age > ttl
        dest = archive_dir if expired else dest_outbox
        status = _move(path, dest, args.apply)

        if status == "skip-exists":
            counts["skip-exists"] += 1
            action = "skip-exists"
        elif expired:
            counts["archive-expired"] += 1
            action = f"archive-expired/{status}"
        else:
            counts["requeue"] += 1
            action = f"requeue/{status}"
        if status not in ("moved", "would-move", "skip-exists"):
            errors += 1

        print(f"{env_id[:36]:36}  {sender[:28]:28}  {age_str:>10}  {action}")

    total = sum(counts.values())
    print("#")
    print(f"# scanned {total} envelope(s):")
    print(f"#   requeue (live)      : {counts['requeue']}")
    print(f"#   archive (TTL-expired): {counts['archive-expired']}")
    print(f"#   archive (corrupt)   : {counts['archive-corrupt']}")
    print(f"#   skipped (exists)    : {counts['skip-exists']}")
    if not args.apply:
        print("#")
        print("# dry run only -- nothing moved. Re-run with --apply to act.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
