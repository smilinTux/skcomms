#!/usr/bin/env python3
"""skfed P8 — backfill the file-location index from the ``docs`` corpus.

Iterates the live ``docs`` table on skmem-pg (.158) and, for every row whose
``source`` resolves to an **existing local file under an exposed root** (and is
NOT a hard-denied secret path), UPSERTs a row into ``file_locations``
(``node='.158'``, ``path``=absolute file path, ``doc_id``=docs.id, ``mtime``=
``os.stat`` mtime, ``sha``=sha256 of the file).

URLs (youtube/x/etc) and sources that don't resolve to a real file are skipped
and counted. The write is **additive** — only INSERT/UPSERT into
``file_locations``; ``docs`` is never touched. Idempotent on ``(node, path)``.

Source-path semantics
---------------------
``docs.source`` is mostly *relative to a corpus root* (e.g. ``wiki`` sources are
relative to ``~/clawd/wiki/pages``). This script maps each row to a prioritized
list of candidate base dirs (corpus-aware), takes the first base under which the
file exists, then runs the resolved absolute path through the access plane's
``FileAccess._resolve_checked`` (the *same* allowlist + secret hard-deny choke
point used by the A4 file tools). A source that is already an absolute path is
tried as-is first.

Usage
-----
    python scripts/backfill_file_locations.py            # dry-run (default)
    python scripts/backfill_file_locations.py --apply    # write
    python scripts/backfill_file_locations.py --limit 500 --apply
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Iterable, Optional

# Make the in-repo skcomms importable when run from the worktree without install.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from skcomms.access.files import FileAccess, FileAccessConfig, PathDeniedError  # noqa: E402
from skcomms.access.knowledge import (  # noqa: E402
    DEFAULT_DSN,
    LOCAL_NODE,
    ensure_file_locations,
    record_file_location,
)

# --------------------------------------------------------------------------- #
# Corpus -> candidate base dirs (most-specific first). A source is resolved by  #
# joining it onto each base in order and taking the first that EXISTS as a file.#
# An absolute source is tried verbatim before any base.                        #
# --------------------------------------------------------------------------- #

_CLAWD = Path("~/clawd").expanduser()

CORPUS_BASES: dict[Optional[str], list[Path]] = {
    "wiki": [_CLAWD / "wiki" / "pages", _CLAWD / "wiki" / "raw", _CLAWD / "wiki"],
    "wiki-raw": [_CLAWD / "wiki" / "raw", _CLAWD / "wiki" / "pages"],
    "youtube-corpus": [_CLAWD / "ingest" / "youtube" / "_history" / "transcripts"],
    "skingest": [
        _CLAWD / "wiki" / "pages" / "entities" / "yampolskiy",
        _CLAWD / "wiki" / "pages",
        _CLAWD / "wiki" / "raw",
    ],
    # clawd-vault-private resolves under ~/.skcapstone/agents/... which is a
    # HARD-DENIED secret root — left to fall through and be denied by the
    # allowlist/secret check (counted as skipped). No base listed on purpose.
}

# Fallback bases tried for any corpus when the corpus-specific bases miss.
FALLBACK_BASES: list[Path] = [_CLAWD]

# Cheap pre-filter: sources that are obviously remote URLs (never local files).
_URL_PREFIXES = ("http://", "https://", "ftp://", "s3://", "gs://")


def looks_like_url(source: str) -> bool:
    s = (source or "").strip().lower()
    return s.startswith(_URL_PREFIXES)


def candidate_paths(source: str, corpus: Optional[str]) -> Iterable[Path]:
    """Yield candidate absolute paths for a docs.source, best-guess first."""
    src = (source or "").strip()
    if not src:
        return
    p = Path(src).expanduser()
    if p.is_absolute():
        yield p
        return
    bases = list(CORPUS_BASES.get(corpus, []))
    bases.extend(FALLBACK_BASES)
    seen: set[Path] = set()
    for base in bases:
        cand = (base / src)
        if cand in seen:
            continue
        seen.add(cand)
        yield cand


def sha256_file(path: Path, *, chunk: int = 1 << 20) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def resolve_local_file(
    source: str, corpus: Optional[str], fa: FileAccess
) -> Optional[Path]:
    """Return the access-plane-validated absolute Path for a source, or None.

    A source resolves only if (a) some candidate base yields an existing file,
    AND (b) that file passes ``FileAccess._resolve_checked`` (allowlist +
    secret hard-deny). Returns None for URLs, missing files, and denied paths.
    """
    if looks_like_url(source):
        return None
    for cand in candidate_paths(source, corpus):
        try:
            if not cand.is_file():
                continue
        except OSError:
            continue
        try:
            return fa._resolve_checked(str(cand), must_exist=True)
        except (PathDeniedError, Exception):  # noqa: BLE001 - denied => skip
            # Denied (outside allowlist or secret) — keep trying other bases in
            # case a different base lands inside the allowlist; otherwise None.
            continue
    return None


def iter_docs(conn, *, limit: Optional[int]):
    """Yield (id, source, corpus) rows from docs that have a non-empty source."""
    sql = "SELECT id, source, corpus FROM docs WHERE source IS NOT NULL AND source <> '' ORDER BY id"
    params: tuple = ()
    if limit is not None:
        sql += " LIMIT %s"
        params = (limit,)
    with conn.cursor(name="docs_scan") as cur:  # server-side cursor (46k rows)
        cur.itersize = 2000
        cur.execute(sql, params)
        for row in cur:
            yield row


def connect(dsn: str, *, autocommit: bool):
    import psycopg

    return psycopg.connect(dsn, autocommit=autocommit)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="write rows (default: dry-run)")
    ap.add_argument("--limit", type=int, default=None, help="cap docs scanned (testing)")
    ap.add_argument("--dsn", default=DEFAULT_DSN, help="Postgres DSN")
    ap.add_argument("--node", default=LOCAL_NODE, help="node identifier (default .158)")
    ap.add_argument(
        "--root",
        action="append",
        default=None,
        help="exposed root allowlist (repeatable; default ~/clawd)",
    )
    ap.add_argument(
        "--no-sha", action="store_true", help="skip sha256 (faster; sha stored NULL)"
    )
    args = ap.parse_args(argv)
    if not args.root:
        args.root = ["~/clawd"]

    dry_run = not args.apply
    # Exposed root = ~/clawd by default (overridable via --root). We intentionally
    # do NOT include the agent skcapstone home (FileAccess's other default root)
    # so agent soul/memory dirs are never indexed; the secret deny-list still
    # provides defense-in-depth.
    roots = [str(Path(r).expanduser()) for r in args.root]
    fa = FileAccess(FileAccessConfig(roots=roots))

    stats = {
        "scanned": 0,
        "file_backed": 0,
        "urls_skipped": 0,
        "missing_skipped": 0,
        "upserted": 0,
    }

    # Two connections: a transactional one for the server-side read cursor
    # (DECLARE CURSOR needs a transaction), and an autocommit one for the
    # additive file_locations UPSERTs.
    read_conn = connect(args.dsn, autocommit=False)
    write_conn = connect(args.dsn, autocommit=True) if not dry_run else None
    if write_conn is not None:
        ensure_file_locations(write_conn)

    try:
        for doc_id, source, corpus in iter_docs(read_conn, limit=args.limit):
            stats["scanned"] += 1
            if looks_like_url(source):
                stats["urls_skipped"] += 1
                continue
            resolved = resolve_local_file(source, corpus, fa)
            if resolved is None:
                stats["missing_skipped"] += 1
                continue
            stats["file_backed"] += 1
            try:
                mtime = resolved.stat().st_mtime
            except OSError:
                mtime = None
            sha = None if args.no_sha else sha256_file(resolved)
            if dry_run:
                continue
            record_file_location(
                str(resolved),
                node=args.node,
                doc_id=int(doc_id),
                mtime=mtime,
                sha=sha,
                conn=write_conn,
            )
            stats["upserted"] += 1
    finally:
        read_conn.close()
        if write_conn is not None:
            write_conn.close()

    mode = "DRY-RUN (no writes)" if dry_run else "APPLIED"
    print(f"[backfill_file_locations] {mode} node={args.node}")
    for k in ("scanned", "file_backed", "urls_skipped", "missing_skipped", "upserted"):
        print(f"  {k:16s} {stats[k]}")
    if dry_run:
        print("  (re-run with --apply to write file_locations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
