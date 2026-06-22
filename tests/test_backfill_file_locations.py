"""Tests for the P8 file-location backfill (no live Postgres required).

Covers:
* source classification — local-file vs url vs missing
* allowlist enforcement + secret hard-deny skip
* idempotent UPSERT into a sqlite-shim ``file_locations`` table
"""

from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest

# Import the script by path (it lives in scripts/, not an installed package).
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "backfill_file_locations.py"
_spec = importlib.util.spec_from_file_location("backfill_file_locations", _SCRIPT)
bfl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bfl)  # type: ignore[union-attr]

from skcomms.access.files import FileAccess, FileAccessConfig


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


@pytest.fixture()
def exposed_root(tmp_path: Path) -> Path:
    """An exposed root with a couple of files + a secret subdir."""
    root = tmp_path / "clawd"
    (root / "wiki" / "pages" / "claims").mkdir(parents=True)
    (root / "wiki" / "pages" / "claims" / "x.md").write_text("hello\n")
    (root / "wiki" / "raw").mkdir(parents=True)
    (root / "wiki" / "raw" / "y.txt").write_text("world\n")
    # a secret path that must be hard-denied even though it is under the root
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_rsa").write_text("PRIVATE KEY\n")
    return root


@pytest.fixture()
def fa(exposed_root: Path) -> FileAccess:
    return FileAccess(FileAccessConfig(roots=[str(exposed_root)]))


@pytest.fixture(autouse=True)
def _patch_bases(exposed_root: Path, monkeypatch):
    """Point the corpus base map + fallback at the temp exposed root."""
    monkeypatch.setattr(
        bfl,
        "CORPUS_BASES",
        {
            "wiki": [exposed_root / "wiki" / "pages", exposed_root / "wiki" / "raw"],
            "wiki-raw": [exposed_root / "wiki" / "raw"],
        },
    )
    monkeypatch.setattr(bfl, "FALLBACK_BASES", [exposed_root])


# --------------------------------------------------------------------------- #
# sqlite shim that mimics the file_locations UPSERT contract                    #
# --------------------------------------------------------------------------- #


class _SqliteShim:
    """Minimal psycopg-ish connection over sqlite with %s param translation."""

    def __init__(self):
        self._db = sqlite3.connect(":memory:")
        self.closed = False

    def cursor(self, *args, **kwargs):
        return _SqliteCursor(self._db)

    def close(self):
        self.closed = True
        self._db.close()


class _SqliteCursor:
    def __init__(self, db):
        self._cur = db.cursor()

    def execute(self, sql, params=()):
        # Translate the pg dialect used by knowledge.py into sqlite.
        sql = sql.replace("%s", "?")
        sql = sql.replace("bigserial PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
        sql = sql.replace("double precision", "REAL")
        sql = sql.replace("bigint", "INTEGER")
        # The DDL is multi-statement (CREATE TABLE + 2 indexes) — sqlite's
        # execute() runs one statement, so route multi-statement SQL through
        # executescript (which takes no params; the DDL has none).
        if sql.count(";") > 1 and not params:
            self._cur.executescript(sql)
        else:
            self._cur.execute(sql, params)
        return self

    def fetchall(self):
        return self._cur.fetchall()

    def fetchone(self):
        return self._cur.fetchone()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# --------------------------------------------------------------------------- #
# Classification: local-file vs url vs missing                                  #
# --------------------------------------------------------------------------- #


def test_classify_local_file(fa):
    out = bfl.resolve_local_file("claims/x.md", "wiki", fa)
    assert out is not None
    assert out.name == "x.md"
    assert out.is_file()


def test_classify_wiki_raw(fa):
    out = bfl.resolve_local_file("y.txt", "wiki-raw", fa)
    assert out is not None and out.name == "y.txt"


@pytest.mark.parametrize(
    "url",
    [
        "https://youtube.com/watch?v=abc",
        "http://x.com/foo/status/123",
        "s3://bucket/key.md",
    ],
)
def test_classify_url_skipped(fa, url):
    assert bfl.looks_like_url(url) is True
    assert bfl.resolve_local_file(url, "youtube-corpus", fa) is None


def test_classify_missing_skipped(fa):
    # source is a bare corpus name (the NULL-corpus pattern) — no such file.
    assert bfl.resolve_local_file("audio-corpus", None, fa) is None
    assert bfl.resolve_local_file("does/not/exist.md", "wiki", fa) is None


# --------------------------------------------------------------------------- #
# Allowlist + secret hard-deny                                                  #
# --------------------------------------------------------------------------- #


def test_secret_path_hard_denied(fa, exposed_root):
    # The .ssh/id_rsa file EXISTS under the root but must be denied.
    secret = exposed_root / ".ssh" / "id_rsa"
    assert secret.is_file()
    # Direct absolute source -> resolve must refuse it.
    assert bfl.resolve_local_file(str(secret), None, fa) is None


def test_outside_allowlist_denied(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("x")
    fa = FileAccess(FileAccessConfig(roots=[str(tmp_path / "clawd")]))
    assert bfl.resolve_local_file(str(outside), None, fa) is None


# --------------------------------------------------------------------------- #
# Idempotent UPSERT                                                             #
# --------------------------------------------------------------------------- #


def test_upsert_is_idempotent():
    from skcomms.access.knowledge import ensure_file_locations, record_file_location

    conn = _SqliteShim()
    ensure_file_locations(conn)

    record_file_location("/a/b.md", node=".158", doc_id=1, mtime=10.0, sha="aaa", conn=conn)
    record_file_location("/a/b.md", node=".158", doc_id=1, mtime=10.0, sha="aaa", conn=conn)

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM file_locations")
        assert cur.fetchone()[0] == 1

    # Re-ingest same (node,path) with new doc_id/mtime/sha -> updates, no dup.
    record_file_location("/a/b.md", node=".158", doc_id=2, mtime=20.0, sha="bbb", conn=conn)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), max(doc_id), max(sha) FROM file_locations")
        cnt, did, sha = cur.fetchone()
        assert cnt == 1 and did == 2 and sha == "bbb"

    # Distinct path -> new row.
    record_file_location("/a/c.md", node=".158", doc_id=3, conn=conn)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM file_locations")
        assert cur.fetchone()[0] == 2


def test_record_ingest_location_hook(tmp_path):
    """The one-call ingest hook indexes a real file and skips missing ones."""
    from skcomms.access.knowledge import (
        ensure_file_locations,
        record_ingest_location,
    )

    f = tmp_path / "ingested.md"
    f.write_text("body\n")

    conn = _SqliteShim()
    ensure_file_locations(conn)

    ok = record_ingest_location(str(f), doc_id=7, node=".158", conn=conn)
    assert ok is True
    with conn.cursor() as cur:
        cur.execute("SELECT node, path, doc_id, mtime, sha FROM file_locations")
        node, path, did, mtime, sha = cur.fetchone()
        assert node == ".158" and path == str(f) and did == 7
        assert mtime is not None and sha and len(sha) == 64

    # Missing file -> no row, no raise.
    assert record_ingest_location(str(tmp_path / "nope.md"), doc_id=8, conn=conn) is False
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM file_locations")
        assert cur.fetchone()[0] == 1

    # Idempotent re-ingest of same path.
    assert record_ingest_location(str(f), doc_id=9, node=".158", conn=conn) is True
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), max(doc_id) FROM file_locations")
        cnt, did = cur.fetchone()
        assert cnt == 1 and did == 9


def test_candidate_paths_absolute_first(tmp_path):
    abs_src = str(tmp_path / "z.md")
    cands = list(bfl.candidate_paths(abs_src, "wiki"))
    assert cands == [Path(abs_src)]
