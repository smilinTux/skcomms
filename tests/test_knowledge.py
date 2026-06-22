"""Tests for skcomms.access.knowledge (A1 location index + A3 knowledge tools).

The DB layer is mocked with a fake psycopg-style connection/cursor that records
the SQL it was asked to run and returns canned rows, so the unit tests do NOT
require a live Postgres. One integration test runs against the real skmem-pg if
it is reachable and is skipped otherwise.
"""

from __future__ import annotations

import re

import pytest

from skcomms.access import knowledge as K


# --------------------------------------------------------------------------- #
# Fake DB layer                                                               #
# --------------------------------------------------------------------------- #


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.executed.append((sql, params))
        # Match the next canned result by a substring key. Prefer the longest
        # (most specific) matching key so generic substrings don't shadow it.
        best = None
        for key, rows in self.conn.canned.items():
            if key in sql and (best is None or len(key) > len(best[0])):
                best = (key, rows)
        self.conn._last = best[1] if best else []

    def fetchall(self):
        return list(self.conn._last)

    def fetchone(self):
        return self.conn._last[0] if self.conn._last else None


class FakeConn:
    closed = False

    def __init__(self, canned=None):
        self.canned = canned or {}
        self.executed = []
        self._last = []

    def cursor(self):
        return FakeCursor(self)


def norm(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip().lower()


@pytest.fixture(autouse=True)
def reset_config():
    """Make sure module-level injected state doesn't leak between tests."""
    K._conn_factory = None
    K._embed_fn = None
    K._cached_conn = None
    yield
    K._conn_factory = None
    K._embed_fn = None
    K._cached_conn = None


# --------------------------------------------------------------------------- #
# A1 — file_locations DDL + locate                                            #
# --------------------------------------------------------------------------- #


def test_file_locations_ddl_idempotent():
    conn = FakeConn()
    K.ensure_file_locations(conn)
    K.ensure_file_locations(conn)  # second call must be safe / identical
    ddls = [norm(s) for s, _ in conn.executed]
    assert len(ddls) == 2
    assert ddls[0] == ddls[1]
    assert "create table if not exists file_locations" in ddls[0]
    assert "unique (node, path)" in ddls[0]
    assert "create index if not exists file_locations_doc_id_idx" in ddls[0]


def test_record_file_location_upsert():
    conn = FakeConn()
    K.record_file_location(
        "/home/cbrd21/clawd/x.md", node=".41", doc_id=42, mtime=1.5, sha="abc", conn=conn
    )
    sql, params = conn.executed[-1]
    assert "insert into file_locations" in norm(sql)
    assert "on conflict (node, path) do update" in norm(sql)
    assert params == (".41", "/home/cbrd21/clawd/x.md", 42, 1.5, "abc")


def test_pg_locate_by_doc_id_hits_index():
    conn = FakeConn(
        canned={"WHERE doc_id = %s": [(".41", "/home/cbrd21/clawd/x.md", 42, 1.5, "abc")]}
    )
    out = K.pg_locate(42, conn=conn)
    assert out == [
        {"node": ".41", "path": "/home/cbrd21/clawd/x.md", "doc_id": 42,
         "mtime": 1.5, "sha": "abc"}
    ]
    # int doc_id path must NOT do an ILIKE path search
    assert all("ILIKE" not in s for s, _ in conn.executed)


def test_pg_locate_doc_id_falls_back_to_docs_source():
    # No row in file_locations -> derive from docs.source, default node.
    conn = FakeConn(canned={"SELECT source FROM docs WHERE id = %s": [("lens/foo.md",)]})
    out = K.pg_locate("99", conn=conn)  # digit-string treated as doc_id
    assert out == [
        {"node": K.LOCAL_NODE, "path": "lens/foo.md", "doc_id": 99,
         "mtime": None, "sha": None}
    ]


def test_pg_locate_by_path_substring():
    conn = FakeConn(
        canned={"path ILIKE %s": [(".158", "lens/applications/x.md", 7, None, None)]}
    )
    out = K.pg_locate("applications", conn=conn)
    assert out[0]["path"] == "lens/applications/x.md"
    sql, params = conn.executed[0]
    assert params == ("%applications%", 10)


# --------------------------------------------------------------------------- #
# A3 — pg_search                                                              #
# --------------------------------------------------------------------------- #


def test_pg_search_builds_query_and_maps_rows():
    K.configure(embed_fn=lambda t: [0.1, 0.2, 0.3])
    rows = [
        # (id, corpus, source, content, score, node, path)
        (101, "wiki", "lens/a.md", "alpha content " * 30, 0.9, ".41", "/abs/lens/a.md"),
        (102, "youtube-corpus", "vid/b", "beta content", 0.5, None, None),
    ]
    conn = FakeConn(canned={"hybrid_search_docs": rows})

    hits = K.pg_search("capauth enrollment bug", k=10, agent="lumina", conn=conn)

    # query construction: calls hybrid_search_docs joined to file_locations
    sql, params = conn.executed[-1]
    ns = norm(sql)
    assert "hybrid_search_docs(%s, %s::vector, %s, %s)" in ns
    assert "left join file_locations fl on fl.doc_id = h.id" in ns
    # params: (q_text, vec_literal, fetch_k, agent)
    assert params[0] == "capauth enrollment bug"
    assert params[1] == "[0.1,0.2,0.3]"
    assert params[2] == 10  # no layer filter -> fetch_k == k
    assert params[3] == "lumina"

    # row mapping
    assert hits[0]["doc_id"] == 101
    assert hits[0]["score"] == 0.9
    assert hits[0]["source"] == "lens/a.md"
    assert hits[0]["corpus"] == "wiki"
    assert hits[0]["node"] == ".41"
    assert hits[0]["path"] == "/abs/lens/a.md"
    assert hits[0]["snippet"].endswith("…")  # long content truncated
    # second hit had no location row -> backfilled from source + LOCAL_NODE
    assert hits[1]["node"] == K.LOCAL_NODE
    assert hits[1]["path"] == "vid/b"


def test_pg_search_layer_filter_overfetches_and_filters():
    K.configure(embed_fn=lambda t: [1.0])
    rows = [
        (1, "wiki", "a", "x", 0.9, None, None),
        (2, "youtube-corpus", "b", "y", 0.8, None, None),
        (3, "wiki", "c", "z", 0.7, None, None),
    ]
    conn = FakeConn(canned={"hybrid_search_docs": rows})
    hits = K.pg_search("q", k=2, layer="wiki", conn=conn)
    # layer -> fetch_k == k*4
    _, params = conn.executed[-1]
    assert params[2] == 8
    # only wiki corpus rows survive
    assert [h["doc_id"] for h in hits] == [1, 3]
    assert all(h["corpus"] == "wiki" for h in hits)


def test_pg_search_empty_embedding_passes_null_vector():
    K.configure(embed_fn=lambda t: [])  # embed failure
    conn = FakeConn(canned={"hybrid_search_docs": []})
    K.pg_search("q", conn=conn)
    _, params = conn.executed[-1]
    assert params[1] is None  # NULL vector -> BM25-only inside the fn


# --------------------------------------------------------------------------- #
# A3 — graph_query + corpus_stats                                            #
# --------------------------------------------------------------------------- #


def test_graph_query_builds_cypher_and_columns():
    conn = FakeConn(canned={"cypher": [("{...}::vertex",)]})
    out = K.graph_query("MATCH (n) RETURN n LIMIT 1", graph="opus_knowledge",
                        columns=["n"], conn=conn)
    assert out == [("{...}::vertex",)]
    joined = " ".join(norm(s) for s, _ in conn.executed)
    assert "load 'age'" in joined
    assert "cypher('opus_knowledge'," in joined  # graph name inlined, validated
    assert "as (n agtype)" in joined


def test_graph_query_rejects_unsafe_graph_name():
    conn = FakeConn(canned={"cypher": [("x",)]})
    assert K.graph_query("MATCH (n) RETURN n", graph="bad; DROP", conn=conn) == []
    assert conn.executed == []  # never reached the DB


def test_graph_query_best_effort_swallows_errors():
    class BoomConn:
        closed = False

        def cursor(self):
            raise RuntimeError("age not loaded")

    assert K.graph_query("MATCH (n) RETURN n", conn=BoomConn()) == []


def test_corpus_stats_shape():
    conn = FakeConn(
        canned={
            "SELECT count(*) FROM docs": [(46496,)],
            "SELECT count(*) FROM memories": [(16353,)],
            "GROUP BY corpus ORDER BY count(*) DESC": [
                ("wiki", 30000), ("youtube-corpus", 16496)
            ],
            "FROM file_locations": [(5,)],
            "ag_graph": [("lumina_knowledge",), ("opus_knowledge",)],
        }
    )
    stats = K.corpus_stats(conn=conn)
    assert stats["docs"] == 46496
    assert stats["memories"] == 16353
    assert stats["by_corpus"] == {"wiki": 30000, "youtube-corpus": 16496}
    assert stats["file_locations"] == 5
    assert stats["graphs"] == ["lumina_knowledge", "opus_knowledge"]


# --------------------------------------------------------------------------- #
# register()                                                                  #
# --------------------------------------------------------------------------- #


def test_register_with_register_tool_interface():
    calls = []

    class Server:
        def register_tool(self, name, fn, description=None, scope=None):
            calls.append((name, fn, description, scope))

    names = K.register(Server())
    assert names == ["pg_search", "pg_locate", "graph_query", "corpus_stats"]
    assert {c[0] for c in calls} == set(names)
    assert all(c[3] == "read" for c in calls)  # all scope='read'
    # registered callables are the real module functions
    by_name = {c[0]: c[1] for c in calls}
    assert by_name["pg_search"] is K.pg_search
    assert by_name["corpus_stats"] is K.corpus_stats


def test_register_minimal_interface_fallback():
    calls = []

    class MinimalServer:
        def register_tool(self, name, fn):  # no description/scope kwargs
            calls.append((name, fn))

    names = K.register(MinimalServer())
    assert names == ["pg_search", "pg_locate", "graph_query", "corpus_stats"]
    assert len(calls) == 4


def test_register_add_tool_fallback():
    calls = []

    class AddToolServer:
        def add_tool(self, name, fn):
            calls.append(name)

    names = K.register(AddToolServer())
    assert calls == names


# --------------------------------------------------------------------------- #
# Integration (skipped unless live skmem-pg is reachable)                     #
# --------------------------------------------------------------------------- #


def _live_conn():
    try:
        import psycopg

        return psycopg.connect(K.DEFAULT_DSN, autocommit=True, connect_timeout=3)
    except Exception:
        return None


_LIVE = _live_conn()


@pytest.mark.skipif(_LIVE is None, reason="live skmem-pg not reachable")
def test_integration_corpus_stats_and_ddl():
    conn = _LIVE
    K.ensure_file_locations(conn)  # idempotent against live DB
    stats = K.corpus_stats(conn=conn)
    assert stats["docs"] > 0
    assert isinstance(stats["by_corpus"], dict)
    assert "file_locations" in stats
    # locate fallback derives from docs.source even with empty index
    loc = K.pg_locate("lens", conn=conn)
    assert isinstance(loc, list)
