"""skcomms access plane — knowledge tools (A3) + file-location index (A1).

Self-contained module of plain callables. A2's ``sk-access`` MCP server can
register these via :func:`register`, but the module works standalone with no
MCP dependency.

Backed by **skmem-pg** on .158 (custom image: pgvector + ParadeDB pg_search/BM25
+ Apache AGE). Live details discovered from ``~/.config/skmemory/pg.env`` and the
skmemory ``pgvector_backend.py``:

* DSN:        ``postgresql://postgres:skmemory@localhost:5432/skmemory``
* Embed URL:  ``http://192.168.0.100:11434/api/embed`` (mxbai-embed-large, 1024-dim)
* Hybrid fn:  ``hybrid_search_docs(q_text, q_vec vector, k, agent_filter, rrf_k, vec_w)``
              -> ``(id, corpus, source, content, vec_rank, bm25_rank, score)``
* docs cols:  ``id, corpus, source, chunk_idx, content, meta(jsonb), tsv, agent, embedding``
* AGE graphs: ``lumina_knowledge``, ``opus_knowledge``

Design notes
------------
* mxbai-embed-large caps at 512 tokens; this Ollama build 400s on overflow. We
  truncate the query to ~1100 chars and shrink-and-retry on a 400 (matches the
  canonical skmemory backend behaviour).
* The hybrid fn has no ``layer`` / ``corpus`` parameter, so a ``layer`` filter is
  applied client-side against the ``corpus`` column after the RRF fuse.
* ``pg_search`` left-joins :data:`FILE_LOCATIONS_TABLE` so every hit carries
  ``{node, path}`` when the location index has been populated.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Configuration (env-overridable, discovered defaults match the live .158 box) #
# --------------------------------------------------------------------------- #

DEFAULT_DSN = os.environ.get(
    "SKMEMORY_PG_DSN", "postgresql://postgres:skmemory@localhost:5432/skmemory"
)
DEFAULT_EMBED_URL = os.environ.get(
    "SKMEMORY_EMBED_URL", "http://192.168.0.100:11434/api/embed"
)
DEFAULT_EMBED_MODEL = os.environ.get("SKMEMORY_EMBED_MODEL", "mxbai-embed-large")
DEFAULT_GRAPH = os.environ.get("SKMEMORY_AGE_GRAPH", "lumina_knowledge")

#: This node's identifier. Existing docs default to the local node.
LOCAL_NODE = os.environ.get("SKACCESS_NODE", ".158")

#: mxbai-embed-large is a 512-token model; ~1100 chars clears it for typical text.
EMBED_MAX_CHARS = 1100

FILE_LOCATIONS_TABLE = "file_locations"

#: Valid AGE graph-name identifier (graph name must be inlined, not a bound param).
_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# A1 DDL — idempotent. `doc_id` references docs.id (the chunk row); a file may map
# to multiple chunk rows so doc_id is NOT unique, but (node, path) is.
FILE_LOCATIONS_DDL = f"""
CREATE TABLE IF NOT EXISTS {FILE_LOCATIONS_TABLE} (
    id      bigserial PRIMARY KEY,
    node    text   NOT NULL,
    path    text   NOT NULL,
    doc_id  bigint,
    mtime   double precision,
    sha     text,
    UNIQUE (node, path)
);
CREATE INDEX IF NOT EXISTS file_locations_doc_id_idx
    ON {FILE_LOCATIONS_TABLE} (doc_id);
CREATE INDEX IF NOT EXISTS file_locations_path_idx
    ON {FILE_LOCATIONS_TABLE} (path);
"""


# --------------------------------------------------------------------------- #
# Connection + embedding helpers (injectable for tests)                       #
# --------------------------------------------------------------------------- #

# Module-level overrides so tests can mock the DB / embedder without a live PG.
_conn_factory: Optional[Callable[[], Any]] = None
_embed_fn: Optional[Callable[[str], list[float]]] = None
_cached_conn: Any = None


def configure(
    *,
    conn_factory: Optional[Callable[[], Any]] = None,
    embed_fn: Optional[Callable[[str], list[float]]] = None,
) -> None:
    """Inject a connection factory and/or embedder (used by tests and A2)."""
    global _conn_factory, _embed_fn, _cached_conn
    if conn_factory is not None:
        _conn_factory = conn_factory
        _cached_conn = None
    if embed_fn is not None:
        _embed_fn = embed_fn


def _connection(dsn: str = DEFAULT_DSN):
    """Return a live psycopg connection (cached), or the injected one."""
    global _cached_conn
    if _conn_factory is not None:
        return _conn_factory()
    import psycopg  # local import: standalone import must not require pg

    if _cached_conn is None or getattr(_cached_conn, "closed", True):
        _cached_conn = psycopg.connect(dsn, autocommit=True)
        try:
            from pgvector.psycopg import register_vector

            register_vector(_cached_conn)
        except Exception as e:  # noqa: BLE001 - vector adapter optional
            logger.debug("pgvector register_vector skipped: %s", e)
    return _cached_conn


def _embed(text: str) -> list[float]:
    """Embed a query with mxbai-embed-large. Truncates + shrink-retries on 400."""
    if _embed_fn is not None:
        return _embed_fn(text)
    import httpx  # local import

    text = (text or "")[:EMBED_MAX_CHARS]
    while text:
        try:
            r = httpx.post(
                DEFAULT_EMBED_URL,
                json={"model": DEFAULT_EMBED_MODEL, "input": text, "truncate": True},
                timeout=60.0,
            )
            r.raise_for_status()
            data = r.json()
            if "embeddings" in data:
                return data["embeddings"][0]
            if "data" in data:
                return data["data"][0]["embedding"]
            if "embedding" in data:
                return data["embedding"]
            return []
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400 and len(text) > 200:
                text = text[: len(text) // 2]
                continue
            logger.warning("embed failed (%s): %s", DEFAULT_EMBED_URL, e)
            return []
        except Exception as e:  # noqa: BLE001
            logger.warning("embed failed (%s): %s", DEFAULT_EMBED_URL, e)
            return []
    return []


def _vec_literal(vec: Iterable[float]) -> str:
    """pgvector text literal: ``[1,2,3]``. Works without the vector adapter."""
    return "[" + ",".join(repr(float(x)) for x in vec) + "]"


def _snippet(content: Optional[str], length: int = 300) -> str:
    s = (content or "").strip().replace("\n", " ")
    return s[:length] + ("…" if len(s) > length else "")


# --------------------------------------------------------------------------- #
# A1 — file-location index                                                     #
# --------------------------------------------------------------------------- #


def ensure_file_locations(conn: Any = None) -> None:
    """Idempotently create the ``file_locations`` table + indexes (A1 DDL)."""
    conn = conn or _connection()
    with conn.cursor() as cur:
        cur.execute(FILE_LOCATIONS_DDL)


def record_file_location(
    path: str,
    *,
    node: str = LOCAL_NODE,
    doc_id: Optional[int] = None,
    mtime: Optional[float] = None,
    sha: Optional[str] = None,
    conn: Any = None,
) -> None:
    """Upsert one ``{node, path}`` location row. Call from ingest per indexed file.

    Idempotent on ``(node, path)``: re-ingesting a file updates its doc_id / mtime
    / sha rather than duplicating.
    """
    conn = conn or _connection()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO {FILE_LOCATIONS_TABLE} (node, path, doc_id, mtime, sha)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (node, path) DO UPDATE SET
                doc_id = EXCLUDED.doc_id,
                mtime  = EXCLUDED.mtime,
                sha    = EXCLUDED.sha
            """,
            (node, path, doc_id, mtime, sha),
        )


def record_ingest_location(
    abs_path: str,
    *,
    doc_id: Optional[int] = None,
    node: str = LOCAL_NODE,
    conn: Any = None,
    compute_sha: bool = True,
) -> bool:
    """One-call ingest hook: index a freshly-ingested LOCAL FILE.

    Convenience wrapper over :func:`record_file_location` that derives ``mtime``
    (and, by default, the sha256) from ``abs_path`` on disk, then upserts the
    ``{node, path}`` row. Safe to call from an ingest pipeline right after a
    file's chunks are written to ``docs`` (see ``docs/access-plane-p8.md`` for the
    exact skingest insertion point).

    Returns ``True`` if a row was recorded, ``False`` if ``abs_path`` is missing /
    not a regular file (URL ingests, encrypted/private blobs, etc. should simply
    not call this). Never raises on a missing file — ingest must not break.
    """
    import os as _os

    if not abs_path:
        return False
    try:
        st = _os.stat(abs_path)
        if not _os.path.isfile(abs_path):
            return False
        mtime: Optional[float] = st.st_mtime
    except OSError:
        return False

    sha: Optional[str] = None
    if compute_sha:
        try:
            import hashlib

            h = hashlib.sha256()
            with open(abs_path, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            sha = h.hexdigest()
        except OSError:
            sha = None

    record_file_location(
        abs_path, node=node, doc_id=doc_id, mtime=mtime, sha=sha, conn=conn
    )
    return True


def pg_locate(query_or_doc_id: Any, *, limit: int = 10, conn: Any = None) -> list[dict]:
    """Resolve a location: ``{node, path, doc_id, mtime, sha, score?}``.

    * ``int`` (or digit string) -> exact ``doc_id`` lookup.
    * ``str`` -> path substring (ILIKE) match against the location index.

    Falls back to deriving locations from ``docs.source`` (defaulting node to
    :data:`LOCAL_NODE`) if the location index has no hit, so it is useful even
    before a backfill.
    """
    conn = conn or _connection()
    is_doc_id = isinstance(query_or_doc_id, int) or (
        isinstance(query_or_doc_id, str) and query_or_doc_id.strip().isdigit()
    )
    with conn.cursor() as cur:
        if is_doc_id:
            doc_id = int(query_or_doc_id)
            cur.execute(
                f"""SELECT node, path, doc_id, mtime, sha
                    FROM {FILE_LOCATIONS_TABLE} WHERE doc_id = %s LIMIT %s""",
                (doc_id, limit),
            )
            rows = cur.fetchall()
            if rows:
                return [_loc_row(r) for r in rows]
            # fallback: derive from docs.source
            cur.execute("SELECT source FROM docs WHERE id = %s", (doc_id,))
            src = cur.fetchone()
            if src and src[0]:
                return [{"node": LOCAL_NODE, "path": src[0], "doc_id": doc_id,
                         "mtime": None, "sha": None}]
            return []
        # text path-substring search
        q = str(query_or_doc_id)
        cur.execute(
            f"""SELECT node, path, doc_id, mtime, sha
                FROM {FILE_LOCATIONS_TABLE}
                WHERE path ILIKE %s ORDER BY path LIMIT %s""",
            (f"%{q}%", limit),
        )
        rows = cur.fetchall()
        if rows:
            return [_loc_row(r) for r in rows]
        # fallback: search docs.source
        cur.execute(
            "SELECT DISTINCT source, min(id) FROM docs WHERE source ILIKE %s "
            "GROUP BY source ORDER BY source LIMIT %s",
            (f"%{q}%", limit),
        )
        return [
            {"node": LOCAL_NODE, "path": r[0], "doc_id": r[1],
             "mtime": None, "sha": None}
            for r in cur.fetchall()
            if r[0]
        ]


def _loc_row(r) -> dict:
    return {"node": r[0], "path": r[1], "doc_id": r[2], "mtime": r[3], "sha": r[4]}


# --------------------------------------------------------------------------- #
# A3 — knowledge tools                                                         #
# --------------------------------------------------------------------------- #


def pg_search(
    query: str,
    k: int = 10,
    layer: Optional[str] = None,
    agent: Optional[str] = None,
    *,
    conn: Any = None,
) -> list[dict]:
    """Hybrid (vector + BM25) search over the docs corpus.

    Embeds ``query`` with mxbai, runs ``hybrid_search_docs`` (RRF fuse), then
    left-joins :data:`FILE_LOCATIONS_TABLE` so hits carry ``{node, path}`` when
    known. ``agent`` is pushed into the SQL fn; ``layer`` maps to the ``corpus``
    column and is filtered client-side (the fn has no corpus param).

    Returns ``[{doc_id, score, snippet, source, corpus, node?, path?}]``.
    """
    conn = conn or _connection()
    vec = _embed(query)
    vec_param = _vec_literal(vec) if vec else None
    # Over-fetch when a client-side layer filter is in play so we still return ~k.
    fetch_k = k * 4 if layer else k

    with conn.cursor() as cur:
        # The location index is keyed UNIQUE(node, path), so it stores ONE
        # representative chunk doc_id per file. A search hit is an arbitrary
        # chunk of that file, so a doc_id-only join misses sibling chunks. We
        # therefore join in two passes and COALESCE: (1) exact doc_id, then
        # (2) a source-suffix fallback (``fl.path`` ends with ``h.source``),
        # which resolves any chunk of a backfilled file to its absolute path.
        cur.execute(
            """
            SELECT h.id, h.corpus, h.source, h.content, h.score,
                   COALESCE(fl_id.node, fl_src.node)  AS node,
                   COALESCE(fl_id.path, fl_src.path)  AS path
            FROM hybrid_search_docs(%s, %s::vector, %s, %s) AS h
            LEFT JOIN file_locations fl_id  ON fl_id.doc_id = h.id
            LEFT JOIN LATERAL (
                SELECT node, path FROM file_locations
                WHERE h.source IS NOT NULL
                  AND path LIKE '%%/' || h.source
                ORDER BY length(path) LIMIT 1
            ) AS fl_src ON TRUE
            """,
            (query, vec_param, fetch_k, agent),
        )
        rows = cur.fetchall()

    hits: list[dict] = []
    for r in rows:
        doc_id, corpus, source, content, score, node, path = r
        if layer is not None and corpus != layer:
            continue
        hit = {
            "doc_id": doc_id,
            "score": float(score) if score is not None else None,
            "snippet": _snippet(content),
            "source": source,
            "corpus": corpus,
        }
        if node is not None:
            hit["node"] = node
        if path is not None:
            hit["path"] = path
        # Backfill location from docs.source when the index has no row yet.
        if "node" not in hit and source:
            hit["node"] = LOCAL_NODE
            hit["path"] = source
        hits.append(hit)
        if len(hits) >= k:
            break
    return hits


def graph_query(
    cypher: str,
    graph: str = DEFAULT_GRAPH,
    *,
    columns: Optional[list[str]] = None,
    conn: Any = None,
) -> list:
    """Best-effort Apache AGE cypher passthrough.

    ``columns`` declares the agtype output columns (AGE requires a column list).
    Defaults to a single ``v agtype`` column. Returns the raw rows; on error
    returns ``[]`` and logs (best-effort, per spec).
    """
    conn = conn or _connection()
    cols = columns or ["v"]
    col_decl = ", ".join(f"{c} agtype" for c in cols)
    # AGE requires the graph name as a literal constant (not a bound param), so
    # we validate it as a plain identifier and inline it. Cypher body stays in a
    # dollar-quoted literal so its content is never interpolated as SQL.
    if not _SAFE_IDENT.match(graph):
        logger.warning("graph_query: unsafe graph name %r", graph)
        return []
    try:
        with conn.cursor() as cur:
            cur.execute('LOAD \'age\'; SET search_path = ag_catalog, "$user", public;')
            cur.execute(
                f"SELECT * FROM cypher('{graph}', $cy${cypher}$cy$) AS ({col_decl});"
            )
            return cur.fetchall()
    except Exception as e:  # noqa: BLE001 - graph is best-effort
        logger.warning("graph_query failed (graph=%s): %s", graph, e)
        return []


def corpus_stats(*, conn: Any = None) -> dict:
    """Return corpus row counts + breakdowns for observability.

    ``{docs, memories, by_corpus: {...}, file_locations, graphs: [...]}``.
    """
    conn = conn or _connection()
    out: dict = {}
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM docs")
        out["docs"] = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM memories")
        out["memories"] = cur.fetchone()[0]
        cur.execute(
            "SELECT coalesce(corpus,'(none)'), count(*) FROM docs "
            "GROUP BY corpus ORDER BY count(*) DESC"
        )
        out["by_corpus"] = {r[0]: r[1] for r in cur.fetchall()}
        try:
            cur.execute(f"SELECT count(*) FROM {FILE_LOCATIONS_TABLE}")
            out["file_locations"] = cur.fetchone()[0]
        except Exception:  # noqa: BLE001 - table may not exist yet
            out["file_locations"] = None
        try:
            cur.execute("SELECT name FROM ag_catalog.ag_graph ORDER BY name")
            out["graphs"] = [r[0] for r in cur.fetchall()]
        except Exception:  # noqa: BLE001
            out["graphs"] = []
    return out


# --------------------------------------------------------------------------- #
# MCP registration helper (guarded; module works standalone)                  #
# --------------------------------------------------------------------------- #

#: Public knowledge/location tool catalog (scope='read'). Each entry:
#: ``(name, callable, description, scope)``.
TOOL_CATALOG = [
    (
        "pg_search",
        pg_search,
        "Hybrid (vector+BM25) semantic search over the sovereign corpus; "
        "returns hits tagged with {node, path}.",
        "read",
    ),
    (
        "pg_locate",
        pg_locate,
        "Resolve a query or doc_id to its authoritative {node, path} location(s).",
        "read",
    ),
    (
        "graph_query",
        graph_query,
        "Run an Apache AGE cypher query against a knowledge graph (best-effort).",
        "read",
    ),
    (
        "corpus_stats",
        corpus_stats,
        "Corpus statistics: doc/memory counts, by-corpus breakdown, graphs.",
        "read",
    ),
]


def register(server: Any) -> list[str]:
    """Register the knowledge/location tools on A2's ``sk-access`` MCP server.

    ``server`` is expected to expose ``register_tool(name, fn, description=...,
    scope=...)`` (A2's interface). This helper is duck-typed and tolerant: it
    falls back to positional args or an ``add_tool``/``tool`` API if present.

    Returns the list of registered tool names. The import-of-A2 is the caller's
    concern — this module never imports A2, so it works standalone.
    """
    registered: list[str] = []
    for name, fn, desc, scope in TOOL_CATALOG:
        if hasattr(server, "register_tool"):
            try:
                server.register_tool(name, fn, description=desc, scope=scope)
            except TypeError:
                server.register_tool(name, fn)  # minimal interface
        elif hasattr(server, "add_tool"):
            server.add_tool(name, fn)
        else:  # decorator-style FastMCP-like fallback
            server.tool(name=name, description=desc)(fn)
        registered.append(name)
    return registered
