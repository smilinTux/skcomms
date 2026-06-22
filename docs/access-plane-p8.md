# Access Plane P8 — File-Location Index Backfill + Ingest Wiring

P8 makes the A1 file-location index (`file_locations` table, created/queried by
`src/skcomms/access/knowledge.py`) return **real `{node, path}`** for indexed
files: (1) a one-shot **backfill** from the existing corpus, and (2) an **ingest
hook** so the index stays current.

## What ships

* `scripts/backfill_file_locations.py` — scans `docs` (~46.5k rows on skmem-pg
  .158), resolves each `source` to an existing local file under the exposed-root
  allowlist (default `~/clawd`, secrets hard-denied via the **same**
  `FileAccess._resolve_checked` choke point the A4 file tools use), and UPSERTs
  `file_locations(node='.158', path=<abs>, doc_id, mtime, sha)`. `--dry-run`
  default; `--apply` to write; idempotent on `(node, path)`.
* `knowledge.record_ingest_location(abs_path, *, doc_id, node=LOCAL_NODE, conn)`
  — one-call ingest hook (derives `mtime`+`sha256` from disk, upserts; returns
  `False` and never raises for missing/non-file paths).

## Backfill result (live `--apply`, 2026-06-22)

```
scanned          46496
file_backed      18963   # chunk rows whose source resolved to a real local file
urls_skipped     0       # no http(s)/s3 sources in this corpus
missing_skipped  27533   # 27314 NULL-corpus placeholder rows (source = a corpus
                         #   name, not a file) + 218 clawd-vault-private (under
                         #   ~/.skcapstone/agents → out of allowlist) + 1 d6test
upserted         18963   # collapsed by UNIQUE(node,path) to 11653 distinct files
```

`docs` is **never** modified — writes are additive to `file_locations` only, so
they replicate cleanly to the .41 hot-standby.

### Source → base-dir map (corpus-aware)

`docs.source` is mostly *relative to a corpus root*. The backfill tries, in
order, the corpus-specific bases then `~/clawd`, and takes the first existing
file:

| corpus           | base dir(s)                                              |
|------------------|---------------------------------------------------------|
| `wiki`           | `~/clawd/wiki/pages`, `~/clawd/wiki/raw`                 |
| `wiki-raw`       | `~/clawd/wiki/raw`, `~/clawd/wiki/pages`                 |
| `youtube-corpus` | `~/clawd/ingest/youtube/_history/transcripts`           |
| `skingest`       | `~/clawd/wiki/pages/entities/yampolskiy`, `…/pages`, raw |
| (any)            | fallback `~/clawd`                                       |

Absolute sources are tried verbatim first.

## Ingest wiring — precise insertion point

The corpus is populated by **skingest** (a separate repo:
`~/clawd/skingest`), not skcomms. The single place every local-file ingest
writes `docs` is:

* **File:** `~/clawd/skingest/src/skingest/stores/pg_upsert.py`,
  `upsert_chunks(...)` — the `INSERT INTO docs … ON CONFLICT (source, chunk_idx)`.
* **Caller with the absolute path:**
  `~/clawd/skingest/src/skingest/pipeline.py`, the `upsert_chunks(...)` call
  (~line 254). `abs_path` (the absolute local file) is in scope there; `rel_path`
  is what's stored in `docs.source`.

### One-call hook to add (in `pipeline.py`, right after `upsert_chunks` succeeds)

```python
# P8: keep the access-plane file-location index current. Only for non-private,
# non-encrypted local files (private/encrypted blobs stay pg-only, KYA-gated).
if not private and not extra.get("encrypted"):
    try:
        from skcomms.access.knowledge import record_ingest_location
        record_ingest_location(abs_path, node=".158")  # doc_id optional
    except Exception:
        pass  # never let location indexing break an ingest
```

Notes:
* `doc_id` is optional — `pg_search` resolves any chunk of a backfilled file to
  its absolute path via the **source-suffix** join fallback (below), so a
  per-file row without a specific chunk's `doc_id` is sufficient.
* `record_ingest_location` opens its own connection if `conn` is omitted; pass a
  live `conn` to reuse one. It is psycopg(3)-based (skcomms), independent of
  skingest's psycopg2 — no version coupling.
* This edit is intentionally **not** applied to the skingest repo from the P8
  branch (cross-repo); it is documented here for the skingest owner to land. The
  helper it depends on ships and is tested in skcomms.

## pg_search path coverage (knowledge.py change)

`file_locations` is `UNIQUE(node, path)` → one representative chunk `doc_id` per
file. A search hit is an *arbitrary* chunk, so a `doc_id`-only join misses
sibling chunks. `pg_search` now joins in two passes and `COALESCE`s:

1. exact `fl_id.doc_id = h.id`, then
2. a `LATERAL` source-suffix fallback (`fl.path LIKE '%/' || h.source`).

Result: **44/44** search hits whose `source` is a real `.md/.txt/.json` file now
carry the absolute `{node, path}`; the only no-path hits are the NULL-corpus
placeholder rows that have no backing file.

## Verification

```
$ pg_locate('on-controllability-of-ai')
  → {node:'.158', path:'…/wiki/pages/entities/wiki/on-controllability-of-ai.md',
     doc_id:42351, mtime:…, sha:88c737…}

$ pg_locate(31254)
  → {node:'.158', path:'…/entities/yampolskiy/impossibility-results-survey.md', …}
```

Tests: `tests/test_backfill_file_locations.py` (classification, allowlist +
secret-skip, idempotent upsert, ingest hook) and `tests/test_knowledge.py`
(updated pg_search join shape) — all green via:

```
cd /home/cbrd21 && PYTHONPATH=/home/cbrd21/wt/p8-backfill/src \
  python -m pytest tests/test_backfill_file_locations.py tests/test_knowledge.py -q
```
