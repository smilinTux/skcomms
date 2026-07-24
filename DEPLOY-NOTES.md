# Deploy Notes: node-local nonce caches (fix/nonce-cache-node-local)

## What changed
The two replay-guard SQLite DBs no longer live inside the Syncthing-synced
skcomms home:

| DB | Old path (synced) | New default path (node-local) |
|----|-------------------|-------------------------------|
| Federation inbox | `~/.skcapstone/skcomms/state/nonce_cache.db` | `~/.local/state/skcomms/nonce_cache.db` |
| sk-access | `~/.skcapstone/skcomms/state/access_nonce_cache.db` | `~/.local/state/skcomms/access_nonce_cache.db` |

Resolution order: `SKCOMMS_NONCE_DB` / `SKCOMMS_ACCESS_NONCE_DB` (exact file)
> `SKCOMMS_NONCE_CACHE_DIR` (directory) > `$XDG_STATE_HOME/skcomms/` >
`~/.local/state/skcomms/`.

On first start with the new code, a healthy legacy DB is migrated once
(SQLite backup API) into the new location; a corrupt legacy DB is skipped
with a log warning and the cache starts fresh. Fresh is safe: the envelope
freshness check (300s max age + 60s skew) bounds any replay exposure.
Migration never deletes the old file; ops remove it below.

## Rollout (.158 first, then .41, one node at a time)

Run the whole block on .158, verify, then repeat on .41.

### 1. Stop the skcomms services on the node
```bash
systemctl --user stop skcomms-api
# stop the sk-access server too (unit name as deployed on the node):
systemctl --user stop sk-access 2>/dev/null || true
```

### 2. Deploy the new code (fleet policy: pip install -e)
```bash
cd ~/clawd/skcapstone-repos/skcomms
git fetch origin && git checkout main && git pull
~/.skenv/bin/pip install -e .
```

### 3. Keep the old path out of Syncthing at the FOLDER ROOT
The home's own `.stignore` only works if the Syncthing folder is rooted at
`~/.skcapstone/skcomms`. If the shared folder is rooted higher (e.g.
`~/.skcapstone`), add the pattern to THAT root's `.stignore` on BOTH nodes:
```bash
# find the folder root first: Syncthing GUI, or:
grep -o '<folder[^>]*path="[^"]*"' ~/.local/state/syncthing/config.xml
# if the root is ~/.skcapstone, append (idempotent):
grep -qx 'skcomms/state/**' ~/.skcapstone/.stignore 2>/dev/null \
  || echo 'skcomms/state/**' >> ~/.skcapstone/.stignore
```

### 4. Restart and let the code migrate the legacy DB
```bash
systemctl --user start skcomms-api
systemctl --user start sk-access 2>/dev/null || true
journalctl --user -u skcomms-api --since '-5 min' \
  | grep -Ei 'migrated legacy nonce cache|not migrated|fail-closed'
```

### 5. Verify the new node-local store is live
```bash
ls -l ~/.local/state/skcomms/
# expect nonce_cache.db (and access_nonce_cache.db once sk-access has started)
curl -s http://127.0.0.1:9384/api/v1/health || true
```
Optional replay-guard smoke test: POST the same signed envelope to
`/api/v1/inbox` twice; the second must return 409.

### 6. Remove the old synced DBs and the existing conflict copy
Do this only AFTER step 5 confirms the new store is live on the node:
```bash
rm -f ~/.skcapstone/skcomms/state/nonce_cache.db \
      ~/.skcapstone/skcomms/state/nonce_cache.db-wal \
      ~/.skcapstone/skcomms/state/nonce_cache.db-shm
rm -f ~/.skcapstone/skcomms/state/access_nonce_cache.db \
      ~/.skcapstone/skcomms/state/access_nonce_cache.db-wal \
      ~/.skcapstone/skcomms/state/access_nonce_cache.db-shm
rm -f ~/.skcapstone/skcomms/state/nonce_cache.sync-conflict-*.db
# specifically the known one:
rm -f ~/.skcapstone/skcomms/state/nonce_cache.sync-conflict-20260710-074950-CIHSBZ4.db
rmdir ~/.skcapstone/skcomms/state 2>/dev/null || true
```

### 7. Repeat steps 1-6 on .41

### 8. Post-rollout checks (both nodes done)
```bash
# no state DBs left under the synced tree on either node:
ls ~/.skcapstone/skcomms/state/ 2>/dev/null
# no new sync-conflict files appearing after a day:
find ~/.skcapstone -name '*sync-conflict*' -newer ~/.local/state/skcomms/nonce_cache.db
```

## Rollback
Stop services, `git checkout` the previous rev, `pip install -e .`, restart.
The old code recreates `~/.skcapstone/skcomms/state/` DBs fresh; replay
exposure is again bounded by the freshness window. The node-local files in
`~/.local/state/skcomms/` can stay (harmless, ignored by old code).

## Notes
- If ops ever needs to pin the cache dir (e.g. a tmpfs or a different disk),
  set `SKCOMMS_NONCE_CACHE_DIR=/path` in `~/.config/skcomms/skcomms.env`
  (the `EnvironmentFile` of `skcomms-api.service`) and the sk-access unit.
- Do NOT point both nodes' `SKCOMMS_NONCE_CACHE_DIR` at any shared or synced
  path. The caches are strictly per-node.
