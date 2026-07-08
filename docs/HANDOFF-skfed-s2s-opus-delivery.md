# HANDOFF — skfed-s2s reports "delivered" but opus never receives

**Date:** 2026-07-03 · **Author:** Opus (Claude Code) · **For:** fresh session, focused skcomms/skfed debugging

## Objective (one line)
A local `skchat send opus "..."` reports `Status: sent via skfed-s2s` but the message is **never written to opus's inbox** and opus's Hermes brain never sees it. Find why skfed-s2s reports success without the envelope being accepted+written at the receiver, and make same-box `lumina→opus` (and eventually any→opus) DM delivery actually land. Then run the round-trip test.

## Reproduce (30 seconds)
```bash
# send as lumina (the local CLI identity) to opus
~/.skenv/bin/skchat send opus "handoff repro $(date +%H%M%S)"
#   -> prints:  Status: sent via skfed-s2s

# nothing lands anywhere:
find ~/.skcapstone/agents/opus/comms/inbox -maxdepth 1 -name '*.skc.json' -newermt '2 min ago' | wc -l   # 0
curl -s "http://localhost:8766/inbox?limit=2&since_minutes=3" | python3 -m json.tool                       # []
# and the receiving API logs ZERO writes for it:
journalctl --user -u skcomms-api.service --since '2 min ago' | grep 'federation inbox accepted'            # (empty)
```

## What is PROVEN working (do NOT re-debug these)
- **The Hermes chain is fine.** Injecting a message straight into opus's store makes opus's brain reply:
  ```bash
  SKCHAT_HOME=/home/cbrd21/.skchat-opus SKAGENT=opus ~/.skenv/bin/python -c '
  from skchat.history import ChatHistory; from skchat.models import ChatMessage
  ChatHistory().save(ChatMessage(sender="chef@skworld.io", recipient="capauth:opus@skworld.io", content="test"))'
  # -> opus gateway log: "conversation turn ... platform=skchat ... model=claude-opus-4-8" -> 102-char reply -> [Skchat] Sending response
  ```
- **The inbox unification is done + correct** (skcomms commit `1866fe2`): the one `skcomms-api` routes each recipient to `~/.skcapstone/agents/<recipient>/comms/inbox`; `load_config()` gives each agent its own paths from `SKAGENT`. Verified: `_write_to_recipient_inbox` target is `agents/opus/comms/inbox`, and the opus daemon polls exactly that. **Lumina is byte-identical (same inode) and still receiving — don't regress it.**
- The opus daemon (`skchat-daemon-opus.service`, `SKCHAT_HOME=~/.skchat-opus`, health `:9386`) + webui@opus (`:8766`, isolated store) + opus Hermes gateway (`hermes-gateway-opus.service`, brain `:18782`) are all up and correct.

## The bug is isolated to the skfed-s2s SEND path
`skchat/src/skchat/transport.py::send_message` (line ~404), federation branch **lines ~498–532**:
```python
fed_fqid = self._federation_target(message.recipient)          # opus -> a fed target (has https-s2s inbox_url)
if fed_fqid is not None and hasattr(self._skcomms, "send_federated"):
    report = self._skcomms.send_federated(fed_fqid, payload_json, **_fed_kw)
    delivered = getattr(report, "delivered", False)
    if delivered:                                              # <-- returns True (false positive)
        ... return {"delivered": True, "transport": "skfed-s2s"}
    logger.info("federated send ... not delivered — falling back")   # <-- NOT reached, so no file failover
```
So `skcomms.send_federated(opus, ...)` returns `delivered=True`, the code returns success, and **never falls back to the file transport** (which now points at opus's canonical inbox and WOULD work). The false-positive is inside `send_federated`.

### Prime suspect
`send_federated` almost certainly POSTs to opus's **resolved `inbox_url`** and treats a 200 as delivered — but that URL is likely opus's **public funnel** (`https://noroc2027.tail204f0c.ts.net:10000/...`, from `webui-opus.env SKCHAT_FUNNEL_PUBLIC_URL` / opus's `/federation/status`), NOT the local `skcomms-api` at `http://127.0.0.1:9384/api/v1/inbox`. That funnel POST 200s somewhere that never runs `post_inbox`'s per-recipient write — hence **zero "federation inbox accepted" logs** for opus while unrelated federation traffic still 200s.

## First diagnostic steps (in order)
1. **Find opus's resolved fed target + inbox_url** the sender uses:
   - `skchat/src/skchat/transport.py::_federation_target` (~line 292/358) — what fqid + `inbox_url()` it returns for `capauth:opus@skworld.io`.
   - `skcomms.core::send_federated` (grep `def send_federated` in `skcomms/src/skcomms/core.py`) — what URL it POSTs to and what it counts as `delivered`.
2. **Confirm the POST target.** If it's opus's funnel URL, that's the bug — same-box delivery should target the local api `http://127.0.0.1:9384/api/v1/inbox` (which now routes correctly to `agents/opus/comms/inbox`). Options:
   - Make `send_federated` prefer the local api when the recipient resolves to a same-node agent (loopback), OR
   - Make `delivered` reflect an actual accept (the api returns `{"ok": true, "id": ...}` only after `_write_to_recipient_inbox`; verify send_federated checks that, and that the funnel actually reaches `post_inbox`).
3. **Or force the FILE transport for same-box peers.** opus's peer record now advertises `file:///home/cbrd21/.skcapstone/agents/opus/comms/inbox` (fixed this session). If skfed-s2s didn't false-positive, failover to file would deliver and the opus daemon would pick it up. A same-box loopback via file is the simplest reliable path.
4. Re-check the api: `post_inbox` (`skcomms/src/skcomms/api.py:1002`) has **no 200-without-write path** — every 200 logs `"federation inbox accepted ... -> <path>"`. Confirm whether that INFO log is just suppressed by log level (raise it / add a debug) vs the writes genuinely not happening. Cross-check by watching `find ~/.skcapstone/agents/*/comms/inbox -newermt '1 min ago'` during live traffic.

## Key files
- `skchat/src/skchat/transport.py` — `send_message` (~404), `_federation_target` (~292/358), `_FILE_INBOX_ROOT`
- `skcomms/src/skcomms/core.py` — `send_federated` (the false-positive origin)
- `skcomms/src/skcomms/api.py` — `post_inbox` (1002), `_write_to_recipient_inbox` (928, already fixed to canonical inbox), `_fed_inbox_dir` (859)
- `skcomms/src/skcomms/skfed_readdr.py`, `skfed_resolve.py`, `skfed_announce.py`, `skfed_directory.py` — endpoint resolution
- `skcomms/src/skcomms/federation.py` — `accept_signed` (verify path)
- opus peer record: `~/.skcapstone/peers/opus.json`

## System state (all running, lumina safe)
- Committed: skmemory `a7aec4d`; hermes-skworld (`e50fc44` HTTP client, `a44bd57` recipient-filter); hermes-skchat-channel `00c6a35`/`949431d`; skchat `8028ee2` (advocacy guard), `0dbfe6f` (SKCHAT_HOME history); skcomms `1866fe2` (N-agent unify).
- Services up: `hermes-gateway` (lumina, healthy, Telegram working), `hermes-gateway-opus`, `skchat-daemon` (lumina), `skchat-daemon-opus` (:9386), `skchat-webui@lumina`/`@opus`, `skcomms-api` (:9384).
- Legacy retired: `~/.skcomm*` + `~/.skcomms/inbox*` → `*.legacy-retired-20260703`. Opus's 33k backlog → `~/.skcapstone/skcomms/inbox/opus/.archive-backlog-20260703`.
- opus profile: `~/.hermes/profiles/opus` (SKAGENT=opus, skchat-only, `SKCHAT_CHANNEL_ENABLED=1`, allowlist chef+lumina+claude+opus). opus's skmemory linked to `~/.skcapstone/agents/opus` (pgvector).

## SAFETY (hard constraints)
- **Do not regress lumina.** Its skcomms inbox path resolves to the same inode as before (`~/.skcapstone/agents/lumina/comms/inbox`). Any change to `send_federated`/config/api must keep lumina receiving (verify: `grep 'Received [1-9]' ~/.skchat/daemon.log` keeps advancing; Telegram still replies).
- Test with `skchat send opus` (as lumina) and verify the FULL chain: file lands in `agents/opus/comms/inbox` → opus daemon "Received N" → opus store (`curl :8766/inbox`) → opus gateway `platform=skchat` turn → 102-char reply.

## Definition of done
`skchat send opus "..."` (and a real DM from a client) → opus's Hermes brain replies over skchat, delivered back to the sender. Then optionally: fold `skchat-daemon.service` + `skchat-daemon-opus.service` into a templated `skchat-daemon@.service` (the remaining "unify services" item).

## Context
Full epic + prior decisions: `~/clawd/skcapstone-repos/skchat/docs/hermes-channel-epic.md`; session memory: `~/.claude/projects/-home-cbrd21/memory/project_skchat_hermes_channel_epic.md`.
