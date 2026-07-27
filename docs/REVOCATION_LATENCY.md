# Revocation Propagation Latency

**Spec / gap:** G10 (card `b2185307`, security SPEC, HIGH)
**Status:** RESOLVED by documentation. This spec states the accepted
revocation-propagation window and the per-use guarantee. It does not change
code; the residual caveat in section 4 is an accepted limitation with a scoped
follow-up option, not built here.
**Scope:** the primary daemon authentication path (skcomms CapAuth bearer
tokens) and the skcapstone signed-token fallback path.

---

## 1. Summary answer: how fast does a revocation take effect

When a CapAuth **signing key** is revoked or expires, that revocation takes
effect on the daemon auth path within:

```
worst-case latency  =  bearer-token TTL (<= 300 s)
                     +  peers-store convergence time (Syncthing)
```

- **Bearer-token TTL: <= 300 s.** skcomms CapAuth bearer tokens carry an
  embedded UNIX timestamp and are accepted only inside a +/-300 s window
  (`_TOKEN_WINDOW_SECS = 300`, `src/skcomms/capauth_validator.py:165`, enforced
  at `capauth_validator.py:330-338`). A token is therefore effectively re-minted
  at least every 5 minutes; a stale token stops validating on its own once it
  ages past the window, independent of any key state.

- **Peers-store convergence.** The revocation certificate (and any updated /
  expired public key) is distributed as an armored `.asc` in the
  Syncthing-synced peers store and resolved at verify time by
  `_find_pubkey_by_fingerprint`, which globs
  `~/.skcapstone/skcomms/**/peers/*.asc`
  (`capauth_validator.py:72`). The revoked key becomes visible on a given node
  only once Syncthing has replicated the updated `.asc` to that node.

**Realistic bound.** Under healthy sync (fsWatcher live, nodes online), peers
store convergence is seconds, so end-to-end revocation latency is dominated by
the token TTL and is typically **under ~5 minutes**. The convergence term is
**not** fixed: it depends on sync health. If fsWatcher misses the change or a
node is offline / partitioned, convergence is bounded only by Syncthing's
periodic full-rescan interval (default 1 hour) and by the node coming back
online. The honest worst case is therefore **~5 minutes plus the current
peers-store convergence time**, which is seconds when sync is healthy and can
stretch to the rescan interval (or until a partitioned node reconnects) when it
is not.

> Operational note: revocation latency is only as good as Syncthing health. A
> node whose peers store is stale (offline, `.stignore` clobbered, fsWatcher
> wedged - see `docs/SYNCTHING_TOPOLOGY.md`) will keep honoring a key until it
> reconverges. Monitor peers-store freshness the same way you monitor the rest
> of the synced tree.

---

## 2. Per-use guarantee (signing-key revocation / expiry)

Key-level revocation and expiry are re-checked on **every** authentication, not
cached per session or per token.

`CapAuthValidator.validate()` routes local tokens to `_validate_local()`
(`capauth_validator.py:213-234, 236`). On every call `_validate_local()`:

1. re-loads the signer's public key by fingerprint from the peers store
   (`_load_public_key` -> `_find_pubkey_by_fingerprint`, `capauth_validator.py:351`,
   `403-467`, `45-84`), and
2. runs `_reject_reason_if_key_unusable(pub_key, signer_keyids)` **before**
   trusting the signature (`capauth_validator.py:365-370`).

`_reject_reason_if_key_unusable` delegates to capauth's single source of truth,
`capauth.crypto.pgpy_backend._assert_key_usable`
(`capauth/src/capauth/crypto/pgpy_backend.py:24-60`), which raises
`KeyRevokedError` on any revocation signature (primary or the signing subkey)
and `KeyExpiredError` on expiry
(`pgpy_backend.py:47-60`). If that helper cannot be imported, skcomms falls back
to an inline mirror of the same checks (`capauth_validator.py:132-148`) so the
path stays fail-closed. The same guard also protects the SDP path
(`verify_detached`, `capauth_validator.py:519-527`).

This is the fix from cards `6abe9bef` / `a93b0528`: `pgpy.verify()` performs
neither revocation nor expiry checks, so without this guard a signature from a
revoked or expired key would verify as valid. Because the check runs per-use and
reads the current peers-store copy of the key, **a revoked signing key stops
authenticating within the section 1 window** (token TTL + convergence), with no
long-lived session bypass.

---

## 3. Guaranteed vs. accepted

| Property | Behavior | Guarantee |
|---|---|---|
| Signing-key revocation | Re-checked every `validate()` against the synced peers store | Takes effect within TTL (<=300 s) + peers convergence |
| Signing-key expiry | Same per-use check | Same window |
| Stale/replayed bearer token | Rejected once older than +/-300 s | <=300 s, no key state needed |
| skcapstone capability-token-id revocation (fallback path) | See section 4 | **Not** propagated fleet-wide; node-local |

---

## 4. Residual / accepted caveat: skcapstone capability-token-list revocation

There is a second, lower-traffic revocation mechanism that does **not** meet the
section 1 propagation guarantee. It is documented here as an accepted
limitation.

skcapstone issues its own signed capability tokens
(`skcapstone/src/skcapstone/tokens.py`). `verify_token()`
(`tokens.py:176-196`) checks only `payload.is_active` (`tokens.py:186`) and the
PGP signature (`tokens.py:190-193`). It does **not** consult
`is_revoked()`. Token-ID revocation is a separate, node-**local** list:

- `revoke_token()` / `is_revoked()` read and write
  `home / "security" / "revoked-tokens.json"`
  (`tokens.py:212, 239`), which lives under the agent home and is **not** part
  of the Syncthing-synced store. A revocation recorded on one node is invisible
  to the others.
- The daemon and API bearer-auth paths use skcomms `CapAuthValidator` as the
  primary check and only fall back to `verify_token()` in the
  `except ImportError` branch, i.e. **when skcomms is not installed**
  (`api.py:530-542` and `api.py:1914-1924`; `daemon.py:2266-2278`). None of
  those fallback sites call `is_revoked()`, so even on a node where the list
  exists, the daemon/api fallback would honor a locally-revoked token.
- Only the interactive CLI verify (`cli/token.py:124-143`,
  `_cli_monolith.py:1513-1532`) consults `is_revoked()` before `verify_token()`.

**Accepted limitation:** skcapstone capability-token-ID revocation is node-local
and is not enforced on the daemon/api fallback path. In the current fleet this
path is rarely taken (skcomms is installed everywhere, so the primary
CapAuth-key path in sections 1-2 is what runs), which is why this is accepted
rather than blocking.

**Scoped follow-up option (do NOT build as part of this spec):**

1. Call `is_revoked(config.home, tok.payload.token_id)` in the three fallback
   sites (`api.py:539`, `api.py:1923`, `daemon.py:2274`) and deny on a hit, and
2. move `revoked-tokens.json` under the Syncthing-synced store (or otherwise
   replicate it) so a revocation propagates fleet-wide with the same convergence
   term as section 1.

That change would bring the capability-token path under the same propagation
guarantee. It is out of scope here.

---

## 5. Resolve-before-skcode-P2 note

Card `b2185307` permits closing G10 by **documentation or code**, and
documentation is the chosen path. This file is that resolution: the accepted
revocation-propagation window is now specified (section 1), the per-use
key-revocation guarantee is confirmed against the code (section 2), and the one
residual gap is recorded as an accepted limitation with a scoped follow-up
(section 4). G10 is considered **resolved for the purpose of enabling skcode
P2**; the section 4 follow-up is tracked separately and does not block P2.

---

## References (verified 2026-07-27)

- `skcomms/src/skcomms/capauth_validator.py`
  - `_TOKEN_WINDOW_SECS = 300` (:165); replay-window enforcement (:330-338)
  - `validate()` (:213); `_validate_local()` (:236); per-use usability gate (:365-370)
  - `_reject_reason_if_key_unusable` (:92-148); inline fallback mirror (:132-148)
  - peers-store resolution `_find_pubkey_by_fingerprint` (:45-84, glob at :72);
    `_load_public_key` (:403-467)
  - `verify_detached` SDP guard (:519-527)
- `capauth/src/capauth/crypto/pgpy_backend.py`
  - `_assert_key_usable` revocation/expiry checks (:24-60)
- `skcapstone/src/skcapstone/tokens.py`
  - `verify_token()` is_active + signature only, no is_revoked (:176-196)
  - `revoke_token()` / `is_revoked()` local `revoked-tokens.json` (:199-241)
- `skcapstone/src/skcapstone/api.py` fallback (:530-542, :1914-1924);
  `skcapstone/src/skcapstone/daemon.py` fallback (:2266-2278);
  `skcapstone/src/skcapstone/cli/token.py` CLI revocation check (:124-143)
- `skcomms/docs/SYNCTHING_TOPOLOGY.md` (sync health / convergence caveats)
