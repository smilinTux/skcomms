"""SKFed P4 — Nostr-relay store-and-forward (offline deferred delivery, §9b).

When every DIRECT federation rail fails (peer offline / NAT'd / unreachable),
the router's last resort is to *publish the signed envelope to the Nostr relay*
so the recipient node pulls it when it comes back online. This turns a hard
delivery failure into a deferred one.

Event shape
-----------
A store-and-forward event is a NIP-17/NIP-59 **gift-wrapped encrypted DM** (the
same crypto the :class:`~skcomms.transports.nostr.NostrTransport` uses), with two
differences from a plain DM:

* the inner DM **content is the recipient-encrypted ``SignedEnvelope`` bytes**
  (base64). The public relay is an UNTRUSTED rail, so the body is encrypted to
  the recipient's Nostr pubkey (NIP-44) on top of being PGP-signed — the relay
  (and anyone watching) sees only ciphertext addressed to an ephemeral key.
* the outer kind-1059 gift wrap carries the recipient's pubkey in a ``#p`` tag
  (addressing) **plus an ``#k`` skfed marker tag** (``["k", SKFED_SF_MARKER]``)
  so the puller can filter store-and-forward events specifically and a node's
  ordinary DM poller is not disturbed.

Send path
---------
:class:`StoreForwardTransport` is a :class:`~skcomms.transport.Transport` named
``"nostr"`` so it slots straight into the router's
``_store_forward_transport`` hook (``Router._try_store_forward``) — when all
direct rails fail the router calls ``send(signed_bytes, recipient_fqid)``. It
resolves ``recipient_fqid → nostr_pubkey`` via the discovery
:class:`~skcomms.discovery.PeerStore`, gift-wraps the (already-signed) envelope
encrypted to that pubkey, and publishes to the relay(s). Best-effort.

Pull path
---------
:class:`StoreForwardPuller` is the receive side a node runs on a timer: it
queries the relay for S&F gift wraps addressed to this node's Nostr pubkey,
NIP-44-decrypts each, parses the inner :class:`SignedEnvelope`, runs the full
federation accept gate (:func:`skcomms.federation.accept_signed`: signature →
freshness → nonce-replay), and on success writes it to the recipient's inbox —
the *same* terminal step ``POST /api/v1/inbox`` performs. Idempotent: the relay
event-id dedup (skip already-seen gift wraps) plus the federation nonce cache
(replay guard) make redelivery a no-op.

Relay I/O sits behind injectable ``publish``/``query`` seams (mirroring
:mod:`skcomms.nostr_discovery`), so the whole module is testable with fakes — no
network.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from typing import Callable, Iterable, Optional

from .envelope import SignedEnvelope
from .transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

logger = logging.getLogger("skcomms.store_forward")

# Outer-gift-wrap marker tag value so a puller can filter S&F events without
# colliding with ordinary NIP-17 DMs (kind 1059 is shared).
SKFED_SF_MARKER = "skfed-sf"

# A publish seam takes a built Nostr event dict and returns whether it landed.
PublishFn = Callable[[dict], bool]
# A query seam takes a Nostr filter dict and returns matching event dicts.
QueryFn = Callable[[dict], list]


# ---------------------------------------------------------------------------
# Default relay seams (real network) — wrap the skcomms nostr low-level
# ---------------------------------------------------------------------------


def _default_publish(relays: Iterable[str]) -> PublishFn:
    from .transports.nostr import _publish_to_relay

    relays = list(relays)

    def _pub(event: dict) -> bool:
        ok = False
        for relay in relays:
            ok = _publish_to_relay(relay, event) or ok
        return ok

    return _pub


def _default_query(relays: Iterable[str]) -> QueryFn:
    from .transports.nostr import _query_relay

    relays = list(relays)

    def _qry(filters: dict) -> list:
        out: list = []
        seen: set[str] = set()
        for relay in relays:
            for ev in _query_relay(relay, filters):
                eid = ev.get("id", "")
                if eid and eid in seen:
                    continue
                if eid:
                    seen.add(eid)
                out.append(ev)
        return out

    return _qry


def default_relays() -> list[str]:
    """Resolve the S&F relay list from the environment.

    Honors ``SKCHAT_NOSTR_RELAYS`` (comma- or whitespace-separated) — the same
    relay var the rest of SKFed federation uses. Empty when unset.
    """
    import os

    raw = os.environ.get("SKCHAT_NOSTR_RELAYS", "")
    return [r.strip() for r in raw.replace(",", " ").split() if r.strip()]


# ---------------------------------------------------------------------------
# fqid → Nostr pubkey resolution
# ---------------------------------------------------------------------------


def resolve_nostr_pubkey(recipient: str, store=None) -> Optional[str]:
    """Resolve a recipient (fqid or bare name) to its Nostr x-only hex pubkey.

    Looks the recipient up in the discovery :class:`~skcomms.discovery.PeerStore`
    and returns its pinned ``nostr_pubkey``. A 64-char hex string passed in
    directly is treated as already-a-pubkey (pass-through).

    Args:
        recipient: Recipient fqid (``<agent>@<operator>.<realm>``), bare agent
            name, or a literal 64-char hex Nostr pubkey.
        store: Optional :class:`PeerStore` (a default one is used otherwise).

    Returns:
        The 64-char hex Nostr pubkey, or ``None`` if it can't be resolved.
    """
    # Literal hex pubkey → pass through.
    if _looks_like_hex_pubkey(recipient):
        return recipient.lower()

    try:
        from .discovery import PeerStore

        store = store or PeerStore()
        name = recipient.split("@", 1)[0] if "@" in recipient else recipient
        peer = store.get(name)
        if peer is None and "@" in recipient:
            for p in store.list_all():
                if p.fqid == recipient:
                    peer = p
                    break
        if peer is not None and peer.nostr_pubkey:
            return peer.nostr_pubkey
    except Exception as exc:  # noqa: BLE001
        logger.debug("nostr pubkey resolution failed for %s: %s", recipient, exc)
    return None


def _looks_like_hex_pubkey(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Event build / parse (gift-wrapped, recipient-encrypted)
# ---------------------------------------------------------------------------


def build_store_forward_event(
    signed_bytes: bytes,
    recipient_pubkey_hex: str,
    *,
    sender_secret: Optional[bytes] = None,
) -> dict:
    """Gift-wrap signed-envelope bytes as an encrypted, addressed S&F event.

    The bytes (a :class:`SignedEnvelope`) are base64-encoded, wrapped as a
    NIP-17 DM, NIP-44-encrypted and NIP-59 gift-wrapped to ``recipient_pubkey``
    (reusing :func:`skcomms.transports.nostr.wrap_dm`), then tagged with the
    skfed S&F marker so the puller can filter for it.

    Args:
        signed_bytes: The exact ``SignedEnvelope.to_bytes()`` to deliver.
        recipient_pubkey_hex: Recipient's 64-char hex Nostr x-only pubkey.
        sender_secret: Sender's 32-byte Nostr secret. When omitted an ephemeral
            secret is used (sender anonymity; the recipient learns nothing about
            the sender from the wrap — the PGP signature inside is authoritative).

    Returns:
        A signed kind-1059 gift-wrap Nostr event dict ready to publish.
    """
    from .transports.nostr import _pubkey_of, _random_secret, wrap_dm

    secret = sender_secret or _random_secret()
    sender_x, _ = _pubkey_of(secret)
    content_b64 = base64.b64encode(signed_bytes).decode()
    gift = wrap_dm(secret, sender_x.hex(), recipient_pubkey_hex, content_b64)
    # Mark it as a store-and-forward event (kind 1059 is shared with plain DMs).
    gift.setdefault("tags", []).append(["k", SKFED_SF_MARKER])
    return gift


def parse_store_forward_event(
    event: dict, recipient_secret: bytes
) -> Optional[SignedEnvelope]:
    """Unwrap + decrypt an S&F gift wrap back into a :class:`SignedEnvelope`.

    Args:
        event: A kind-1059 gift-wrap Nostr event dict (from a relay).
        recipient_secret: This node's 32-byte Nostr secret.

    Returns:
        The inner :class:`SignedEnvelope`, or ``None`` if the event isn't a
        valid S&F event / can't be decrypted / doesn't carry a SignedEnvelope.
    """
    from .transports.nostr import unwrap_dm

    result = unwrap_dm(recipient_secret, event)
    if result is None:
        return None
    _sender_pub, content_b64 = result
    try:
        raw = base64.b64decode(content_b64)
        return SignedEnvelope.from_bytes(raw)
    except Exception as exc:  # noqa: BLE001
        logger.debug("S&F event %s carried no SignedEnvelope: %s", event.get("id", "?")[:8], exc)
        return None


# ---------------------------------------------------------------------------
# Send side — the router's store-and-forward rail
# ---------------------------------------------------------------------------


# Rail name the router selects as its store-and-forward fallback. Distinct from
# the general-purpose "nostr" DM rail (which addresses a hex pubkey directly):
# this rail resolves an fqid → pubkey and is purpose-built for federation S&F.
STORE_FORWARD_RAIL = "nostr-sf"


class StoreForwardTransport(Transport):
    """Nostr-relay store-and-forward rail (the router's S&F fallback).

    Named ``"nostr-sf"`` so :class:`~skcomms.router.Router` can be pointed at it
    via ``store_forward_transport="nostr-sf"``: when all direct rails fail the
    router's ``_try_store_forward`` calls :meth:`send` with the signed envelope
    bytes and the recipient fqid.

    Unlike :class:`~skcomms.transports.nostr.NostrTransport` (a general DM rail
    that addresses a 64-char hex pubkey directly), this rail is purpose-built for
    federation S&F: it resolves the recipient *fqid* → Nostr pubkey via the
    :class:`PeerStore`, marks events with the skfed S&F tag, and treats the relay
    as untrusted (always encrypts). The *receive* side is the dedicated
    :class:`StoreForwardPuller`, so :meth:`receive` returns ``[]`` (the router's
    receive loop must not also pull S&F events — that would bypass the federation
    accept gate + inbox write).

    Attributes:
        name: ``"nostr-sf"`` (point ``Router(store_forward_transport=...)`` here).
        priority: 9 — last-resort fallback; ordered after direct rails.
        category: STEALTH — encrypted relay transport with metadata hiding.
    """

    name: str = STORE_FORWARD_RAIL
    priority: int = 9
    category: TransportCategory = TransportCategory.STEALTH

    def __init__(
        self,
        *,
        sender_secret: Optional[bytes] = None,
        relays: Optional[list[str]] = None,
        store=None,
        publish: Optional[PublishFn] = None,
        priority: int = 9,
    ) -> None:
        """Initialize the store-and-forward rail.

        Args:
            sender_secret: Optional 32-byte Nostr secret to wrap with (ephemeral
                per-send if omitted).
            relays: Relay WebSocket URLs (defaults to ``SKCHAT_NOSTR_RELAYS``).
            store: Optional :class:`PeerStore` for fqid→pubkey resolution.
            publish: Injectable publish seam (tests / custom relay transport).
            priority: Rail priority (lower = higher; default 9 = last resort).
        """
        self.priority = priority
        self._secret = sender_secret
        self._relays = relays if relays is not None else default_relays()
        self._store = store
        self._publish = publish or _default_publish(self._relays)

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys ``relays``, ``private_key_hex``.
        """
        if "relays" in config:
            self._relays = config["relays"]
            self._publish = _default_publish(self._relays)
        if config.get("private_key_hex"):
            self._secret = bytes.fromhex(config["private_key_hex"])

    def is_available(self) -> bool:
        """The rail is usable if Nostr crypto deps are present.

        A missing relay set is tolerated (publish is best-effort and will simply
        land nowhere), but without the crypto stack we cannot wrap at all.
        """
        try:
            from .transports.nostr import NOSTR_AVAILABLE

            return bool(NOSTR_AVAILABLE)
        except Exception:  # noqa: BLE001
            return False

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Publish signed envelope bytes to the relay for offline pickup.

        Args:
            envelope_bytes: The ``SignedEnvelope.to_bytes()`` (router passes the
                exact wire bytes; for federation these are already signed).
            recipient: Recipient fqid / bare name / literal hex Nostr pubkey.

        Returns:
            SendResult — success only if a relay accepted the event.
        """
        start = time.monotonic()
        env_id = _extract_envelope_id(envelope_bytes)

        pubkey = resolve_nostr_pubkey(recipient, store=self._store)
        if not pubkey:
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=env_id,
                latency_ms=(time.monotonic() - start) * 1000,
                error=f"no nostr_pubkey known for recipient {recipient!r}",
            )

        try:
            event = build_store_forward_event(
                envelope_bytes, pubkey, sender_secret=self._secret
            )
            published = self._publish(event)
        except Exception as exc:  # noqa: BLE001
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=env_id,
                latency_ms=(time.monotonic() - start) * 1000,
                error=f"store-forward publish error: {exc}",
            )

        elapsed = (time.monotonic() - start) * 1000
        if published:
            logger.info("store-forward published %s for %s", env_id[:8], recipient)
            return SendResult(
                success=True,
                transport_name=self.name,
                envelope_id=env_id,
                latency_ms=elapsed,
            )
        return SendResult(
            success=False,
            transport_name=self.name,
            envelope_id=env_id,
            latency_ms=elapsed,
            error="no relay accepted the store-forward event",
        )

    def receive(self) -> list[bytes]:
        """No-op — S&F receive is the dedicated :class:`StoreForwardPuller`.

        Returning ``[]`` keeps the router's ordinary receive loop from pulling
        S&F events (which must go through the federation accept gate + inbox
        write, not the generic receive path).
        """
        return []

    def health_check(self) -> HealthStatus:
        """Report rail health (crypto availability + relay count)."""
        ok = self.is_available()
        return HealthStatus(
            transport_name=self.name,
            status=TransportStatus.AVAILABLE if ok else TransportStatus.UNAVAILABLE,
            error=None if ok else "nostr crypto deps unavailable",
            details={"relays": self._relays, "marker": SKFED_SF_MARKER},
        )


def create_transport(
    priority: int = 9,
    private_key_hex: Optional[str] = None,
    relays: Optional[list[str]] = None,
    **kwargs,
) -> StoreForwardTransport:
    """Factory for the router's transport loader (``BUILTIN_TRANSPORTS``).

    Args:
        priority: Rail priority (lower = higher; default 9 = last resort).
        private_key_hex: Optional 64-char hex Nostr secret to wrap with.
        relays: Relay WebSocket URLs (defaults to ``SKCHAT_NOSTR_RELAYS``).

    Returns:
        A configured :class:`StoreForwardTransport`.
    """
    secret = bytes.fromhex(private_key_hex) if private_key_hex else None
    return StoreForwardTransport(sender_secret=secret, relays=relays, priority=priority)


# ---------------------------------------------------------------------------
# Pull side — query, decrypt, accept_signed, write to inbox
# ---------------------------------------------------------------------------


# A sink takes a verified Envelope v1 and persists it; returns an id/path.
DeliverFn = Callable[[object], str]


def _default_deliver(env) -> str:
    """Default inbox sink: write a verified Envelope v1 to the local inbox.

    Reuses the SAME terminal step as ``POST /api/v1/inbox``
    (:func:`skcomms.api._write_to_recipient_inbox`) so a store-and-forward
    pickup is delivered identically to an S2S HTTP delivery.
    """
    from .api import _write_to_recipient_inbox

    return _write_to_recipient_inbox(env)


def _default_verifier_for(from_fqid: str):
    """Build an inbox verifier loaded with the sender's trusted key.

    Reuses :func:`skcomms.api._build_inbox_verifier` (TOFU-pinned pubkey →
    discovery peer pubkey) so the S&F accept gate trusts the exact same keys the
    HTTP inbox does.
    """
    from .api import _build_inbox_verifier

    return _build_inbox_verifier(from_fqid)


class StoreForwardPuller:
    """Poll the relay for S&F events, accept-gate them, deliver to the inbox.

    The receive side of P4. On each :meth:`pull` it queries the relay for S&F
    gift wraps addressed to this node's Nostr pubkey, decrypts each, parses the
    inner :class:`SignedEnvelope`, runs :func:`skcomms.federation.accept_signed`
    (signature → freshness → nonce-replay), and on success writes the verified
    envelope to the recipient inbox.

    Idempotency is two-layered:
      * **relay event-id dedup** — a gift wrap already seen this process is
        skipped before any work (cheap).
      * **federation nonce cache** — even across processes / relays, a replayed
        envelope is rejected by the shared :class:`~skcomms.federation.NonceCache`
        so it is never delivered twice.

    Args:
        recipient_secret: This node's 32-byte Nostr secret (its inbox key).
        relays: Relay WebSocket URLs (defaults to ``SKCHAT_NOSTR_RELAYS``).
        nonce_cache: Shared replay guard. Pass the SAME instance the HTTP inbox
            uses (``skcomms.api._get_nonce_cache()``) for cross-rail idempotency.
            ``None`` resolves that durable cache itself and RAISES if the store
            cannot be opened (fail-closed; never a silent in-memory fallback).
        query: Injectable query seam (tests / custom relay transport).
        deliver: Injectable inbox sink (default: write to the local inbox).
        verifier_factory: ``from_fqid -> EnvelopeVerifier`` (default: the HTTP
            inbox's TOFU verifier).
        since_window: How far back (seconds) to query the relay.
    """

    def __init__(
        self,
        recipient_secret: bytes,
        *,
        relays: Optional[list[str]] = None,
        nonce_cache=None,
        query: Optional[QueryFn] = None,
        deliver: Optional[DeliverFn] = None,
        verifier_factory: Optional[Callable[[str], object]] = None,
        since_window: int = 7 * 24 * 3600,
    ) -> None:
        from .transports.nostr import _pubkey_of

        self._secret = recipient_secret
        x, _ = _pubkey_of(recipient_secret)
        self._pubkey_hex = x.hex()
        self._relays = relays if relays is not None else default_relays()
        self._query = query or _default_query(self._relays)
        self._deliver = deliver or _default_deliver
        self._verifier_factory = verifier_factory or _default_verifier_for
        self._since_window = since_window
        self._seen_event_ids: set[str] = set()

        if nonce_cache is None:
            # Fail closed: share the HTTP inbox's durable replay cache. If the
            # durable store cannot be opened, this raises rather than silently
            # downgrading to a fresh in-memory cache, which would re-open the
            # restart replay window on the S&F rail while the HTTP inbox
            # correctly fails closed (coord 11e295a3 review).
            from .api import _get_nonce_cache

            nonce_cache = _get_nonce_cache()
        self._nonce_cache = nonce_cache

    @property
    def pubkey(self) -> str:
        """This node's Nostr x-only hex pubkey (the S&F inbox address)."""
        return self._pubkey_hex

    def pull(self) -> list[str]:
        """One pull sweep: query → decrypt → accept_signed → deliver.

        Best-effort and idempotent — a malformed / untrusted / replayed event is
        skipped without aborting the batch.

        Returns:
            List of inbox ids/paths written this sweep (one per newly-delivered
            envelope).
        """
        from .federation import (
            ReplayError,
            SignatureError,
            StaleError,
            accept_signed,
        )

        since = int(time.time()) - self._since_window
        filters = {
            "kinds": [1059],  # KIND_GIFT_WRAP
            "#p": [self._pubkey_hex],
            "#k": [SKFED_SF_MARKER],
            "since": since,
        }
        delivered: list[str] = []

        for event in self._query(filters):
            eid = event.get("id", "")
            if eid and eid in self._seen_event_ids:
                continue  # relay event-id dedup (layer 1)
            if eid:
                self._seen_event_ids.add(eid)

            signed = parse_store_forward_event(event, self._secret)
            if signed is None:
                continue

            from_fqid = signed.envelope.from_fqid
            try:
                verifier = self._verifier_factory(from_fqid)
                env = accept_signed(
                    signed, verifier=verifier, nonce_cache=self._nonce_cache
                )
            except ReplayError:
                logger.debug("S&F replay rejected from %s (nonce dedup)", from_fqid)
                continue
            except (SignatureError, StaleError) as exc:
                logger.warning("S&F event from %s rejected: %s", from_fqid, exc)
                continue
            except Exception as exc:  # noqa: BLE001
                logger.warning("S&F accept gate error from %s: %s", from_fqid, exc)
                continue

            try:
                ref = self._deliver(env)
                delivered.append(ref)
                logger.info("store-forward delivered %s from %s -> %s", env.id, from_fqid, ref)
            except Exception as exc:  # noqa: BLE001
                logger.warning("S&F inbox write failed for %s: %s", env.id, exc)

        return delivered


# ---------------------------------------------------------------------------
# Startup hook — run the pull loop on a timer (config-gated, non-fatal)
# ---------------------------------------------------------------------------


def _resolve_self_nostr_secret() -> Optional[bytes]:
    """Best-effort: resolve this node's Nostr secret for the puller.

    Honors ``SKCOMMS_NOSTR_SECRET`` (64-char hex) — the inbox key the node also
    advertises (as ``nostr_pubkey``) in its discovery record. Returns ``None``
    if unset / malformed (the caller should then skip the puller).
    """
    import os

    raw = os.environ.get("SKCOMMS_NOSTR_SECRET", "").strip()
    if not raw:
        return None
    try:
        secret = bytes.fromhex(raw)
        return secret if len(secret) == 32 else None
    except ValueError:
        return None


def start_pull_loop(
    *,
    recipient_secret: Optional[bytes] = None,
    relays: Optional[list[str]] = None,
    interval: float = 60.0,
    nonce_cache=None,
    puller: Optional[StoreForwardPuller] = None,
) -> Optional[threading.Thread]:
    """Start the store-and-forward pull loop as a daemon thread (best-effort).

    Designed to be wired into node/skcomms startup. **Never raises** — any
    failure (no key, no relays, missing deps) is logged and the loop is simply
    not started, so S&F can't take the node down.

    Config gate: returns ``None`` (does nothing) unless a Nostr secret is
    available (arg or ``SKCOMMS_NOSTR_SECRET``) AND
    ``SKCOMMS_STORE_FORWARD_PULL`` is truthy (``1``/``true``/``yes``), so the
    loop only runs where the operator has opted in.

    Args:
        recipient_secret: This node's 32-byte Nostr secret (else env-resolved).
        relays: Relay URLs (else ``SKCHAT_NOSTR_RELAYS``).
        interval: Seconds between pull sweeps.
        nonce_cache: Shared replay guard (else the HTTP inbox's durable
            cache; if that store cannot be opened the loop is NOT started,
            fail-closed, with an error-level log).
        puller: Pre-built :class:`StoreForwardPuller` (tests / custom seams);
            bypasses the env gate when provided.

    Returns:
        The started daemon :class:`threading.Thread`, or ``None`` if not started.
    """
    import os

    try:
        if puller is None:
            gate = os.environ.get("SKCOMMS_STORE_FORWARD_PULL", "").strip().lower()
            if gate not in ("1", "true", "yes", "on"):
                logger.debug("store-forward pull loop disabled (SKCOMMS_STORE_FORWARD_PULL unset)")
                return None
            secret = recipient_secret or _resolve_self_nostr_secret()
            if not secret:
                logger.debug("store-forward pull loop: no nostr secret — skipping")
                return None
            if nonce_cache is None:
                # Fail closed on the replay guard: without the durable cache
                # the pull rail would accept replays across restarts, so the
                # loop is not started at all (rail degraded but secure).
                try:
                    from .api import _get_nonce_cache

                    nonce_cache = _get_nonce_cache()
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "store-forward pull loop NOT started (fail-closed): "
                        "durable nonce replay cache unavailable: %s. Fix the "
                        "replay store (SKCOMMS_NONCE_DB, "
                        "SKCOMMS_NONCE_CACHE_DIR, or the node-local "
                        "~/.local/state/skcomms/) and restart.",
                        exc,
                    )
                    return None
            puller = StoreForwardPuller(secret, relays=relays, nonce_cache=nonce_cache)

        stop = threading.Event()

        def _loop() -> None:
            while not stop.is_set():
                try:
                    puller.pull()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("store-forward pull sweep error (non-fatal): %s", exc)
                stop.wait(timeout=interval)

        thread = threading.Thread(target=_loop, daemon=True, name="skcomms-sf-pull")
        thread.start()
        logger.info("store-forward pull loop started (interval=%.0fs)", interval)
        return thread
    except Exception as exc:  # noqa: BLE001
        logger.warning("store-forward pull loop failed to start (non-fatal): %s", exc)
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _extract_envelope_id(envelope_bytes: bytes) -> str:
    """Best-effort envelope id extraction from SignedEnvelope wire bytes."""
    try:
        data = json.loads(envelope_bytes)
        env = data.get("envelope", data)
        return env.get("id") or env.get("envelope_id") or f"unknown-{int(time.time())}"
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        return f"unknown-{int(time.time())}"
