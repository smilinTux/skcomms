"""
SKComms router — the brain that picks how to deliver.

Decides which transport(s) to use based on routing mode,
transport priority, health status, and peer configuration.
Handles failover, broadcast, and retry logic.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import OrderedDict
from typing import Optional

from .envelope import SignedEnvelope
from .models import MessageEnvelope, MessagePayload, RoutingConfig, RoutingMode
from .ratelimit import RateLimiter
from .transport import (
    DeliveryReport,
    SendResult,
    Transport,
    TransportCategory,
    TransportError,
    TransportStatus,
)

logger = logging.getLogger("skcomms.router")

# Failure tracking defaults
FAILURE_THRESHOLD = 3  # consecutive failures before cooldown
COOLDOWN_SECONDS = 60.0  # seconds to skip a transport after repeated failures

# Rails that address a single, specific peer and therefore cannot serve a
# ``recipient == "*"`` broadcast (they need a concrete inbox_url / IP). Offering
# them for a ``*`` heartbeat turned into a peer-store lookup for the literal
# name ``"*"`` (``Peer name '*' is empty after sanitization``) plus a paired
# WARNING every ~60s (RC3). For a broadcast we drop them from candidates so the
# broadcast only ever reaches relay/file rails that can actually fan out.
POINT_TO_POINT_TRANSPORTS = frozenset({"https-s2s", "tailscale"})

# Growing backoff for structurally-undeliverable (perm: / '*') attempts (RC2).
# These never arm the transient cooldown (that would starve OTHER, deliverable
# recipients on a healthy rail), but without any backoff they repeat — and log —
# every cycle. The window doubles per consecutive failure of the same
# (rail, recipient) pair, capped, so a rail that keeps perm-failing to one
# recipient stops being re-attempted for that recipient for a growing interval.
PERM_BACKOFF_BASE_SECONDS = 60.0
PERM_BACKOFF_MAX_SECONDS = 3600.0

# Startup health-gate re-probe cadence (RC4). A rail quarantined at startup
# (enabled but its ``health_check`` reported UNAVAILABLE) is re-probed at most
# this often during selection; a passing probe releases it back into routing.
QUARANTINE_REPROBE_SECONDS = 300.0

# Matches an HTTP 4xx status reported in a rail's error string (e.g. the
# https-s2s rail's ``perm: HTTP 422 ...``) so the observability counters can
# separate client-side rejections (bad/blocked payloads) from rail health.
_HTTP_4XX_RE = re.compile(r"HTTP 4\d\d\b")

# Federation default rail chain (by transport name). Used to order candidate
# transports when a peer advertises no explicit rail order. Rails not named
# here fall to the back, ordered by their global priority.
FEDERATION_DEFAULT_CHAIN = [
    "https-s2s",
    "tailscale",
    "nostr",
    "ble",
    "lora",
    "telegram",
    "file",
]

# Rails whose receiving endpoint only accepts a signed wire format (e.g.
# https-s2s's ``POST /api/v1/inbox`` hard-requires a ``SignedEnvelope`` —
# see ``api.py::post_inbox``, ``SignedEnvelope.from_bytes`` -> 422 on anything
# else). ``Router.route()`` is the LEGACY/unsigned ``MessageEnvelope`` path
# (used by ``Comm.send()`` for heartbeats, typing indicators, and any
# non-federated send) and serializes a plain ``MessageEnvelope`` — never a
# ``SignedEnvelope`` — so offering one of these rails as a candidate there is
# a guaranteed, 100%-reproducible permanent failure, not a real fallback
# option. The SIGNED federation path (``route_bytes``/``route_signed``, which
# puts real ``SignedEnvelope`` bytes on the wire) is unaffected — these rails
# stay full candidates there.
SIGNED_ENVELOPE_ONLY_TRANSPORTS = frozenset({"https-s2s"})

# Designated store-and-forward fallback rail. Tried last, after every direct
# rail has failed, as the final in-band delivery attempt (durable retry beyond
# that is owned by the caller's federation outbox). This is the
# SKFed P4 Nostr-relay S&F rail (``skcomms.store_forward.StoreForwardTransport``,
# name ``"nostr-sf"``): it resolves the recipient fqid→Nostr pubkey, encrypts the
# signed envelope to that pubkey (untrusted public relay), and publishes it for
# the offline recipient to pull. Excluded from DIRECT candidate selection — it is
# only ever invoked by ``_try_store_forward``.
DEFAULT_STORE_FORWARD_TRANSPORT = "nostr-sf"

# Deduplication cache limit
SEEN_IDS_MAX = 10_000

# Upper bound on the per-(rail, recipient) perm-backoff map. Entries are only
# dropped on a subsequent success, so a stream of permanently-undeliverable
# recipients (e.g. a broadcast fanned to many transient fqids) would otherwise
# leak forever. Mirrors SEEN_IDS_MAX: TTL-evict dead entries (past the max
# backoff window they no longer affect selection) then LRU-cap the remainder.
PERM_BACKOFF_MAX_ENTRIES = 10_000


class Router:
    """Transport router with multi-mode delivery and automatic failover.

    Supports four routing modes:
    - failover: try transports in priority order, stop on first success
    - broadcast: send via ALL available transports simultaneously
    - stealth: use only high-stealth transports (file, dns_txt, ipfs)
    - speed: use only low-latency transports (netcat, tailscale, iroh)

    Tracks consecutive send failures per transport. After
    ``FAILURE_THRESHOLD`` failures a transport enters a cooldown period
    (``COOLDOWN_SECONDS``) during which it is temporarily skipped.

    Args:
        transports: List of configured Transport instances.
        default_mode: Fallback routing mode when envelope doesn't specify.
        store_forward_transport: Name of the last-resort S&F rail.
        rate_limiter: Optional outbound :class:`~skcomms.ratelimit.RateLimiter`
            (coord 74d7b799). When set, EVERY send attempt (route/route_bytes/
            route_signed, retries, broadcasts, store-and-forward) passes
            through it in :meth:`_try_send`; throttled attempts fail fast with
            a ``throttled:`` error and never reach the transport, so a backlog
            flush or presence broadcast is paced instead of flooding a peer.
            ``None`` (default) keeps the historical unthrottled behavior for
            directly constructed routers; :class:`skcomms.core.SKComms` wires
            one in from config.
    """

    STEALTH_CATEGORIES = {TransportCategory.STEALTH, TransportCategory.FILE_BASED}
    SPEED_CATEGORIES = {TransportCategory.REALTIME}

    def __init__(
        self,
        transports: Optional[list[Transport]] = None,
        default_mode: RoutingMode = RoutingMode.FAILOVER,
        store_forward_transport: str = DEFAULT_STORE_FORWARD_TRANSPORT,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self._transports: list[Transport] = transports or []
        self._default_mode = default_mode
        self._rate_limiter = rate_limiter
        # Name of the designated store-and-forward fallback rail. When all
        # direct rails fail this rail is tried last (if available + not in
        # cooldown) as the final in-band delivery attempt.
        self._store_forward_transport = store_forward_transport
        self._seen_ids: OrderedDict[str, float] = OrderedDict()
        self._seen_ttl = 7 * 24 * 3600  # 7 days

        # Failure tracking: {transport_name: (consecutive_fail_count, last_fail_time)}
        self._transport_failures: dict[str, tuple[int, float]] = {}

        # Cumulative, observability-only failure counters (distinct from the
        # consecutive-failure cooldown state above, which resets on any
        # success). These monotonically count EVERY failed send attempt per
        # rail, plus the subset that were 4xx rejections (e.g. the inbox gate
        # 422ing a non-signed payload), so GET /api/v1/status and /metrics can
        # surface per-rail failure totals that the cooldown state cannot.
        # {transport_name: {"failures": int, "http_4xx": int, "last_error": str}}
        self._failure_counters: dict[str, dict] = {}

        # Log-once-per-state-change dedup (RC2). Set of (channel, name,
        # recipient, error-signature) tuples currently "active": the first time a
        # given (rail, recipient, failure-mode) triple fails it WARNs and is
        # recorded here; identical repeats drop to DEBUG. Cleared (with one
        # recovery line) when the rail next succeeds. ``channel`` is "send" or
        # "recv" (recv uses recipient="").
        self._active_failure_sigs: set[tuple[str, str, str, str]] = set()

        # Growing per-(rail, recipient) backoff for perm:/'*' failures (RC2):
        # {(transport_name, recipient): (consecutive_count, last_fail_monotonic)}.
        self._perm_backoff: dict[tuple[str, str], tuple[int, float]] = {}

        # Startup health-gate quarantine (RC4): {transport_name: last_probe_ts}.
        # A quarantined rail is skipped by _select_transports until a periodic
        # re-probe of its health_check() passes.
        self._quarantined: dict[str, float] = {}

    @property
    def transports(self) -> list[Transport]:
        """All registered transports, sorted by priority."""
        return sorted(self._transports, key=lambda t: t.priority)

    def register_transport(self, transport: Transport) -> None:
        """Add a transport to the routing table.

        Args:
            transport: A configured Transport instance.
        """
        existing = next((t for t in self._transports if t.name == transport.name), None)
        if existing:
            self._transports.remove(existing)
        self._transports.append(transport)
        logger.info(
            "Registered transport '%s' (priority=%d, category=%s)",
            transport.name,
            transport.priority,
            transport.category.value,
        )

    def unregister_transport(self, name: str) -> bool:
        """Remove a transport from the routing table.

        Args:
            name: Transport name to remove.

        Returns:
            True if the transport was found and removed.
        """
        before = len(self._transports)
        self._transports = [t for t in self._transports if t.name != name]
        removed = len(self._transports) < before
        if removed:
            logger.info("Unregistered transport '%s'", name)
        return removed

    def route(self, envelope: MessageEnvelope) -> DeliveryReport:
        """Route an envelope through the appropriate transport(s).

        Selects transports based on the envelope's routing mode,
        filters by availability, and handles delivery with retry.

        Args:
            envelope: The message envelope to deliver.

        Returns:
            DeliveryReport with all attempt results.
        """
        mode = envelope.routing.mode or self._default_mode
        report = DeliveryReport(envelope_id=envelope.envelope_id, delivered=False)

        # This is the unsigned/legacy MessageEnvelope path — exclude rails
        # that require a SignedEnvelope on the wire (see
        # SIGNED_ENVELOPE_ONLY_TRANSPORTS above).
        candidates = self._select_transports(mode, envelope, exclude_signed_only=True)
        envelope_bytes = envelope.to_bytes()

        if not candidates:
            # No DIRECT rails — fall through to the store-and-forward fallback
            # rather than giving up immediately.
            logger.warning(
                "No direct transports for envelope %s (mode=%s)",
                envelope.envelope_id[:8],
                mode.value,
            )
        elif mode == RoutingMode.BROADCAST:
            report = self._route_broadcast(envelope_bytes, envelope, candidates, report)
        else:
            report = self._route_failover(envelope_bytes, envelope, candidates, report)

        # Store-and-forward fallback: when every direct rail failed, try the
        # designated S&F rail (default "nostr") as a last in-band resort.
        # Skipped if it was already a candidate (and thus already attempted)
        # above.
        if not report.delivered:
            report = self._try_store_forward(envelope_bytes, envelope, candidates, report)

        if report.delivered:
            logger.info(
                "Delivered %s via %s",
                envelope.envelope_id[:8],
                report.successful_transport,
            )
        else:
            # Durable retry is owned by the caller's federation outbox
            # (skcomms.outbox.PersistentOutbox is the single queue of record),
            # so route() no longer persists anything of its own here.
            logger.warning(
                "Failed to deliver %s after %d attempts",
                envelope.envelope_id[:8],
                len(report.attempts),
            )

        return report

    def route_bytes(
        self,
        envelope_bytes: bytes,
        recipient: str,
        *,
        envelope_id: str = "",
        sender: str = "skfed-router",
        preferred_transports: Optional[list[str]] = None,
        mode: Optional[RoutingMode] = None,
    ) -> DeliveryReport:
        """Best-effort deliver pre-serialized wire bytes to ``recipient``.

        The federation send path: the caller supplies the EXACT wire bytes
        (a :class:`~skcomms.envelope.SignedEnvelope`) and owns durability/retry
        (the federation outbox is authoritative — see ``outbox.py``). This does
        rail selection (peer-advertised order or the federation default chain)
        → failover → store-and-forward fallback, and returns the report. Like
        :meth:`route`, the router itself persists nothing on failure: durable
        retry belongs entirely to the caller's federation outbox.

        Args:
            envelope_bytes: The exact bytes to put on the wire (e.g.
                ``SignedEnvelope.to_bytes()``).
            recipient: Recipient address used for rail resolution (fqid/name).
            envelope_id: Stable id for dedup/reporting (the inner Envelope id).
            sender: Sender address (informational; not on the wire).
            preferred_transports: Peer-advertised ordered rail list.
            mode: Routing mode override (default the router's default).

        Returns:
            DeliveryReport for this attempt.
        """
        mode = mode or self._default_mode
        carrier = MessageEnvelope(
            envelope_id=envelope_id or "",
            sender=sender,
            recipient=recipient,
            payload=MessagePayload(content=""),
            routing=RoutingConfig(mode=mode, preferred_transports=preferred_transports or []),
        )
        report = DeliveryReport(envelope_id=carrier.envelope_id, delivered=False)
        candidates = self._select_transports(mode, carrier)
        if not candidates:
            # No DIRECT rails — but the store-and-forward fallback may still be
            # able to defer the envelope (offline recipient), so don't give up
            # before trying it.
            logger.warning("No direct rails for %s (mode=%s)", recipient, mode.value)
        elif mode == RoutingMode.BROADCAST:
            # Honor broadcast semantics for signed bytes too (sign-at-send
            # callers pass the same routing modes route() supported).
            report = self._route_broadcast(envelope_bytes, carrier, candidates, report)
        else:
            report = self._route_failover(envelope_bytes, carrier, candidates, report)
        if not report.delivered:
            report = self._try_store_forward(envelope_bytes, carrier, candidates, report)
        return report

    def route_signed(
        self,
        signed: SignedEnvelope,
        *,
        preferred_transports: Optional[list[str]] = None,
        mode: Optional[RoutingMode] = None,
        pqroute: Optional[bool] = None,
        dest_hybrid_pub: Optional[bytes] = None,
        next_hop: Optional[str] = None,
        pqroute_flags: Optional[list[str]] = None,
        pqroute_pad: bool = True,
    ) -> DeliveryReport:
        """Route a canonical :class:`SignedEnvelope` to its ``to_fqid``.

        The signed envelope's own bytes go on the wire verbatim (so the remote
        node's ``POST /inbox`` parses the same ``SignedEnvelope`` and verifies
        it). Rail order comes from ``preferred_transports`` (peer-advertised) or
        the federation default chain.

        **Opt-in pqroute (P3) metadata-sealing** — additive + flag-gated. When
        ``pqroute`` resolves enabled (per :func:`skcomms.pqroute_transport.pqroute_enabled`,
        e.g. ``SKCOMMS_PQROUTE=1`` or ``pqroute=True``) AND a destination hybrid
        prekey (``dest_hybrid_pub``) and ``next_hop`` relay are supplied, the
        FINAL destination FQID + flags + the whole signed envelope are
        hybrid-sealed into the wire blob and only the ``next_hop`` stays
        relay-readable; the envelope is then routed to ``next_hop`` (the relay)
        instead of directly to ``to_fqid``. Default OFF / missing prekey -> the
        exact verbatim-bytes behaviour above (byte-for-byte unchanged).

        When the pqroute path is taken, the body is additionally length-hidden
        with the P2 size-class padding ladder *under* the seal (``pqroute_pad``,
        default ``True``) so the on-wire length leaks only a coarse size class.
        Set ``pqroute_pad=False`` to keep the un-padded wrapped form. The OFF
        path is unaffected (no padding, byte-for-byte unchanged).
        """
        env = signed.envelope

        # Default path: nothing new on the wire (verbatim signed bytes to to_fqid).
        from .pqroute_transport import pqroute_enabled, wrap_signed

        if pqroute_enabled(pqroute) and dest_hybrid_pub and next_hop:
            wire = wrap_signed(
                signed,
                next_hop=next_hop,
                dest_hybrid_pub=dest_hybrid_pub,
                enabled=True,
                flags=pqroute_flags,
                pad=pqroute_pad,
            )
            # The relay only ever sees / resolves the next hop — the final
            # destination is sealed inside the blob.
            return self.route_bytes(
                wire,
                next_hop,
                envelope_id=env.id,
                sender=env.from_fqid,
                preferred_transports=preferred_transports,
                mode=mode,
            )

        return self.route_bytes(
            signed.to_bytes(),
            env.to_fqid,
            envelope_id=env.id,
            sender=env.from_fqid,
            preferred_transports=preferred_transports,
            mode=mode,
        )

    def route_anon(
        self,
        payload: bytes,
        aqid: str,
        secret: bytes,
        *,
        enabled: Optional[bool] = None,
        nonce: Optional[bytes] = None,
        preferred_transports: Optional[list[str]] = None,
        mode: Optional[RoutingMode] = None,
    ) -> DeliveryReport:
        """Send ``payload`` to a no-identity ``aqid:`` address (RFC-0001 P5).

        The **anonymous** send path: composes the vetted
        :mod:`skcomms.anon_transport` framing (opaque ``aqid`` addressing +
        deniable HMAC auth + length-padding) with the existing rail-selection /
        failover / store-forward machinery via :meth:`route_bytes`. The opaque
        anon frame goes on the wire addressed to the **relay** decoded from the
        ``aqid``; there is NO fqid, DID, public key, or fingerprint anywhere on
        the wire — the relay routes only on the opaque ``sender_id``.

        **Flag-gated (additive guarantee).** This is a brand-new method that
        does not touch the classical / sovereign / pqroute paths, so those stay
        byte-identical. Within this method the gate is enforced by
        :func:`skcomms.anon_transport.frame_anon`: with anon OFF (no
        ``enabled=True`` and ``SKCOMMS_ANON`` unset/falsey) it raises
        :class:`~skcomms.anon_transport.AnonDisabledError` and nothing is emitted.

        **Confidentiality is composed, not provided here.** This layer does NOT
        encrypt ``payload`` — a relay sees the padded body bytes. Pass an
        ALREADY-sealed body (e.g. a hybrid X25519 || ML-KEM-768 ciphertext from
        :mod:`skcomms.pqdm`/:mod:`skcomms.pqkem`, FIPS 203 — confidential if
        EITHER leg holds; no "quantum-proof" claim) for end-to-end secrecy. The
        deniable MAC gives authenticity + repudiation, never non-repudiation.

        Durability, like :meth:`route_bytes`, is the caller's (no retry-queue
        enqueue here): an anon frame carries no envelope identity to dedup on.

        Args:
            payload: The opaque (ideally already-sealed) body bytes to frame.
            aqid: The recipient's published ``aqid:<relay>/<id>`` address.
            secret: The shared per-queue deniable-auth secret (out-of-band).
            enabled: Per-call override of the anon flag gate.
            nonce: Optional explicit per-frame nonce (defaults to fresh CSPRNG).
            preferred_transports: Peer-advertised ordered rail list.
            mode: Routing-mode override (default the router's default).

        Returns:
            DeliveryReport for this attempt (routed to the relay).

        Raises:
            AnonDisabledError: the anon flag gate is OFF.
            AnonFrameError: malformed ``aqid`` / ``secret`` / ``nonce``.
        """
        from .anon_transport import AnonChannel

        chan = AnonChannel.from_address(aqid, secret)
        # frame_anon (via seal) raises AnonDisabledError when the gate is OFF, so
        # nothing reaches the transport unless anon was intentionally turned on.
        wire = chan.seal(payload, nonce=nonce, enabled=enabled)
        # The relay is the only address on the wire — never an fqid/identity.
        return self.route_bytes(
            wire,
            chan.relay,
            envelope_id="",
            sender="aqid",
            preferred_transports=preferred_transports,
            mode=mode,
        )

    @staticmethod
    def is_anon_inbound(wire: bytes) -> bool:
        """True iff ``wire`` is an anon frame (carries the anon magic prefix).

        Lets a receiver cleanly dispatch an inbound anon frame apart from a
        plain JSON ``SignedEnvelope`` or a ``pqroute1`` blob before parsing.
        """
        from .anon_transport import is_anon_frame

        return is_anon_frame(wire)

    def parse_anon_inbound(
        self,
        wire: bytes,
        secret: bytes,
        *,
        expected_sender_id: Optional[bytes] = None,
    ):
        """Parse + deniably-authenticate an inbound anon frame.

        Delegates to :func:`skcomms.anon_transport.parse_anon`: recomputes the
        deniable HMAC tag (constant-time), rejects on mismatch, and unpads back
        to the exact opaque ``payload``. Parsing is **ungated** — a recipient
        that opted into anon mode must be able to read what it receives.

        Args:
            wire: The inbound anon-frame bytes.
            secret: The shared per-queue deniable-auth secret.
            expected_sender_id: If given, the frame's routing id MUST equal it
                (a wrong-queue frame is rejected before the body is touched).

        Returns:
            :class:`skcomms.anon_transport.AnonFrame` — opaque ``sender_id`` and
            recovered ``payload``.

        Raises:
            AnonFrameError: malformed/truncated frame or wrong-queue id.
            AnonAuthError: the deniable tag does not verify (wrong secret /
                tampered frame).
        """
        from .anon_transport import parse_anon

        return parse_anon(wire, secret, expected_sender_id=expected_sender_id)

    def receive_all(self) -> list[bytes]:
        """Poll all transports for incoming envelopes.

        Returns:
            List of raw envelope bytes from all transports,
            deduplicated by envelope_id.
        """
        self._prune_seen_ids()
        all_data: list[bytes] = []

        for transport in self.transports:
            if not transport.is_available():
                continue
            try:
                incoming = transport.receive()
                for data in incoming:
                    env_id = self._extract_envelope_id(data)
                    if env_id and env_id in self._seen_ids:
                        logger.debug(
                            "Duplicate envelope %s via %s — skipping",
                            env_id[:8],
                            transport.name,
                        )
                        continue
                    if env_id:
                        self._seen_ids[env_id] = time.time()
                        self._seen_ids.move_to_end(env_id)
                    all_data.append(data)
                # A clean poll clears any receive-side failing state and logs a
                # single recovery line (mirrors the send-side dedup).
                if self._clear_failure_state("recv", transport.name):
                    logger.info("Transport '%s' receive recovered", transport.name)
            except Exception as exc:
                # Log once on transition into the failing state, DEBUG while the
                # same failure repeats (RC2, receive-side mirror of _try_send).
                warn = self._note_failure_and_should_warn("recv", transport.name, str(exc))
                (logger.warning if warn else logger.debug)(
                    "Error receiving from transport '%s': %s", transport.name, exc
                )
                self._record_failure(transport.name)

        return all_data

    def health_report(self) -> dict[str, dict]:
        """Get health status of all registered transports.

        Returns:
            Dict mapping transport name to health info.
        """
        report = {}
        for transport in self.transports:
            try:
                health = transport.health_check()
                report[transport.name] = health.model_dump(mode="json")
            except Exception as exc:
                logger.warning("Health check failed for transport '%s': %s", transport.name, exc)
                report[transport.name] = {
                    "transport_name": transport.name,
                    "status": "unavailable",
                    "error": str(exc),
                }
        return report

    def _is_in_cooldown(self, transport_name: str) -> bool:
        """Check whether a transport is in failure cooldown.

        Args:
            transport_name: Name of the transport to check.

        Returns:
            True if the transport has exceeded the failure threshold and
            the cooldown period has not yet elapsed.
        """
        entry = self._transport_failures.get(transport_name)
        if entry is None:
            return False
        fail_count, last_fail = entry
        if fail_count < FAILURE_THRESHOLD:
            return False
        return (time.monotonic() - last_fail) < COOLDOWN_SECONDS

    def _select_transports(
        self,
        mode: RoutingMode,
        envelope: MessageEnvelope,
        *,
        exclude_signed_only: bool = False,
    ) -> list[Transport]:
        """Filter and order transports for the given routing mode.

        Ordering precedence (federation rail selection):
        1. **Peer-advertised ordered rail list** — when the envelope carries
           ``routing.preferred_transports``, that order is honored *strictly*.
           The named rails lead, in exactly the order given; any remaining
           available rails follow, ordered by the federation default chain.
        2. **Federation default chain** — when the peer advertises no order,
           rails are ordered by :data:`FEDERATION_DEFAULT_CHAIN` (by name),
           with un-named rails appended by global priority.

        Transports in failure cooldown (and, for stealth/speed modes, rails of
        the wrong category) are excluded from candidates.

        Args:
            mode: The routing mode to apply.
            envelope: The envelope being routed (carries the peer-advertised
                ordered rail list in ``routing.preferred_transports``).
            exclude_signed_only: When True, drop rails in
                :data:`SIGNED_ENVELOPE_ONLY_TRANSPORTS` from candidates. Set by
                :meth:`route` (the unsigned/legacy path) — never by the signed
                federation path (``route_bytes``/``route_signed``), which puts
                a real ``SignedEnvelope`` on the wire and so those rails work.

        Returns:
            Ordered list of eligible, available transports.
        """
        # Re-probe any quarantined rails whose re-probe window has elapsed, so a
        # rail that has recovered can rejoin selection (RC4).
        self._maybe_reprobe_quarantine()

        recipient = envelope.recipient
        available = [
            t
            for t in self._transports
            if t.is_available()
            and not self._is_in_cooldown(t.name)
            # The designated store-and-forward rail is NEVER a direct candidate;
            # it is reserved for the _try_store_forward last-resort fallback.
            and t.name != self._store_forward_transport
            and not (exclude_signed_only and t.name in SIGNED_ENVELOPE_ONLY_TRANSPORTS)
            # Startup health-gate: an enabled-but-unreachable rail stays out of
            # selection until a periodic re-probe passes (RC4).
            and t.name not in self._quarantined
            # Structurally-undeliverable (perm:/'*') rails are backed off per
            # recipient within a growing window instead of retried every cycle
            # (RC2).
            and not self._in_perm_backoff(t.name, recipient)
        ]

        # A '*' broadcast can only be served by relay/file rails that fan out;
        # point-to-point rails need a concrete peer and would turn '*' into a
        # bad peer-store lookup, so drop them here (RC3).
        if recipient == "*":
            available = [t for t in available if t.name not in POINT_TO_POINT_TRANSPORTS]

        if mode == RoutingMode.STEALTH:
            available = [t for t in available if t.category in self.STEALTH_CATEGORIES]
        elif mode == RoutingMode.SPEED:
            available = [t for t in available if t.category in self.SPEED_CATEGORIES]

        preferred = envelope.routing.preferred_transports
        if preferred:
            # Reason: respect the peer-advertised rail ORDER exactly — the peer
            # knows which rails it is reachable on and in what preference. We do
            # not re-sort the advertised rails by our own global priority.
            by_name = {t.name: t for t in available}
            ordered: list[Transport] = []
            seen: set[str] = set()
            for name in preferred:
                t = by_name.get(name)
                if t is not None and t.name not in seen:
                    ordered.append(t)
                    seen.add(t.name)
            # Remaining available rails (not advertised) follow as fallbacks,
            # ordered by the federation default chain.
            rest = [t for t in available if t.name not in seen]
            return ordered + self._order_by_default_chain(rest)

        # No peer-advertised order → federation default chain.
        return self._order_by_default_chain(available)

    @staticmethod
    def _order_by_default_chain(transports: list[Transport]) -> list[Transport]:
        """Order transports by the federation default chain, then priority.

        Rails named in :data:`FEDERATION_DEFAULT_CHAIN` lead, in chain order;
        rails not in the chain follow, ordered by ascending global priority.

        Args:
            transports: The transports to order.

        Returns:
            A new, ordered list.
        """
        chain_index = {name: i for i, name in enumerate(FEDERATION_DEFAULT_CHAIN)}
        in_chain = [t for t in transports if t.name in chain_index]
        out_of_chain = [t for t in transports if t.name not in chain_index]
        in_chain.sort(key=lambda t: chain_index[t.name])
        out_of_chain.sort(key=lambda t: t.priority)
        return in_chain + out_of_chain

    def _route_failover(
        self,
        envelope_bytes: bytes,
        envelope: MessageEnvelope,
        candidates: list[Transport],
        report: DeliveryReport,
    ) -> DeliveryReport:
        """Try transports in priority order, stop on first success."""
        for transport in candidates:
            result = self._try_send(transport, envelope_bytes, envelope.recipient)
            report.attempts.append(result)
            if result.success:
                report.delivered = True
                break
        return report

    def _route_broadcast(
        self,
        envelope_bytes: bytes,
        envelope: MessageEnvelope,
        candidates: list[Transport],
        report: DeliveryReport,
    ) -> DeliveryReport:
        """Send via ALL available transports simultaneously."""
        for transport in candidates:
            result = self._try_send(transport, envelope_bytes, envelope.recipient)
            report.attempts.append(result)
            if result.success:
                report.delivered = True
        return report

    def _try_store_forward(
        self,
        envelope_bytes: bytes,
        envelope: MessageEnvelope,
        candidates: list[Transport],
        report: DeliveryReport,
    ) -> DeliveryReport:
        """Last-resort store-and-forward fallback after all direct rails fail.

        Attempts delivery via the designated store-and-forward rail
        (``self._store_forward_transport``, default "nostr"). The Nostr relay
        rail holds the signed envelope for an offline/NAT'd recipient to pull
        later — turning a hard failure into a deferred delivery.

        The rail is tried only if it is registered, available, not in cooldown,
        and was not already among the ``candidates`` attempted above (so we
        never double-send on the same rail).

        Args:
            envelope_bytes: Serialized envelope to deliver.
            envelope: The envelope being routed (for recipient).
            candidates: The direct rails already attempted this route.
            report: The delivery report to append the attempt to.

        Returns:
            The (possibly updated) delivery report.
        """
        sf_name = self._store_forward_transport
        if not sf_name:
            return report

        # Don't re-attempt a rail that was already tried as a direct candidate.
        already_tried = {t.name for t in candidates}
        if sf_name in already_tried:
            return report

        sf = next((t for t in self._transports if t.name == sf_name), None)
        if (
            sf is None
            or not sf.is_available()
            or self._is_in_cooldown(sf.name)
            # Honor the startup health-gate like _select_transports: a quarantined
            # rail (unreachable at startup, awaiting a passing re-probe) must not
            # be used as the store-and-forward fallback either.
            or sf.name in self._quarantined
        ):
            return report

        logger.info(
            "All direct rails failed for %s — attempting store-and-forward via '%s'",
            envelope.envelope_id[:8],
            sf_name,
        )
        result = self._try_send(sf, envelope_bytes, envelope.recipient)
        report.attempts.append(result)
        if result.success:
            report.delivered = True
        return report

    def _record_failure(self, transport_name: str) -> None:
        """Increment the consecutive failure counter for a transport.

        After ``FAILURE_THRESHOLD`` consecutive failures a warning is
        logged and the transport enters cooldown.  Each subsequent failure
        beyond the threshold is logged at ERROR to ensure repeated
        breakdowns remain visible.

        Args:
            transport_name: Name of the transport that failed.
        """
        prev = self._transport_failures.get(transport_name, (0, 0.0))
        new_count = prev[0] + 1
        now = time.monotonic()
        self._transport_failures[transport_name] = (new_count, now)
        if new_count == FAILURE_THRESHOLD:
            logger.warning(
                "Transport '%s' hit %d consecutive failures — entering %.0fs cooldown",
                transport_name,
                FAILURE_THRESHOLD,
                COOLDOWN_SECONDS,
            )
        elif new_count > FAILURE_THRESHOLD:
            logger.error(
                "Transport '%s' has now failed %d consecutive times "
                "(threshold=%d) — still in cooldown",
                transport_name,
                new_count,
                FAILURE_THRESHOLD,
            )

    def _record_success(self, transport_name: str) -> None:
        """Reset the failure counter for a transport after a successful send.

        Also clears any send-side log-dedup state for the rail and, if it was
        in a failing state, emits a single recovery line so a rail coming back
        is visible without the per-cycle WARNING storm it replaces (RC2).

        Args:
            transport_name: Name of the transport that succeeded.
        """
        self._transport_failures.pop(transport_name, None)
        if self._clear_failure_state("send", transport_name):
            logger.info("Transport '%s' send recovered", transport_name)

    @staticmethod
    def _error_signature(error: Optional[str]) -> str:
        """Collapse a failure's error string to a stable per-failure-mode key.

        Quoted names (recipients) and numbers (ports, status codes, ids) are
        normalized away so repeated failures of the SAME mode share one
        signature (and dedup to a single WARNING), while a genuinely different
        failure mode gets its own signature (and its own WARNING).

        Args:
            error: The failure's error string (may be ``None``).

        Returns:
            A short, stable signature string.
        """
        if not error:
            return "unknown"
        sig = re.sub(r"'[^']*'", "'*'", str(error))
        sig = re.sub(r"\d+", "N", sig)
        return sig[:120]

    def _note_failure_and_should_warn(
        self,
        channel: str,
        transport_name: str,
        error: Optional[str],
        recipient: str = "",
    ) -> bool:
        """Record a failure and decide whether it is WARN-worthy (vs DEBUG).

        Returns ``True`` only on the transition INTO a failing state for this
        ``(channel, transport, recipient, error-signature)`` — i.e. the first
        time this exact failure mode is seen for this recipient while not already
        active. Identical repeats return ``False`` (log at DEBUG). A new/different
        failure signature for the same rail — OR the same signature for a NEW
        recipient — returns ``True`` again.

        The recipient is part of the key because :meth:`_error_signature`
        normalizes quoted names and numbers away, which otherwise collapses
        distinct recipients (``'alice'`` vs ``'bob'``) into one signature and
        silently DEBUG-suppresses the first genuine failure to a new peer on an
        already-warned rail.

        Args:
            channel: ``"send"`` or ``"recv"`` (kept distinct so the two paths
                dedup independently).
            transport_name: The failing rail.
            error: The failure's error string.
            recipient: The send recipient (``""`` for the receive path, which is
                not recipient-scoped).

        Returns:
            Whether the caller should log at WARNING (else DEBUG).
        """
        key = (channel, transport_name, recipient, self._error_signature(error))
        if key in self._active_failure_sigs:
            return False
        self._active_failure_sigs.add(key)
        return True

    def _clear_failure_state(self, channel: str, transport_name: str) -> bool:
        """Clear a rail's active failing-log state for a channel.

        Args:
            channel: ``"send"`` or ``"recv"``.
            transport_name: The rail whose failing state to clear.

        Returns:
            ``True`` if the rail HAD an active failing state (so the caller can
            emit a single recovery line), else ``False``.
        """
        before = len(self._active_failure_sigs)
        self._active_failure_sigs = {
            k
            for k in self._active_failure_sigs
            if not (k[0] == channel and k[1] == transport_name)
        }
        return len(self._active_failure_sigs) < before

    def _record_perm_backoff(self, transport_name: str, recipient: str) -> None:
        """Arm/extend the growing backoff for a perm:/'*' failure (RC2).

        Args:
            transport_name: The rail that structurally failed.
            recipient: The recipient it could not deliver to (the backoff is
                scoped per recipient so OTHER recipients stay unaffected).
        """
        count, _ = self._perm_backoff.get((transport_name, recipient), (0, 0.0))
        self._perm_backoff[(transport_name, recipient)] = (count + 1, time.monotonic())
        self._prune_perm_backoff()

    def _prune_perm_backoff(self) -> None:
        """Bound the perm-backoff map (TTL + size), mirroring _prune_seen_ids.

        Entries are normally dropped only on a subsequent success, so
        never-succeeding recipients would accumulate without bound. First evict
        entries older than the max backoff window (past it they no longer gate
        selection anyway), then LRU-cap to :data:`PERM_BACKOFF_MAX_ENTRIES` by
        dropping the oldest-by-last-failure entries.
        """
        now = time.monotonic()
        expired = [
            key
            for key, (_, last) in self._perm_backoff.items()
            if now - last > PERM_BACKOFF_MAX_SECONDS
        ]
        for key in expired:
            del self._perm_backoff[key]
        overflow = len(self._perm_backoff) - PERM_BACKOFF_MAX_ENTRIES
        if overflow > 0:
            for key in sorted(
                self._perm_backoff, key=lambda k: self._perm_backoff[k][1]
            )[:overflow]:
                del self._perm_backoff[key]

    def _in_perm_backoff(self, transport_name: str, recipient: str) -> bool:
        """Whether a rail is inside its growing backoff window for a recipient.

        Args:
            transport_name: The rail to check.
            recipient: The recipient (backoff is per-recipient).

        Returns:
            ``True`` while the doubling backoff window has not yet elapsed.
        """
        entry = self._perm_backoff.get((transport_name, recipient))
        if not entry:
            return False
        count, last = entry
        window = min(
            PERM_BACKOFF_BASE_SECONDS * (2 ** max(0, count - 1)),
            PERM_BACKOFF_MAX_SECONDS,
        )
        return (time.monotonic() - last) < window

    def quarantine_transport(self, transport_name: str) -> None:
        """Mark a rail as quarantined (skipped by selection until a re-probe).

        Called by :meth:`skcomms.core.SKComms.from_config` for a rail whose
        startup ``health_check`` reported UNAVAILABLE (RC4), so an enabled-but-
        unreachable rail is not retried (and logged) every cycle.

        Args:
            transport_name: The rail to quarantine.
        """
        self._quarantined[transport_name] = time.monotonic()
        logger.debug("Transport '%s' quarantined (unreachable at startup)", transport_name)

    def _maybe_reprobe_quarantine(self) -> None:
        """Re-probe quarantined rails whose re-probe window has elapsed (RC4).

        For each quarantined rail past :data:`QUARANTINE_REPROBE_SECONDS` since
        its last probe, call ``health_check()`` best-effort: an AVAILABLE result
        releases it back into routing; anything else (or a missing/raising
        ``health_check``) keeps it quarantined with the probe timestamp bumped.
        Never raises.
        """
        if not self._quarantined:
            return
        now = time.monotonic()
        for transport in list(self._transports):
            last = self._quarantined.get(transport.name)
            if last is None or (now - last) < QUARANTINE_REPROBE_SECONDS:
                continue
            self._quarantined[transport.name] = now
            try:
                health = transport.health_check()
            except Exception as exc:  # noqa: BLE001 - probe must never break selection
                logger.debug("Quarantine re-probe failed for '%s': %s", transport.name, exc)
                continue
            if getattr(health, "status", None) == TransportStatus.AVAILABLE:
                self._quarantined.pop(transport.name, None)
                logger.info(
                    "Transport '%s' passed re-probe — leaving quarantine", transport.name
                )

    @staticmethod
    def _is_http_4xx(error: Optional[str]) -> bool:
        """Return whether an error string reports an HTTP 4xx rejection.

        The https-s2s rail formats 4xx failures as ``perm: HTTP 4NN ...`` (see
        :meth:`skcomms.transports.http_s2s.HttpS2STransport._failure`), and its
        local structural gate refuses non-SignedEnvelope payloads that "the
        inbox gate would 422". Both are counted as 4xx so the 422-per-rail
        counter surfaces payload/authorization rejections separately from
        transient rail health problems.
        """
        if not error:
            return False
        return bool(_HTTP_4XX_RE.search(error)) or "would 422 it" in error

    def _count_failure(self, transport_name: str, error: Optional[str]) -> None:
        """Increment the cumulative, observability-only failure counters.

        Counts EVERY failed send (unlike :meth:`_record_failure`, which is
        skipped for permanent/broadcast failures to protect the cooldown), and
        separately counts the 4xx subset. Purely additive: never affects
        routing, cooldown, or send semantics.

        Args:
            transport_name: Rail whose send failed.
            error: The failure's error string, used to classify 4xx.
        """
        stats = self._failure_counters.get(transport_name)
        if stats is None:
            stats = {"failures": 0, "http_4xx": 0, "last_error": None}
            self._failure_counters[transport_name] = stats
        stats["failures"] += 1
        if self._is_http_4xx(error):
            stats["http_4xx"] += 1
        if error:
            stats["last_error"] = error

    def failure_stats(self) -> dict[str, dict]:
        """Return a snapshot of cumulative per-transport failure counters.

        Returns:
            ``{transport_name: {"failures": int, "http_4xx": int,
            "last_error": str | None}}`` — a deep-ish copy safe to serialise
            into GET /api/v1/status and /metrics.
        """
        return {name: dict(stats) for name, stats in self._failure_counters.items()}

    def _count_throttle(self, transport_name: str) -> None:
        """Increment the cumulative outbound-throttle counter for a rail.

        Kept separate from ``failures``/``http_4xx``: a throttle is local
        pacing (coord 74d7b799), not a transport failure, so it never arms the
        cooldown and never inflates the failure totals. Surfaced via
        :meth:`failure_stats` as the ``throttled`` key.

        Args:
            transport_name: Rail whose send was throttled.
        """
        stats = self._failure_counters.get(transport_name)
        if stats is None:
            stats = {"failures": 0, "http_4xx": 0, "last_error": None}
            self._failure_counters[transport_name] = stats
        stats["throttled"] = stats.get("throttled", 0) + 1

    def _throttle_check(self, transport: Transport, recipient: str) -> Optional[SendResult]:
        """Outbound rate-limit gate for one send attempt (coord 74d7b799).

        Consults the router's outbound :class:`RateLimiter` (transport bucket +
        per-peer bucket). A denied attempt returns a failed
        :class:`SendResult` whose error starts with ``throttled:`` WITHOUT
        touching the transport, so throttling is pacing, never wire traffic.
        The throttle is deliberately NOT a ``perm:`` error and is excluded
        from the cooldown/failure accounting: durable callers (the
        PersistentOutbox) simply retry the entry on a later, paced sweep.

        Args:
            transport: The rail about to be attempted.
            recipient: The recipient (peer bucket key; ``*`` broadcasts use
                only the transport bucket).

        Returns:
            A failed SendResult when throttled, else None (attempt allowed).
        """
        if self._rate_limiter is None:
            return None
        peer = recipient if recipient != "*" else ""
        if self._rate_limiter.allow(transport.name, peer):
            return None
        wait = self._rate_limiter.wait_time(transport.name, peer)
        self._count_throttle(transport.name)
        logger.debug(
            "Outbound throttled on '%s' for %s (retry in ~%.1fs)",
            transport.name,
            recipient,
            wait,
        )
        return SendResult(
            success=False,
            transport_name=transport.name,
            envelope_id="",
            latency_ms=0.0,
            error=(
                f"throttled: outbound rate limit on '{transport.name}' "
                f"(retry in ~{wait:.1f}s)"
            ),
        )

    def _try_send(self, transport: Transport, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Attempt to send through a single transport with error handling."""
        throttled = self._throttle_check(transport, recipient)
        if throttled is not None:
            return throttled
        start = time.monotonic()
        try:
            result = transport.send(envelope_bytes, recipient)
            if result.success:
                self._record_success(transport.name)
                # A rail that just delivered to this recipient is no longer
                # structurally-undeliverable to it — drop its perm backoff.
                self._perm_backoff.pop((transport.name, recipient), None)
            else:
                self._count_failure(transport.name, result.error)
                # Log once on transition into the failing state, DEBUG while the
                # same failure repeats (RC2) — a structurally-undeliverable rail
                # (bad perm: target, '*' on a point-to-point rail) used to WARN
                # every ~5s and fill the daemon log.
                warn = self._note_failure_and_should_warn(
                    "send", transport.name, result.error, recipient
                )
                (logger.warning if warn else logger.debug)(
                    "Transport '%s' send failed: %s",
                    transport.name,
                    result.error or "no error detail",
                )
                # Structural/permanent routing failures — no inbox_url for THIS
                # recipient, a broadcast '*' a point-to-point transport can't
                # serve, or a 4xx rejection — are NOT transport-health problems.
                # Counting them would trip the cooldown and then block OTHER,
                # deliverable recipients on an otherwise-healthy transport (e.g. a
                # presence heartbeat to '*' every 60s starving real DMs). Only
                # transient failures (timeout/connection/5xx) arm the cooldown;
                # perm:/'*' failures instead arm the growing per-recipient
                # backoff so they stop being re-attempted every cycle (RC2).
                if not (result.error or "").startswith("perm:") and recipient != "*":
                    self._record_failure(transport.name)
                else:
                    self._record_perm_backoff(transport.name, recipient)
            return result
        except TransportError as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.warning("Transport '%s' TransportError: %s", transport.name, exc)
            self._count_failure(transport.name, str(exc))
            self._record_failure(transport.name)
            return SendResult(
                success=False,
                transport_name=transport.name,
                envelope_id="",
                latency_ms=elapsed,
                error=str(exc),
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.warning("Transport '%s' failed: %s", transport.name, exc)
            self._count_failure(transport.name, str(exc))
            self._record_failure(transport.name)
            return SendResult(
                success=False,
                transport_name=transport.name,
                envelope_id="",
                latency_ms=elapsed,
                error=str(exc),
            )

    def _extract_envelope_id(self, data: bytes) -> Optional[str]:
        """Best-effort extraction of envelope_id from raw bytes for dedup."""
        import json

        try:
            parsed = json.loads(data)
            return parsed.get("envelope_id")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _prune_seen_ids(self) -> None:
        """Remove expired and excess entries from the deduplication cache.

        Evicts TTL-expired entries first, then removes oldest entries
        if the cache exceeds ``SEEN_IDS_MAX`` to prevent unbounded growth.
        """
        now = time.time()
        # Remove TTL-expired entries
        expired = [eid for eid, ts in self._seen_ids.items() if now - ts > self._seen_ttl]
        for eid in expired:
            del self._seen_ids[eid]
        # Evict oldest entries if cache exceeds max size (LRU eviction)
        while len(self._seen_ids) > SEEN_IDS_MAX:
            self._seen_ids.popitem(last=False)
