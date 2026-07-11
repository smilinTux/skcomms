"""HTTP S2S transport — federation server-to-server delivery over the tailnet.

Pushes signed envelope bytes directly to a peer node's HTTP inbox endpoint
(``POST /api/v1/inbox``). This is the canonical federation rail: when both
nodes expose their skcomms API on the tailnet (TLS-terminated via Tailscale),
S2S HTTP gives reliable, ACK'd, idempotent delivery with the strongest
priority of the realtime rails.

Wire protocol:
    The raw signed-envelope bytes are POSTed to the peer's ``inbox_url`` with
    ``Content-Type: application/skcomms-signed-envelope+json``. A short
    timeout (~10s) bounds the attempt. The peer's inbox verifies the
    signature, checks freshness + nonce-replay, and writes to the recipient's
    local inbox. Delivery is push-only — this transport never receives
    (receipt is via the API ``/inbox`` endpoint, built separately as S2).

Status mapping (drives router retry vs. drop decisions):
    - 2xx              → success (delivered)
    - 425 Too Early    → retryable failure (stale envelope: freshness-window
      expiry from clock skew or a delayed retry, valid on a fresh attempt)
    - 4xx (other)      → permanent failure (bad request/auth/replay — no retry)
    - 5xx / timeout /
      connection error → retryable failure (router falls back / re-queues)

Structural gate (defense in depth, sign-at-send invariant):
    The peer's inbox parses ONLY :class:`~skcomms.envelope.SignedEnvelope`
    bytes, so any other payload shape is a guaranteed 422 on the far end.
    ``send`` therefore refuses payloads that
    :func:`skcomms.outbox.classify_envelope_json` does not classify as
    ``"signed"`` locally, as a permanent (``perm:``) failure, WITHOUT making
    the HTTP round trip. A legacy-envelope leak can then never re-create the
    422 round-trip storm on this rail.

Peer inbox_url discovery:
    Peer store YAML ``transports[].settings.inbox_url`` for a transport entry
    with ``transport == "https-s2s"`` — mirrors the tailscale transport's
    ``_peer_ip_from_store``.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Optional

from ..outbox import classify_envelope_json
from ..ssrf import SSRFBlockedError, guarded_urlopen, vet_url
from ..transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

logger = logging.getLogger("skcomms.transports.http_s2s")

#: Content type for raw signed-envelope payloads on the S2S rail.
CONTENT_TYPE = "application/skcomms-signed-envelope+json"

#: Default HTTP request timeout (seconds) for a single inbox POST.
SEND_TIMEOUT = 10.0

#: Transport name advertised in peer store entries + BUILTIN_TRANSPORTS.
TRANSPORT_NAME = "https-s2s"


class HttpS2STransport(Transport):
    """Federation S2S transport: POST signed envelopes to a peer's HTTP inbox.

    Resolves the recipient's ``inbox_url`` from the SKComms peer store and
    POSTs the raw envelope bytes. Highest-priority realtime rail (above the
    Tailscale TCP rail) because it carries an application-level ACK and is
    idempotent via the inbox's nonce-replay check.

    Attributes:
        name: Always ``"https-s2s"``.
        priority: Default 1 (above tailscale TCP at priority 2).
        category: ``REALTIME`` — selected by ``RoutingMode.SPEED``.
    """

    name: str = TRANSPORT_NAME
    priority: int = 1
    category: TransportCategory = TransportCategory.REALTIME

    def __init__(
        self,
        timeout: float = SEND_TIMEOUT,
        priority: int = 1,
        **kwargs,
    ):
        """Initialize the HTTP S2S transport.

        Args:
            timeout: Per-request HTTP timeout in seconds for the inbox POST.
            priority: Transport priority (lower = higher priority in routing).
        """
        self._timeout = float(timeout)
        self.priority = priority

        # Cached peer inbox URLs: name/fingerprint → https://host/api/v1/inbox
        self._peer_urls: dict[str, str] = {}

        # inbox URLs that came from a REMOTE realm directory (attacker
        # influenced, unlike operator-configured store/manual URLs). Sends to
        # these go through the pinned, SSRF-guarded fetch path.
        self._directory_urls: set[str] = set()

    # ──────────────────────────────────────────────────────────────────────
    # Transport ABC implementation
    # ──────────────────────────────────────────────────────────────────────

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys: ``timeout``, ``priority``.
        """
        if "timeout" in config:
            self._timeout = float(config["timeout"])
        if "priority" in config:
            self.priority = int(config["priority"])

    def is_available(self) -> bool:
        """True if at least one peer advertises an ``inbox_url``.

        Cheap check: scans the peer store for any ``https-s2s`` transport
        entry carrying an ``inbox_url``. Returns False only when no peer is
        reachable via this rail, so the router can fall back transparently.

        Returns:
            True when at least one peer has an S2S inbox URL.
        """
        try:
            from skcomms.discovery import PeerStore

            store = PeerStore()
            for peer in store.list_all():
                for t in peer.transports:
                    if t.transport == TRANSPORT_NAME and t.settings.get("inbox_url"):
                        return True
        except Exception as exc:
            logger.debug("http_s2s is_available check failed: %s", exc)
        return False

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """POST a signed envelope to the recipient peer's HTTP inbox.

        Resolves the peer's ``inbox_url`` from the peer store, then POSTs the
        raw bytes with the S2S content type. Maps the HTTP outcome to a
        retry/permanent/success decision for the router.

        Args:
            envelope_bytes: Serialised SignedEnvelope bytes.
            recipient: Agent name or fingerprint.

        Returns:
            SendResult. ``success=False`` with a ``perm:``-prefixed error for
            permanent (4xx or structural) failures; a plain error string for
            retryable (5xx / timeout / connection) failures.
        """
        start = time.monotonic()
        envelope_id = self._extract_id(envelope_bytes)

        # Structural gate (defense in depth): the receiving inbox parses ONLY
        # SignedEnvelope bytes and 422s anything else, so a non-signed payload
        # is refused locally as a permanent failure, with NO network call.
        try:
            payload_kind = classify_envelope_json(envelope_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            payload_kind = "corrupt"
        if payload_kind != "signed":
            logger.warning(
                "https-s2s refusing non-signed payload for %s (classified %r)",
                recipient,
                payload_kind,
            )
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=(time.monotonic() - start) * 1000,
                error=(
                    "perm: refusing non-SignedEnvelope payload on https-s2s "
                    f"(classified {payload_kind!r}); the inbox gate would 422 it"
                ),
            )

        inbox_url = self._resolve_inbox_url(recipient)
        if not inbox_url:
            # TRANSIENT, not structural: the peer simply is not discovered on
            # this rail yet (its https-s2s inbox_url may appear once discovery /
            # the peer store catches up). Emitting a ``perm:`` here armed the
            # router's growing per-recipient backoff, diverting directed traffic
            # off the only direct rail for up to 1h — and, because a backed-off
            # rail is excluded from selection, it could never produce the success
            # that would clear it. Return a retryable error so the router treats
            # it as an ordinary transient miss (short cooldown, self-clearing).
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=(time.monotonic() - start) * 1000,
                error=(
                    f"retry: no https-s2s inbox_url known for '{recipient}' "
                    "(peer not yet discovered)"
                ),
            )

        try:
            if inbox_url in self._directory_urls:
                # Directory-derived target: the URL came from a REMOTE realm's
                # signed directory, so its operator controls where it points
                # (including this node's internal network) and its DNS can
                # rebind between vetting and connect. POST through the central
                # SSRF guard: policy-vetted, connection pinned to the vetted
                # address, redirects on POST refused (see skcomms.ssrf).
                opened = guarded_urlopen(
                    inbox_url,
                    data=envelope_bytes,
                    method="POST",
                    headers={"Content-Type": CONTENT_TYPE},
                    timeout=self._timeout,
                )
            else:
                # Operator-configured target (manual registration / local peer
                # store): trusted local config, plain fetch (LAN/tailnet URLs
                # are legitimate here).
                req = urllib.request.Request(
                    inbox_url,
                    data=envelope_bytes,
                    method="POST",
                    headers={"Content-Type": CONTENT_TYPE},
                )
                opened = urllib.request.urlopen(req, timeout=self._timeout)
            with opened as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                try:
                    body = resp.read()
                except Exception:  # noqa: BLE001 - a body we cannot read is not a confirmation
                    body = b""
                elapsed = (time.monotonic() - start) * 1000
                if 200 <= status < 300:
                    # A 2xx alone is NOT delivery. ``POST /api/v1/inbox`` returns
                    # ``{"ok": true, "id": ...}`` ONLY after the per-recipient
                    # write (api.py::post_inbox). A 2xx WITHOUT that confirming
                    # body (an empty 200, a funnel/proxy ack that never reached
                    # post_inbox, or ``{"ok": false}``) is the exact
                    # opus-delivery false-success: the peer never wrote the
                    # envelope. Treat it as an undelivered, retryable failure so
                    # the router fails over and the sender keeps the envelope.
                    if not self._body_confirms_receipt(body):
                        logger.warning(
                            "https-s2s got %d from %s (%s) but body did not "
                            "confirm receipt ({\"ok\": true}); treating as "
                            "undelivered (opus-delivery guard)",
                            status,
                            recipient,
                            inbox_url,
                        )
                        return SendResult(
                            success=False,
                            transport_name=self.name,
                            envelope_id=envelope_id,
                            latency_ms=elapsed,
                            error=(
                                f"retry: HTTP {status} without a confirming "
                                '{"ok": true} body; the inbox did not accept '
                                "the write"
                            ),
                        )
                    logger.info(
                        "Sent %d bytes to %s (%s) via https-s2s [%d] (%.1fms)",
                        len(envelope_bytes),
                        recipient,
                        inbox_url,
                        status,
                        elapsed,
                    )
                    return SendResult(
                        success=True,
                        transport_name=self.name,
                        envelope_id=envelope_id,
                        latency_ms=elapsed,
                    )
                # Non-2xx returned without raising (rare for urllib): treat by class.
                return self._failure(envelope_id, start, status, "unexpected status")
        except SSRFBlockedError as exc:
            # The SSRF guard refused the destination (private/internal address,
            # bad scheme, or a rebinding host). Permanent: retrying the same
            # blocked URL can never succeed.
            elapsed = (time.monotonic() - start) * 1000
            logger.warning(
                "https-s2s send to %s (%s) blocked by SSRF guard: %s",
                recipient,
                inbox_url,
                exc,
            )
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error=f"perm: {exc}",
            )
        except urllib.error.HTTPError as exc:
            # HTTPError carries the response code: classify 4xx vs 5xx.
            return self._failure(envelope_id, start, exc.code, str(exc))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Timeout / connection refused / DNS / reset → retryable.
            elapsed = (time.monotonic() - start) * 1000
            logger.warning("https-s2s send to %s (%s) failed: %s", recipient, inbox_url, exc)
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error=f"retry: {exc}",
            )

    def receive(self) -> list[bytes]:
        """Push-model rail — never receives directly.

        Inbound delivery arrives via the skcomms API ``POST /inbox`` endpoint
        (built separately), not through this transport.

        Returns:
            Always an empty list.
        """
        return []

    def health_check(self) -> HealthStatus:
        """Report how many peers are reachable via the S2S rail.

        Returns:
            HealthStatus: AVAILABLE when ≥1 peer advertises an inbox_url,
            otherwise DEGRADED (the rail works but has no targets).
        """
        peer_urls: dict[str, str] = {}
        try:
            from skcomms.discovery import PeerStore

            store = PeerStore()
            for peer in store.list_all():
                for t in peer.transports:
                    if t.transport == TRANSPORT_NAME:
                        url = t.settings.get("inbox_url")
                        if url:
                            peer_urls[peer.name] = url
        except Exception as exc:
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.DEGRADED,
                error=f"peer store unavailable: {exc}",
                details={"timeout": self._timeout},
            )

        return HealthStatus(
            transport_name=self.name,
            status=(
                TransportStatus.AVAILABLE if peer_urls else TransportStatus.DEGRADED
            ),
            details={
                "timeout": self._timeout,
                "known_inboxes": len(peer_urls),
            },
        )

    # ──────────────────────────────────────────────────────────────────────
    # inbox_url resolution
    # ──────────────────────────────────────────────────────────────────────

    def register_peer_url(self, peer_name: str, inbox_url: str) -> None:
        """Manually register a peer's S2S inbox URL.

        Args:
            peer_name: Agent name or fingerprint to register.
            inbox_url: Full ``https://host/api/v1/inbox`` URL.
        """
        self._peer_urls[peer_name] = inbox_url
        logger.debug("Registered https-s2s peer: %s → %s", peer_name, inbox_url)

    def _resolve_inbox_url(self, recipient: str) -> Optional[str]:
        """Resolve a recipient's S2S inbox URL.

        Checks (in order): manual registry → peer store YAML.

        Args:
            recipient: Agent name or fingerprint.

        Returns:
            The inbox URL string, or None if not found.
        """
        # A '*' broadcast (or an empty recipient) has no single peer inbox: never
        # drive a peer-store lookup for it (that sanitizes '*' to empty and
        # raises "Peer name '*' is empty after sanitization", logged as a
        # per-heartbeat WARNING — RC3). Fail closed here, before any store call.
        if recipient in ("*", ""):
            return None

        url = self._peer_urls.get(recipient)
        if url:
            return url

        url = self._inbox_url_from_store(recipient)
        if url:
            self._peer_urls[recipient] = url
            return url

        # 3. SKFed realm directory (sovereign, no-local-config): reach an agent by
        # FQID alone. Gated on a pinned realm-operator key — fails closed.
        url = self._inbox_url_from_directory(recipient)
        if url:
            self._peer_urls[recipient] = url
            self._directory_urls.add(url)
            return url

        return None

    def _inbox_url_from_directory(self, recipient: str) -> Optional[str]:
        """Resolve the recipient's inbox via its realm's signed SKFed directory.

        Builds the FQID from a bare name using the local realm/operator, pins the
        realm-operator verifier, and resolves through the :443-funnel directory
        (``inbox_url_for`` step 3). Fails **closed** (None) when the realm is
        unpinned / unresolvable — never raises.
        """
        try:
            from skcomms.skfed_resolve import (_realm_of, default_http_get,
                                               realm_verifier)

            fqid = recipient
            if "@" not in fqid:
                from skcomms.cluster import get_operator, get_realm

                fqid = f"{recipient}@{get_operator()}.{get_realm()}"
            realm = _realm_of(fqid)
            verifier = realm_verifier(realm) if realm else None
            if verifier is None:
                return None
            from skcomms.discovery import inbox_url_for

            url = inbox_url_for(fqid, http_get=default_http_get, verifier=verifier)
            if url:
                # SSRF guard: an inbox_url from a REMOTE directory is chosen by
                # that realm's operator, so refuse private/internal targets up
                # front (vet_url raises, caught below -> fail closed to None).
                vet_url(url)
            return url
        except Exception as exc:  # never let directory resolution break delivery
            logger.debug("skfed directory inbox_url for %s failed: %s", recipient, exc)
            return None

    def _inbox_url_from_store(self, recipient: str) -> Optional[str]:
        """Look up the S2S inbox URL from the SKComms peer store.

        The peer YAML should contain::

            transports:
              - transport: https-s2s
                settings:
                  inbox_url: "https://node.ts.net/api/v1/inbox"

        Args:
            recipient: Agent name or fingerprint.

        Returns:
            inbox_url from the peer store, or None.
        """
        # Belt-and-suspenders with _resolve_inbox_url: a '*'/'' recipient never
        # reaches the peer-store sanitizer (RC3), so the WARNING below only ever
        # fires for a genuine lookup error on a real recipient.
        if recipient in ("*", ""):
            logger.debug("skipping https-s2s inbox lookup for broadcast/empty recipient")
            return None

        try:
            # Use the fqid-aware resolver (S5): handles recipient given as a
            # full fqid ("lumina@chef.skworld") OR a bare name ("lumina"),
            # which name-only PeerStore.get() does not.
            from skcomms.discovery import inbox_url_for

            url = inbox_url_for(recipient)
            if url:
                return url
            # Fallback: direct name lookup (fingerprint/legacy keys).
            from skcomms.discovery import PeerStore

            peer = PeerStore().get(recipient)
            if peer:
                for t in peer.transports:
                    if t.transport == TRANSPORT_NAME:
                        return t.settings.get("inbox_url")
        except Exception as exc:
            logger.warning("http_s2s peer store lookup failed: %s", exc)
        return None

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _failure(
        self, envelope_id: str, start: float, status: int, detail: str
    ) -> SendResult:
        """Build a failure SendResult, classifying retryable vs permanent by status.

        Args:
            envelope_id: Envelope id for the result.
            start: monotonic start time for latency accounting.
            status: HTTP status code from the response.
            detail: Error detail string.

        Returns:
            SendResult with ``perm:`` prefix for 4xx, ``retry:`` for 5xx/other.
            The one 4xx exception is 425 (Too Early): the inbox emits it for a
            stale-but-valid envelope (freshness-window expiry from clock skew or
            a delayed retry), which is retryable rather than permanent.
        """
        elapsed = (time.monotonic() - start) * 1000
        if status == 425:
            kind = "retry"
        elif 400 <= status < 500:
            kind = "perm"
        else:
            kind = "retry"
        logger.warning("https-s2s inbox returned %d (%s): %s", status, kind, detail)
        return SendResult(
            success=False,
            transport_name=self.name,
            envelope_id=envelope_id,
            latency_ms=elapsed,
            error=f"{kind}: HTTP {status} {detail}",
        )

    @staticmethod
    def _body_confirms_receipt(body: bytes) -> bool:
        """True only when the inbox response body confirms the per-recipient write.

        ``POST /api/v1/inbox`` returns ``{"ok": true, "id": ...}`` ONLY after
        :func:`skcomms.api._write_to_recipient_inbox` succeeds (see
        ``api.py::post_inbox``). Any other 2xx body (empty, a funnel/proxy ack
        that never ran the write, or ``{"ok": false}``) does NOT prove the
        envelope was accepted, so it must not be counted as delivered.

        Args:
            body: The raw HTTP response body bytes.

        Returns:
            True iff the body parses to a JSON object with ``ok == True``.
        """
        if not body:
            return False
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return False
        return isinstance(data, dict) and data.get("ok") is True

    @staticmethod
    def _extract_id(envelope_bytes: bytes) -> str:
        """Best-effort extraction of envelope_id from raw envelope bytes.

        Args:
            envelope_bytes: Raw JSON envelope.

        Returns:
            The envelope id, or a timestamp-based fallback.
        """
        try:
            parsed = json.loads(envelope_bytes)
            inner = parsed.get("envelope")
            inner_id = inner.get("id") if isinstance(inner, dict) else None
            return (
                parsed.get("envelope_id")
                or parsed.get("id")
                or inner_id
                or f"unknown-{int(time.time())}"
            )
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            return f"unknown-{int(time.time())}"


def create_transport(
    timeout: float = SEND_TIMEOUT,
    priority: int = 1,
    **kwargs,
) -> HttpS2STransport:
    """Factory function called by the SKComms router transport loader.

    Args:
        timeout: Per-request HTTP timeout in seconds.
        priority: Transport priority (lower = higher priority in routing).

    Returns:
        Configured HttpS2STransport instance.
    """
    return HttpS2STransport(timeout=timeout, priority=priority)
