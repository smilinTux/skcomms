"""Nostr-backed federation auto-discovery (SKFed P3, §9b).

Replaces MANUAL peer seeding with zero-config discovery. Each node publishes a
signed *directory record* for every local agent to the Nostr relay on startup;
peers self-resolve an unknown ``fqid`` → home-node ``inbox_url`` + capauth pubkey
+ advertised rails straight from the relay into the :class:`~skcomms.discovery.
PeerStore`. Add a node, it announces; others find it.

Directory event
---------------
A **replaceable** Nostr event (NIP-33 parameterised-replaceable range)::

    kind    = 30079                 (DIRECTORY_KIND, "skfed-directory")
    tags    = [["d", "<fqid>"]]     d-tag = fqid (one replaceable slot per agent)
    content = JSON {
        "fqid":      "lumina@chef.skworld",
        "node":      "noroc2027",                  # home-node hostname
        "inbox_url": "https://<node>/api/v1/inbox", # https-s2s S2S rail
        "pubkey":    "-----BEGIN PGP PUBLIC KEY BLOCK----- ...",  # capauth armored
        "rails":     ["https-s2s", "syncthing", "nostr"],
        "ts":        1750000000
    }

The ``d`` tag makes it replaceable: a fresh publish for the same fqid supersedes
the old record (relay keeps only the latest), so directory state stays current
without churn.

Trust
-----
Relay-published pubkeys are **never** blindly trusted. Each resolved record runs
through :mod:`skcomms.tofu`: first sight pins the capauth fingerprint (TRUST_NEW),
a matching key is accepted (TRUST_MATCH), and a *changed* key for a known fqid is
a CONFLICT — rejected and logged, the existing pin left untouched. The relay is
a discovery hint, not an authority.

Relay I/O sits behind injectable ``publish``/``query`` seams (mirroring
skchat's ``spaces/federation/nostr_io.py``), so the whole module is testable with
fakes — no network.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from .discovery import PEERS_DIR_NAME, PeerInfo, PeerStore, PeerTransport
from .home import skcomms_home
from .identity import resolve_self_identity
from .tofu import TofuStatus, verify_fingerprint

logger = logging.getLogger("skcomms.nostr_discovery")


def _default_store() -> PeerStore:
    """PeerStore rooted at the env-aware skcomms home (matches the TOFU store).

    ``discovery.PeerStore`` defaults to a hardcoded constant; we root ours at
    :func:`skcomms.home.skcomms_home` so ``SKCOMMS_HOME`` redirects both the
    peer store and the TOFU pin store together (test isolation + sovereign home).
    """
    return PeerStore(peers_dir=skcomms_home() / PEERS_DIR_NAME)

# Parameterised-replaceable event kind (NIP-33 range 30000-39999).
DIRECTORY_KIND = 30079
DIRECTORY_DTAG = "skfed-directory"  # marker; the real d-tag value is the fqid

# How far back to query directory records by default (records are replaceable,
# but relays may key `since` off created_at — keep a generous window).
DEFAULT_SINCE_WINDOW = 30 * 24 * 3600  # 30 days

# A publish seam takes a signed event dict and returns whether it landed.
PublishFn = Callable[[dict], bool]
# A query seam takes a Nostr filter dict and returns matching event dicts.
QueryFn = Callable[[dict], list]


# ---------------------------------------------------------------------------
# Default relay seams (real network) — wrap the skcomms nostr low-level
# ---------------------------------------------------------------------------


def default_relays() -> list[str]:
    """Resolve the discovery relay list from the environment.

    Honors ``SKCHAT_NOSTR_RELAYS`` (comma- or whitespace-separated), the same
    var skchat's federation uses. Empty when unset (caller may inject seams).

    Returns:
        List of relay WebSocket URLs.
    """
    raw = os.environ.get("SKCHAT_NOSTR_RELAYS", "")
    return [r.strip() for r in raw.replace(",", " ").split() if r.strip()]


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


# ---------------------------------------------------------------------------
# Event build / parse
# ---------------------------------------------------------------------------


def build_directory_event(record: dict, *, secret: Optional[bytes] = None) -> dict:
    """Build (and, if a secret is given, sign) a directory Nostr event.

    Args:
        record: Directory record dict (``fqid``, ``node``, ``inbox_url``,
            ``pubkey``, ``rails``, ``ts``). ``fqid`` is required (it becomes the
            replaceable ``d`` tag).
        secret: Optional 32-byte Nostr secret. When provided the event is signed
            with a BIP-340 Schnorr signature (real publish); when ``None`` the
            event carries an empty ``sig`` (test/fake-relay use).

    Returns:
        A Nostr event dict ready to publish.

    Raises:
        ValueError: If ``record`` has no ``fqid``.
    """
    fqid = record.get("fqid")
    if not fqid:
        raise ValueError("directory record requires an 'fqid'")
    content = json.dumps(record, separators=(",", ":"), sort_keys=True)
    tags = [["d", fqid]]

    if secret is not None:
        from .transports.nostr import _make_event, _pubkey_of, _sign_event

        x, _ = _pubkey_of(secret)
        ev = _make_event(x.hex(), DIRECTORY_KIND, content, tags, record.get("ts"))
        return _sign_event(ev, secret)

    # Unsigned shell (fake relay / tests). Mirror _make_event's shape minimally.
    return {
        "id": "",
        "pubkey": "",
        "created_at": int(record.get("ts") or time.time()),
        "kind": DIRECTORY_KIND,
        "tags": tags,
        "content": content,
        "sig": "",
    }


def parse_directory_event(event: dict) -> Optional[dict]:
    """Parse a directory Nostr event back into a record dict.

    Args:
        event: A Nostr event dict (from a relay).

    Returns:
        The directory record dict, or ``None`` if the event is the wrong kind or
        the content is unparseable / missing required fields.
    """
    if event.get("kind") != DIRECTORY_KIND:
        return None
    try:
        record = json.loads(event.get("content", ""))
    except (json.JSONDecodeError, TypeError):
        logger.warning("skipping malformed directory event content")
        return None
    if not isinstance(record, dict) or not record.get("fqid"):
        return None
    return record


# ---------------------------------------------------------------------------
# Record → PeerInfo (with TOFU pubkey pinning)
# ---------------------------------------------------------------------------


def _peer_name_for(fqid: str) -> str:
    """Bare-agent name used as the PeerStore key (its file name)."""
    return fqid.split("@", 1)[0] if "@" in fqid else fqid


def _fingerprint_from_armor(pubkey_armor: str) -> Optional[str]:
    """Best-effort PGP fingerprint extraction from an armored public key."""
    try:
        import pgpy  # type: ignore

        key, _ = pgpy.PGPKey.from_blob(pubkey_armor)
        return str(key.fingerprint).replace(" ", "").upper()
    except Exception as exc:  # noqa: BLE001
        logger.debug("could not derive fingerprint from armored pubkey: %s", exc)
        return None


def record_to_peer(record: dict) -> Optional[PeerInfo]:
    """Convert a directory record into a :class:`PeerInfo`, pinning the pubkey.

    The capauth pubkey is run through TOFU (:func:`skcomms.tofu.verify_fingerprint`)
    keyed by fqid: first sight pins it; a *changed* key for a known fqid is a
    CONFLICT and this returns ``None`` (the record is rejected, the pin kept).

    Args:
        record: A parsed directory record dict.

    Returns:
        A :class:`PeerInfo` to upsert, or ``None`` on a TOFU conflict / bad record.
    """
    fqid = record.get("fqid")
    if not fqid:
        return None

    inbox_url = record.get("inbox_url")
    pubkey = record.get("pubkey")
    rails = record.get("rails") or []
    node = record.get("node")

    # TOFU-pin the capauth identity (pubkey → fingerprint) for this fqid.
    pinned_pubkey = pubkey
    fingerprint = None
    if pubkey:
        fingerprint = _fingerprint_from_armor(pubkey)
        if fingerprint:
            result = verify_fingerprint(fqid, fingerprint, pubkey=pubkey)
            if result.status == TofuStatus.CONFLICT:
                logger.warning(
                    "directory record for %s rejected: pubkey conflicts with pinned "
                    "fingerprint (stored=%s presented=%s)",
                    fqid,
                    result.stored_fingerprint,
                    result.presented_fingerprint,
                )
                return None

    transports: list[PeerTransport] = []
    if inbox_url:
        transports.append(
            PeerTransport(
                transport="https-s2s",
                settings={"inbox_url": inbox_url, **({"node": node} if node else {})},
            )
        )

    ts = record.get("ts")
    last_seen = (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, (int, float))
        else datetime.now(timezone.utc)
    )

    return PeerInfo(
        name=_peer_name_for(fqid),
        fqid=fqid,
        fingerprint=fingerprint,
        pubkey=pinned_pubkey,
        transports=transports,
        rails=list(rails),
        discovered_via="nostr-directory",
        last_seen=last_seen,
    )


# ---------------------------------------------------------------------------
# Discovery client
# ---------------------------------------------------------------------------


class NostrDirectory:
    """Publish/resolve federation directory records over Nostr relays.

    Args:
        relays: Relay WebSocket URLs (defaults to ``SKCHAT_NOSTR_RELAYS`` env).
        store: :class:`PeerStore` for upserts (a default one is used otherwise).
        secret: Optional 32-byte Nostr secret used to sign published records.
        publish / query: Injectable relay seams (for tests / custom transport).
    """

    def __init__(
        self,
        relays: Optional[list[str]] = None,
        *,
        store: Optional[PeerStore] = None,
        secret: Optional[bytes] = None,
        publish: Optional[PublishFn] = None,
        query: Optional[QueryFn] = None,
    ) -> None:
        self.relays = relays if relays is not None else default_relays()
        self.store = store or _default_store()
        self._secret = secret
        self._publish = publish or _default_publish(self.relays)
        self._query = query or _default_query(self.relays)

    # -- publish ----------------------------------------------------------

    def publish_directory(self, record: dict) -> bool:
        """Publish a signed directory record for one local agent.

        Args:
            record: Directory record (``fqid``, ``node``, ``inbox_url``,
                ``pubkey``, ``rails``, ``ts``). ``ts`` is filled with now if
                absent.

        Returns:
            True if at least one relay accepted the event.
        """
        record = dict(record)
        record.setdefault("ts", int(time.time()))
        event = build_directory_event(record, secret=self._secret)
        ok = self._publish(event)
        logger.info(
            "published directory record for %s (%s)",
            record.get("fqid"),
            "ok" if ok else "no relay accepted",
        )
        return ok

    # -- resolve / discover ----------------------------------------------

    def resolve_peer(self, fqid: str) -> Optional[PeerInfo]:
        """Resolve a single ``fqid`` from the relay and upsert it.

        Queries the relay for that fqid's directory record (by ``d`` tag),
        parses it, TOFU-pins the pubkey, and upserts a :class:`PeerInfo`.

        Args:
            fqid: The peer's ``<agent>@<operator>.<realm>`` handle.

        Returns:
            The upserted :class:`PeerInfo`, or ``None`` if not found / rejected.
        """
        filters = {"kinds": [DIRECTORY_KIND], "#d": [fqid]}
        events = self._query(filters)
        record = self._latest_record(events, fqid=fqid)
        if record is None:
            logger.debug("no directory record found for %s", fqid)
            return None
        peer = record_to_peer(record)
        if peer is None:
            return None
        self.store.add(peer)
        logger.info("resolved + upserted peer %s (inbox=%s)", fqid, peer.inbox_url())
        return peer

    def discover_all(self) -> list[PeerInfo]:
        """Query *all* directory records and upsert each (auto-seed).

        Idempotent and best-effort: malformed or conflicting records are skipped
        without aborting the batch. Re-running merges into existing peers.

        Returns:
            The list of :class:`PeerInfo` upserted this run.
        """
        filters = {"kinds": [DIRECTORY_KIND]}
        events = self._query(filters)

        # Keep only the newest event per fqid (replaceable semantics).
        latest: dict[str, dict] = {}
        for ev in events:
            record = parse_directory_event(ev)
            if record is None:
                continue
            fqid = record["fqid"]
            created = ev.get("created_at", record.get("ts", 0)) or 0
            prev = latest.get(fqid)
            if prev is None or created >= prev[0]:
                latest[fqid] = (created, record)

        upserted: list[PeerInfo] = []
        for _created, record in latest.values():
            peer = record_to_peer(record)
            if peer is None:
                continue
            try:
                self.store.add(peer)
                upserted.append(peer)
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to upsert peer %s: %s", record.get("fqid"), exc)
        logger.info("discover_all: upserted %d peer(s)", len(upserted))
        return upserted

    # alias — the spec names both discover_all() and sync_directory()
    sync_directory = discover_all

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _latest_record(events: list, *, fqid: str) -> Optional[dict]:
        """Pick the newest valid directory record for *fqid* from events."""
        best: Optional[tuple[int, dict]] = None
        for ev in events:
            record = parse_directory_event(ev)
            if record is None or record.get("fqid") != fqid:
                continue
            created = ev.get("created_at", record.get("ts", 0)) or 0
            if best is None or created >= best[0]:
                best = (created, record)
        return best[1] if best else None


# ---------------------------------------------------------------------------
# Startup hook — announce this node's local agents (best-effort, non-fatal)
# ---------------------------------------------------------------------------


def _node_name() -> str:
    """Resolve this node's hostname (for the directory ``node`` field)."""
    import socket

    return socket.gethostname()


def _self_capauth_pubkey(agent: str) -> Optional[str]:
    """Read the running agent's armored capauth public key, if present."""
    path = (
        Path.home()
        / ".skcapstone"
        / "agents"
        / str(agent)
        / "capauth"
        / "identity"
        / "public.asc"
    )
    if path.exists():
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.debug("could not read capauth public key %s: %s", path, exc)
    return None


def build_self_record(
    *,
    agent: Optional[str] = None,
    inbox_url: Optional[str] = None,
    rails: Optional[list[str]] = None,
    node: Optional[str] = None,
) -> Optional[dict]:
    """Build this node's directory record for the running agent.

    Args:
        agent: Agent short name (defaults to the resolved self identity).
        inbox_url: This node's ``https-s2s`` S2S inbox URL. Falls back to
            ``SKFED_INBOX_URL`` env.
        rails: Advertised rail preference (default ``["https-s2s","syncthing","nostr"]``).
        node: Home-node hostname (default the local hostname).

    Returns:
        A directory record dict, or ``None`` if no fqid can be resolved (nothing
        to announce).
    """
    ident = resolve_self_identity(agent)
    fqid = ident.get("fqid")
    if not fqid:
        logger.debug("no fqid resolved — skipping directory announce")
        return None

    inbox_url = inbox_url or os.environ.get("SKFED_INBOX_URL")
    pubkey = _self_capauth_pubkey(ident.get("agent") or agent or "")
    record = {
        "fqid": fqid,
        "node": node or _node_name(),
        "rails": rails or ["https-s2s", "syncthing", "nostr"],
        "ts": int(time.time()),
    }
    if inbox_url:
        record["inbox_url"] = inbox_url
    if pubkey:
        record["pubkey"] = pubkey
    return record


def announce_self(
    *,
    agent: Optional[str] = None,
    inbox_url: Optional[str] = None,
    rails: Optional[list[str]] = None,
    relays: Optional[list[str]] = None,
    secret: Optional[bytes] = None,
    directory: Optional[NostrDirectory] = None,
) -> bool:
    """Best-effort startup hook: publish this node's directory record.

    Designed to be wired into node/skcomms startup. **Never raises** — any
    failure is logged and swallowed so a missing relay can't take the node down.

    Args:
        agent: Agent to announce (default resolved self).
        inbox_url / rails: Record overrides (see :func:`build_self_record`).
        relays / secret / directory: Override relay set, signing key, or inject a
            pre-built :class:`NostrDirectory` (e.g. with fake seams).

    Returns:
        True if the record was published to at least one relay.
    """
    try:
        record = build_self_record(agent=agent, inbox_url=inbox_url, rails=rails)
        if record is None:
            return False
        dir_client = directory or NostrDirectory(relays=relays, secret=secret)
        return dir_client.publish_directory(record)
    except Exception as exc:  # noqa: BLE001
        logger.warning("announce_self failed (non-fatal): %s", exc)
        return False


# ---------------------------------------------------------------------------
# Send-path hook — resolve an unknown fqid before giving up
# ---------------------------------------------------------------------------


def ensure_peer(
    fqid: str,
    *,
    store: Optional[PeerStore] = None,
    relays: Optional[list[str]] = None,
    directory: Optional[NostrDirectory] = None,
) -> Optional[PeerInfo]:
    """Return a known peer for *fqid*, else try to discover it from the relay.

    Thin hook for the send path: if the recipient is already in the
    :class:`PeerStore`, returns it unchanged; otherwise attempts a single
    :meth:`NostrDirectory.resolve_peer` before the caller fails. Best-effort —
    returns ``None`` rather than raising if discovery is unavailable.

    Args:
        fqid: Recipient ``fqid`` or bare agent name.
        store: Optional :class:`PeerStore`.
        relays / directory: Relay override or injected client (tests).

    Returns:
        The (existing or freshly-discovered) :class:`PeerInfo`, or ``None``.
    """
    store = store or _default_store()
    # Already known by fqid or bare name?
    name = _peer_name_for(fqid)
    existing = store.get(name)
    if existing is None and "@" in fqid:
        # also try a peer whose stored fqid matches exactly
        for p in store.list_all():
            if p.fqid == fqid:
                existing = p
                break
    if existing is not None:
        return existing

    if "@" not in fqid:
        # Discovery is keyed by fqid; a bare name can't be resolved off the relay.
        return None

    try:
        dir_client = directory or NostrDirectory(relays=relays, store=store)
        return dir_client.resolve_peer(fqid)
    except Exception as exc:  # noqa: BLE001
        logger.debug("ensure_peer discovery failed for %s: %s", fqid, exc)
        return None
