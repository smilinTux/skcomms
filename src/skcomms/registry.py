"""Realm peer registry — pluggable, multi-backend peer discovery (T11, ``e1dea61f``).

This is the **realm-discovery layer above** the T8 ``peers.json`` connectivity
store (:mod:`skcomms.peers`). T8 answers "what Syncthing device + PGP key did I
explicitly pin for this fqid?". T11 answers the prior question: "given just an
fqid, how do I *find* the connectivity details to pin?" — by consulting one or
more pluggable backends and merging their hints into a single
:class:`PeerRecord`.

Three backends ship (all share one unified ``peers.json`` schema):

    1. :class:`SyncthingSharedBackend` — **DEFAULT, sovereign**. Reads a
       steward-maintained shared file at ``${SKCOMMS_HOME}/_realm/peers.json``
       (a Syncthing *Receive-Only* folder the realm steward publishes).
       Offline, no network, no daemon.
    2. :class:`HttpsBackend` — **opt-in**. GETs
       ``https://registry.<realm>/peers.json``. The HTTP fetcher is *injected*
       (a callable) so tests pass a fake; the default fetcher uses ``urllib``.
    3. :class:`TailscaleBackend` — **opt-in**. Resolves a peer through a
       ``tailscale status --json`` dict. The status runner is *injected* so
       tests pass a fixture; the default shells out to ``tailscale``.

Tailscale hostname ⇄ fqid convention
-------------------------------------
A tailnet node maps to ``<agent>@<operator>.<realm>`` by its **hostname**
(``HostName`` / ``DNSName`` left-label) following the template
``skcomms-<agent>-<operator>`` (e.g. ``skcomms-opus-casey`` ⇄
``opus@casey.<realm>``). The realm component is not encoded in the hostname (it
is realm-local), so the backend matches on ``<agent>`` + ``<operator>`` only.
Nodes tagged ``tag:skcomms`` are treated as skcomms peers regardless; the
hostname still supplies the agent/operator mapping.

:class:`PeerRegistry` ties it together: ``resolve(fqid)`` tries the ENABLED
backends in configured order and **merges** their hints (first-writer wins for
an already-populated field), producing one enriched :class:`PeerRecord`.
``from_config()`` reads the ``registry`` section (:class:`skcomms.config.RegistryConfig`)
with sovereign defaults (syncthing-shared only).
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Callable, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .cluster import get_realm
from .home import skcomms_home

logger = logging.getLogger("skcomms.registry")

# Injected callable types — both default to real impls but tests always stub.
Fetcher = Callable[[str], str]
StatusRunner = Callable[[], dict]


def _split_fqid(fqid: str) -> tuple[str, str, str]:
    """Split ``<agent>@<operator>.<realm>`` into its triple.

    Raises:
        ValueError: If *fqid* is not a well-formed ``a@o.r`` handle.
    """
    if not isinstance(fqid, str) or "@" not in fqid:
        raise ValueError(f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)")
    agent, rest = fqid.split("@", 1)
    if not agent or "." not in rest:
        raise ValueError(f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)")
    operator, realm = rest.split(".", 1)
    if not operator or not realm:
        raise ValueError(f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)")
    return agent, operator, realm


# ---------------------------------------------------------------------------
# Unified PeerRecord schema
# ---------------------------------------------------------------------------


class PeerRecord(BaseModel):
    """A unified peer record — identity + optional connectivity hints.

    Backward-compatible superset of a T8 ``peers.json`` entry: an entry carrying
    only ``syncthing_device_id`` + ``fingerprint`` parses fine (see
    :meth:`from_entry`). A record can be **enriched** by multiple backends via
    :meth:`merge`, accumulating connectivity hints from each.

    Attributes:
        fqid: The peer handle (``<agent>@<operator>.<realm>``).
        operator: Operator component (auto-derived from *fqid* if omitted).
        pgp_fingerprint: The canonical PGP identity (40-hex), if known.
        pubkey: Optional ASCII-armored public key (so a backend can supply the
            key for a TOFU bind without a separate fetch).
        syncthing_device_id: Syncthing device id hint.
        tailscale: Tailscale hint — any subset of ``{node, magicdns, ip}``.
        https: An HTTPS endpoint hint.
        source: The backend that produced this record.
        sources: All backends that contributed (accumulated by :meth:`merge`).
        added_at: Optional ISO timestamp carried from the source.
    """

    fqid: str
    operator: Optional[str] = None
    pgp_fingerprint: Optional[str] = None
    pubkey: Optional[str] = None
    syncthing_device_id: Optional[str] = None
    tailscale: Optional[dict] = None
    https: Optional[str] = None
    source: Optional[str] = None
    sources: list[str] = Field(default_factory=list)
    added_at: Optional[str] = None

    @field_validator("fqid")
    @classmethod
    def _check_fqid(cls, v: str) -> str:
        _split_fqid(v)  # raises ValueError on a bad shape
        return v

    @model_validator(mode="after")
    def _derive_operator_and_sources(self) -> "PeerRecord":
        if self.operator is None:
            self.operator = _split_fqid(self.fqid)[1]
        if self.source and self.source not in self.sources:
            self.sources.append(self.source)
        return self

    @classmethod
    def from_entry(cls, fqid: str, entry: dict, source: str) -> "PeerRecord":
        """Build a record from a shared/HTTPS ``peers.json`` entry dict.

        Accepts both the T8 field name ``fingerprint`` and the unified
        ``pgp_fingerprint``; tolerates extra keys.

        Args:
            fqid: The peer handle (the map key).
            entry: The per-peer dict from a ``peers.json`` file.
            source: The backend name to stamp on the record.
        """
        return cls(
            fqid=fqid,
            operator=entry.get("operator"),
            pgp_fingerprint=entry.get("pgp_fingerprint") or entry.get("fingerprint"),
            pubkey=entry.get("pubkey"),
            syncthing_device_id=entry.get("syncthing_device_id"),
            tailscale=entry.get("tailscale"),
            https=entry.get("https"),
            added_at=entry.get("added_at"),
            source=source,
        )

    def merge(self, other: "PeerRecord") -> "PeerRecord":
        """Return a new record enriched with *other*'s hints.

        **First-writer wins**: a field already populated on ``self`` is kept;
        ``other`` only fills the gaps. The ``sources`` list accumulates every
        contributing backend (de-duplicated, order-preserving). This makes merge
        order-sensitive in exactly the way the resolver wants — the first backend
        in the configured order is authoritative for any field it provides.

        Raises:
            ValueError: If the two records are for different fqids.
        """
        if other.fqid != self.fqid:
            raise ValueError(
                f"cannot merge records for different fqids: {self.fqid} != {other.fqid}"
            )
        merged = self.model_copy(deep=True)
        for field in (
            "pgp_fingerprint",
            "pubkey",
            "syncthing_device_id",
            "tailscale",
            "https",
            "added_at",
        ):
            if getattr(merged, field) is None and getattr(other, field) is not None:
                setattr(merged, field, getattr(other, field))
        for s in other.sources or ([other.source] if other.source else []):
            if s and s not in merged.sources:
                merged.sources.append(s)
        return merged

    def to_dict(self) -> dict:
        """JSON-friendly dict with empty hints dropped."""
        return self.model_dump(exclude_none=True)


# ---------------------------------------------------------------------------
# Backend ABC
# ---------------------------------------------------------------------------


class RegistryBackend(ABC):
    """A pluggable source of :class:`PeerRecord` hints.

    Implementations must be side-effect-free on construction and must **never**
    raise from :meth:`lookup`/:meth:`list` for ordinary "not found / unreachable"
    conditions — those return ``None`` / ``[]`` so the resolver can fall through
    to the next backend.
    """

    #: Stable backend identifier used in config ``enabled``/``order`` lists and
    #: stamped onto produced records' ``source``.
    name: str = "backend"

    @abstractmethod
    def lookup(self, fqid: str) -> Optional[PeerRecord]:
        """Return a record for *fqid*, or ``None`` on a miss."""

    @abstractmethod
    def list(self) -> list[PeerRecord]:
        """Return all records this backend can enumerate (``[]`` if none)."""


# ---------------------------------------------------------------------------
# SyncthingSharedBackend (DEFAULT, sovereign, offline)
# ---------------------------------------------------------------------------


class SyncthingSharedBackend(RegistryBackend):
    """Reads the steward-maintained shared realm file (the DEFAULT backend).

    The realm steward publishes a ``peers.json`` of the whole realm into a
    Syncthing *Receive-Only* folder mounted at ``${SKCOMMS_HOME}/_realm/``. This
    backend reads it directly — fully sovereign and offline. The file uses the
    same ``{"peers": {fqid: entry}}`` shape as T8's local ``peers.json``, so a
    steward can literally aggregate operators' files.
    """

    name = "syncthing-shared"

    _REALM_DIR = "_realm"
    _FILE = "peers.json"

    def realm_path(self):
        """Path to the shared realm ``peers.json`` under SKCOMMS_HOME."""
        return skcomms_home() / self._REALM_DIR / self._FILE

    def _load(self) -> dict:
        path = self.realm_path()
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("shared realm file unreadable (%s): %s", path, exc)
            return {}
        peers = data.get("peers") if isinstance(data, dict) else None
        return peers if isinstance(peers, dict) else {}

    def lookup(self, fqid: str) -> Optional[PeerRecord]:
        entry = self._load().get(fqid)
        if not entry:
            return None
        return PeerRecord.from_entry(fqid, entry, self.name)

    def list(self) -> list[PeerRecord]:
        return [
            PeerRecord.from_entry(fqid, entry, self.name)
            for fqid, entry in self._load().items()
            if isinstance(entry, dict)
        ]


# ---------------------------------------------------------------------------
# HttpsBackend (opt-in) — injected fetcher
# ---------------------------------------------------------------------------


def _default_https_fetcher(url: str) -> str:
    """Real HTTPS GET (only used outside tests; tests inject a fake).

    SSRF-guarded and rebind-safe: the URL is templated from a realm name that
    can be remote-influenced, so it is vetted and the connection is pinned to
    the vetted address (see :mod:`skcomms.ssrf`). A blocked destination raises
    :class:`~skcomms.ssrf.SSRFBlockedError` (a ``ValueError``) before any
    socket is opened; the resolver treats a raising backend as no-result.
    """
    from .ssrf import guarded_get

    return guarded_get(url, timeout=15).decode("utf-8")


class HttpsBackend(RegistryBackend):
    """Fetches a realm ``peers.json`` over HTTPS (opt-in).

    The endpoint is ``url_template.format(realm=...)`` — e.g.
    ``https://registry.{realm}/peers.json``. The HTTP fetcher is **injected** so
    tests pass a fake returning a fixture string; the default uses ``urllib`` and
    is never exercised by the test suite.
    """

    name = "https"

    def __init__(
        self,
        url_template: str = "https://registry.{realm}/peers.json",
        realm: Optional[str] = None,
        fetcher: Optional[Fetcher] = None,
    ):
        self.url_template = url_template
        self.realm = realm or get_realm()
        self._fetch = fetcher or _default_https_fetcher

    @property
    def url(self) -> str:
        return self.url_template.format(realm=self.realm)

    def _load(self) -> dict:
        try:
            raw = self._fetch(self.url)
            data = json.loads(raw)
        except Exception as exc:  # network down / bad JSON -> a miss, not a crash
            logger.warning("https registry fetch failed (%s): %s", self.url, exc)
            return {}
        peers = data.get("peers") if isinstance(data, dict) else None
        return peers if isinstance(peers, dict) else {}

    def lookup(self, fqid: str) -> Optional[PeerRecord]:
        entry = self._load().get(fqid)
        if not entry:
            return None
        return PeerRecord.from_entry(fqid, entry, self.name)

    def list(self) -> list[PeerRecord]:
        return [
            PeerRecord.from_entry(fqid, entry, self.name)
            for fqid, entry in self._load().items()
            if isinstance(entry, dict)
        ]


# ---------------------------------------------------------------------------
# TailscaleBackend (opt-in) — injected status_runner
# ---------------------------------------------------------------------------


def _default_status_runner() -> dict:
    """Real ``tailscale status --json`` (only used outside tests)."""
    import subprocess

    out = subprocess.run(
        ["tailscale", "status", "--json"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return json.loads(out.stdout)


class TailscaleBackend(RegistryBackend):
    """Resolves peers via the tailnet (opt-in).

    Maps a tailnet node to an fqid by its hostname using ``host_template``
    (default ``skcomms-{agent}-{operator}``). The ``tailscale status --json`` dict
    is supplied by an **injected** ``status_runner`` so tests pass a fixture; the
    default shells out and is never run by the test suite.

    A produced record carries a ``tailscale`` hint of
    ``{node, magicdns, ip}`` (the first IPv4 in ``TailscaleIPs`` when present).
    """

    name = "tailscale"

    def __init__(
        self,
        status_runner: Optional[StatusRunner] = None,
        host_template: str = "skcomms-{agent}-{operator}",
        tag: str = "tag:skcomms",
    ):
        self._status = status_runner or _default_status_runner
        self.host_template = host_template
        self.tag = tag

    # --- status parsing ---------------------------------------------------

    def _nodes(self) -> list[dict]:
        """Flatten Self + Peer entries from ``tailscale status --json``."""
        try:
            status = self._status() or {}
        except Exception as exc:  # tailscale not installed / not up -> miss
            logger.warning("tailscale status failed: %s", exc)
            return []
        nodes: list[dict] = []
        if isinstance(status.get("Self"), dict):
            nodes.append(status["Self"])
        peers = status.get("Peer")
        if isinstance(peers, dict):
            nodes.extend(p for p in peers.values() if isinstance(p, dict))
        return nodes

    @staticmethod
    def _hostname(node: dict) -> str:
        """Best hostname for a node — HostName, else the DNSName left-label."""
        host = node.get("HostName")
        if host:
            return str(host)
        dns = node.get("DNSName") or ""
        return str(dns).rstrip(".").split(".", 1)[0]

    @staticmethod
    def _magicdns(node: dict) -> Optional[str]:
        dns = node.get("DNSName")
        return str(dns).rstrip(".") if dns else None

    @staticmethod
    def _ipv4(node: dict) -> Optional[str]:
        for ip in node.get("TailscaleIPs", []) or []:
            if ":" not in str(ip):
                return str(ip)
        ips = node.get("TailscaleIPs") or []
        return str(ips[0]) if ips else None

    def _hint(self, node: dict) -> dict:
        hint = {"node": self._hostname(node)}
        magic = self._magicdns(node)
        if magic:
            hint["magicdns"] = magic
        ip = self._ipv4(node)
        if ip:
            hint["ip"] = ip
        return hint

    def _agent_operator(self, host: str) -> Optional[tuple[str, str]]:
        """Parse ``skcomms-<agent>-<operator>`` -> ``(agent, operator)``."""
        prefix = self.host_template.split("{", 1)[0]  # "skcomms-"
        if not host.startswith(prefix):
            return None
        rest = host[len(prefix):]
        if "-" not in rest:
            return None
        agent, operator = rest.split("-", 1)
        if not agent or not operator:
            return None
        return agent, operator

    # --- backend API ------------------------------------------------------

    def lookup(self, fqid: str) -> Optional[PeerRecord]:
        try:
            agent, operator, _realm = _split_fqid(fqid)
        except ValueError:
            return None
        want = self.host_template.format(agent=agent, operator=operator)
        for node in self._nodes():
            if self._hostname(node) == want:
                return PeerRecord(
                    fqid=fqid, operator=operator, tailscale=self._hint(node), source=self.name
                )
        return None

    def list(self) -> list[PeerRecord]:
        out: list[PeerRecord] = []
        for node in self._nodes():
            host = self._hostname(node)
            tagged = self.tag in (node.get("Tags") or [])
            parsed = self._agent_operator(host)
            if parsed is None and not tagged:
                continue
            if parsed is None:
                # tagged but non-conventional host — skip (can't form an fqid)
                continue
            agent, operator = parsed
            # realm is realm-local; use the configured/default realm for display
            fqid = f"{agent}@{operator}.{get_realm()}"
            out.append(
                PeerRecord(
                    fqid=fqid, operator=operator, tailscale=self._hint(node), source=self.name
                )
            )
        return out


# ---------------------------------------------------------------------------
# PeerRegistry — order + merge
# ---------------------------------------------------------------------------


class PeerRegistry:
    """Resolves an fqid across enabled backends, merging their hints.

    Backends are consulted in list order; :meth:`resolve` returns the merged
    :class:`PeerRecord` (or ``None`` if no backend has the peer). The first
    backend to supply a given field is authoritative for it (see
    :meth:`PeerRecord.merge`).
    """

    def __init__(self, backends: list[RegistryBackend]):
        self.backends = list(backends)

    # --- factory ----------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        config=None,
        *,
        https_fetcher: Optional[Fetcher] = None,
        tailscale_status_runner: Optional[StatusRunner] = None,
        realm: Optional[str] = None,
    ) -> "PeerRegistry":
        """Build a registry from a :class:`skcomms.config.RegistryConfig`.

        Sovereign default (no config): only the offline ``syncthing-shared``
        backend is enabled. Injectables (``https_fetcher``,
        ``tailscale_status_runner``) are forwarded to the respective backends so
        callers/tests can stub I/O.

        Args:
            config: A ``RegistryConfig`` (default: sovereign defaults).
            https_fetcher: Optional injected HTTP fetcher for the https backend.
            tailscale_status_runner: Optional injected tailscale status runner.
            realm: Override realm (default: from ``cluster.json``).
        """
        from .config import RegistryConfig

        cfg = config or RegistryConfig()
        the_realm = realm or get_realm()

        def _make(name: str) -> Optional[RegistryBackend]:
            if name == "syncthing-shared":
                return SyncthingSharedBackend()
            if name == "https":
                return HttpsBackend(
                    url_template=cfg.https_url_template,
                    realm=the_realm,
                    fetcher=https_fetcher,
                )
            if name == "tailscale":
                return TailscaleBackend(
                    status_runner=tailscale_status_runner,
                    host_template=cfg.tailscale_host_template,
                    tag=cfg.tailscale_tag,
                )
            logger.warning("unknown registry backend in config: %s", name)
            return None

        enabled = set(cfg.enabled)
        # Consult enabled backends in the configured `order`; unlisted enabled
        # names are appended after, preserving their declared sequence.
        ordered = [n for n in cfg.order if n in enabled]
        ordered += [n for n in cfg.enabled if n not in ordered]

        backends = [b for b in (_make(n) for n in ordered) if b is not None]
        return cls(backends)

    # --- resolution -------------------------------------------------------

    def resolve(self, fqid: str) -> Optional[PeerRecord]:
        """Resolve *fqid* across enabled backends, merging hints in order.

        Returns ``None`` if no backend knows the peer.
        """
        merged: Optional[PeerRecord] = None
        for backend in self.backends:
            try:
                rec = backend.lookup(fqid)
            except Exception as exc:  # a misbehaving backend never breaks resolve
                logger.warning("backend %s lookup failed for %s: %s", backend.name, fqid, exc)
                continue
            if rec is None:
                continue
            merged = rec if merged is None else merged.merge(rec)
        return merged

    def list(self) -> list[PeerRecord]:
        """List every peer known to any backend, merging duplicate fqids."""
        by_fqid: dict[str, PeerRecord] = {}
        for backend in self.backends:
            try:
                recs = backend.list()
            except Exception as exc:
                logger.warning("backend %s list failed: %s", backend.name, exc)
                continue
            for rec in recs:
                if rec.fqid in by_fqid:
                    by_fqid[rec.fqid] = by_fqid[rec.fqid].merge(rec)
                else:
                    by_fqid[rec.fqid] = rec
        return list(by_fqid.values())
