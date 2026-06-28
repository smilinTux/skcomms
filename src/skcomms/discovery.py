"""
SKComms peer discovery — find agents on the network and mesh.

Discovery sources (tried in order):
    1. Syncthing comms directories (always available)
    2. File transport inbox/outbox scanning (always available)
    3. Nostr relay metadata queries (if nostr deps installed)
    4. mDNS/Zeroconf LAN announcements (if zeroconf installed)

Discovered peers are persisted as YAML files in ~/.skcapstone/skcomms/peers/
and used by the Router to resolve agent names to transport configs.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from .config import SKCOMMS_HOME

logger = logging.getLogger("skcomms.discovery")

PEERS_DIR_NAME = "peers"
ENVELOPE_SUFFIX = ".skc.json"

# mDNS service type for LAN discovery
MDNS_SERVICE_TYPE = "_skcomms._tcp.local."
MDNS_SERVICE_PORT = 22067


# ---------------------------------------------------------------------------
# Peer model
# ---------------------------------------------------------------------------


class PeerTransport(BaseModel):
    """Transport-specific config for reaching a peer.

    Attributes:
        transport: Transport name (syncthing, file, nostr, etc.).
        settings: Transport-specific connection settings.
    """

    transport: str
    settings: dict = Field(default_factory=dict)


class PeerInfo(BaseModel):
    """Discovered or manually-added peer.

    Attributes:
        name: Human-readable agent name.
        fqid: Full ``<agent>@<operator>.<realm>`` handle, if known. Used by
            federation addressing (``inbox_url_for``) and as the verifier key.
        fingerprint: PGP fingerprint (CapAuth identity), if known.
        pubkey: Pinned ASCII-armored PGP public key (TOFU). The trusted key
            an S2S inbox loads into its :class:`~skcomms.signing.EnvelopeVerifier`.
        nostr_pubkey: Nostr x-only hex pubkey, if known.
        transports: List of transport configs for reaching this peer.
        rails: Ordered rail preference (transport names, most-preferred first)
            the router honors ahead of global priority (SKFed S3/S5).
        discovered_via: How this peer was found (syncthing, mdns, manual, etc.).
        last_seen: When the peer was last observed active.
    """

    name: str
    fqid: Optional[str] = None
    fingerprint: Optional[str] = None
    pubkey: Optional[str] = None
    nostr_pubkey: Optional[str] = None
    transports: list[PeerTransport] = Field(default_factory=list)
    rails: list[str] = Field(default_factory=list)
    discovered_via: str = "manual"
    last_seen: Optional[datetime] = None

    def inbox_url(self) -> Optional[str]:
        """Return this peer's ``https-s2s`` inbox URL, if it carries one."""
        for t in self.transports:
            if t.transport == "https-s2s":
                url = t.settings.get("inbox_url")
                if url:
                    return url
        return None

    def merge(self, other: PeerInfo) -> PeerInfo:
        """Merge another PeerInfo into this one, keeping the richest data.

        Args:
            other: Peer info to merge from.

        Returns:
            New PeerInfo with merged fields.
        """
        fingerprint = self.fingerprint or other.fingerprint
        nostr_pubkey = self.nostr_pubkey or other.nostr_pubkey
        fqid = self.fqid or other.fqid
        pubkey = self.pubkey or other.pubkey
        rails = self.rails or other.rails
        last_seen = max(
            filter(None, [self.last_seen, other.last_seen]),
            default=None,
        )

        existing_transports = {t.transport: t for t in self.transports}
        for t in other.transports:
            if t.transport not in existing_transports:
                existing_transports[t.transport] = t
            else:
                merged_settings = {**existing_transports[t.transport].settings, **t.settings}
                existing_transports[t.transport] = PeerTransport(
                    transport=t.transport,
                    settings=merged_settings,
                )

        return PeerInfo(
            name=self.name,
            fqid=fqid,
            fingerprint=fingerprint,
            pubkey=pubkey,
            nostr_pubkey=nostr_pubkey,
            transports=list(existing_transports.values()),
            rails=rails,
            discovered_via=self.discovered_via,
            last_seen=last_seen,
        )


# ---------------------------------------------------------------------------
# Peer store (YAML persistence)
# ---------------------------------------------------------------------------


class PeerStore:
    """Persistent peer registry at ~/.skcapstone/skcomms/peers/.

    Each peer is stored as a YAML file named {name}.yml.

    Args:
        peers_dir: Directory for peer YAML files.
    """

    def __init__(self, peers_dir: Optional[Path] = None):
        self._dir = peers_dir or Path(SKCOMMS_HOME).expanduser() / PEERS_DIR_NAME
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def peers_dir(self) -> Path:
        """Path to the peers directory."""
        return self._dir

    def add(self, peer: PeerInfo) -> None:
        """Add or update a peer in the store.

        If a peer with the same name exists, fields are merged.

        Args:
            peer: PeerInfo to save.
        """
        existing = self.get(peer.name)
        if existing:
            peer = existing.merge(peer)
        path = self._peer_path(peer.name)
        data = peer.model_dump(mode="json", exclude_none=True)
        path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
        logger.debug("Saved peer %s to %s", peer.name, path)

    def get(self, name: str) -> Optional[PeerInfo]:
        """Retrieve a peer by name.

        Args:
            name: Agent name.

        Returns:
            PeerInfo or None if not found.
        """
        path = self._peer_path(name)
        if not path.exists():
            return None
        try:
            raw = yaml.safe_load(path.read_text())
            return PeerInfo.model_validate(raw)
        except Exception as exc:
            logger.warning("Failed to load peer %s: %s", name, exc)
            return None

    def list_all(self) -> list[PeerInfo]:
        """List all stored peers.

        Returns:
            List of PeerInfo, sorted by name.
        """
        peers: list[PeerInfo] = []
        for path in sorted(self._dir.glob("*.yml")):
            try:
                raw = yaml.safe_load(path.read_text())
                peers.append(PeerInfo.model_validate(raw))
            except Exception as exc:
                logger.warning("Skipping invalid peer file %s: %s", path.name, exc)
        return peers

    def remove(self, name: str) -> bool:
        """Remove a peer from the store.

        Args:
            name: Agent name to remove.

        Returns:
            True if the peer was found and removed.
        """
        path = self._peer_path(name)
        if path.exists():
            path.unlink()
            logger.info("Removed peer %s", name)
            return True
        return False

    def _peer_path(self, name: str) -> Path:
        """Sanitized path for a peer YAML file.

        Strips unsafe characters and verifies the resolved path stays
        within the peers directory to prevent path traversal.

        Args:
            name: Peer name (should already be validated by the API layer).

        Returns:
            Path to the peer YAML file.

        Raises:
            ValueError: If the resulting path escapes the peers directory.
        """
        safe_name = "".join(c for c in name if c.isalnum() or c in "-_")
        if not safe_name:
            raise ValueError(f"Peer name '{name}' is empty after sanitization")
        result = (self._dir / f"{safe_name}.yml").resolve()
        if not str(result).startswith(str(self._dir.resolve())):
            raise ValueError(f"Peer name '{name}' resolves outside peers directory")
        return result


# ---------------------------------------------------------------------------
# Discovery: Syncthing comms directories
# ---------------------------------------------------------------------------


def discover_syncthing(comms_root: Optional[Path] = None) -> list[PeerInfo]:
    """Scan Syncthing comms directories for peer folders.

    Looks for per-peer subdirectories under inbox/ and outbox/.
    Extracts sender info from envelope files when possible.

    Args:
        comms_root: Root of the comms folder (default ~/.skcapstone/comms).

    Returns:
        List of discovered PeerInfo.
    """
    root = comms_root or Path("~/.skcapstone/comms").expanduser()
    peers: dict[str, PeerInfo] = {}
    datetime.now(timezone.utc)

    for subdir in ["inbox", "outbox"]:
        base = root / subdir
        if not base.exists():
            continue
        for peer_dir in base.iterdir():
            if not peer_dir.is_dir() or peer_dir.name.startswith("."):
                continue
            name = peer_dir.name
            if name not in peers:
                peers[name] = PeerInfo(
                    name=name,
                    discovered_via="syncthing",
                    transports=[
                        PeerTransport(
                            transport="syncthing",
                            settings={"comms_root": str(root)},
                        )
                    ],
                )

            last_seen = _newest_envelope_time(peer_dir)
            if last_seen:
                peers[name].last_seen = last_seen

            fingerprint = _extract_sender_fingerprint(peer_dir)
            if fingerprint:
                peers[name].fingerprint = fingerprint

    logger.info("Syncthing discovery: found %d peer(s)", len(peers))
    return list(peers.values())


# ---------------------------------------------------------------------------
# Discovery: File transport directories
# ---------------------------------------------------------------------------


def discover_file_transport(
    inbox_path: Optional[Path] = None,
    outbox_path: Optional[Path] = None,
) -> list[PeerInfo]:
    """Scan file transport directories for peer traces.

    Extracts sender/recipient from envelope JSON files.

    Args:
        inbox_path: File transport inbox (default ~/.skcapstone/skcomms/inbox).
        outbox_path: File transport outbox (default ~/.skcapstone/skcomms/outbox).

    Returns:
        List of discovered PeerInfo.
    """
    inbox = inbox_path or Path(SKCOMMS_HOME).expanduser() / "inbox"
    outbox = outbox_path or Path(SKCOMMS_HOME).expanduser() / "outbox"
    peers: dict[str, PeerInfo] = {}

    for directory in [inbox, outbox]:
        if not directory.exists():
            continue
        for env_file in directory.glob(f"*{ENVELOPE_SUFFIX}"):
            if env_file.name.startswith("."):
                continue
            info = _parse_envelope_for_peer(env_file)
            if info and info.name not in peers:
                peers[info.name] = info
            elif info and info.name in peers:
                peers[info.name] = peers[info.name].merge(info)

    logger.info("File transport discovery: found %d peer(s)", len(peers))
    return list(peers.values())


# ---------------------------------------------------------------------------
# Discovery: mDNS / Zeroconf (optional)
# ---------------------------------------------------------------------------


def discover_mdns(timeout: float = 3.0) -> list[PeerInfo]:
    """Scan the local network for SKComms agents via mDNS.

    Requires the `zeroconf` package. Returns empty list if not installed.

    Args:
        timeout: How long to listen for announcements (seconds).

    Returns:
        List of discovered PeerInfo from LAN.
    """
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError:
        logger.debug("zeroconf not installed — skipping mDNS discovery")
        return []

    peers: list[PeerInfo] = []

    class _Listener:
        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name)
            if info is None:
                return
            props = {k.decode(): v.decode() for k, v in info.properties.items()}
            agent_name = props.get("name", name.split(".")[0])
            peer = PeerInfo(
                name=agent_name,
                fingerprint=props.get("fingerprint"),
                nostr_pubkey=props.get("nostr_pubkey"),
                discovered_via="mdns",
                last_seen=datetime.now(timezone.utc),
                transports=[
                    PeerTransport(
                        transport="mdns",
                        settings={
                            "host": str(info.server),
                            "port": info.port,
                            "addresses": [addr for addr in (info.parsed_addresses() or [])],
                        },
                    )
                ],
            )
            peers.append(peer)

        def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            pass

        def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            pass

    zc = Zeroconf()
    try:
        listener = _Listener()
        ServiceBrowser(zc, MDNS_SERVICE_TYPE, listener)
        time.sleep(timeout)
    finally:
        zc.close()

    logger.info("mDNS discovery: found %d peer(s)", len(peers))
    return peers


def register_mdns(
    name: str,
    fingerprint: Optional[str] = None,
    nostr_pubkey: Optional[str] = None,
    port: int = MDNS_SERVICE_PORT,
) -> object | None:
    """Announce this agent on the local network via mDNS.

    Args:
        name: Agent name to advertise.
        fingerprint: PGP fingerprint to include in TXT record.
        nostr_pubkey: Nostr pubkey to include in TXT record.
        port: Port number for the service.

    Returns:
        The Zeroconf instance (caller must close it), or None if unavailable.
    """
    try:
        import socket

        from zeroconf import ServiceInfo, Zeroconf
    except ImportError:
        logger.debug("zeroconf not installed — cannot register mDNS")
        return None

    props = {"name": name}
    if fingerprint:
        props["fingerprint"] = fingerprint
    if nostr_pubkey:
        props["nostr_pubkey"] = nostr_pubkey

    hostname = socket.gethostname()
    info = ServiceInfo(
        MDNS_SERVICE_TYPE,
        f"{name}.{MDNS_SERVICE_TYPE}",
        port=port,
        properties=props,
        server=f"{hostname}.local.",
    )

    zc = Zeroconf()
    zc.register_service(info)
    logger.info("Registered mDNS service: %s on port %d", name, port)
    return zc


# ---------------------------------------------------------------------------
# Combined discovery
# ---------------------------------------------------------------------------


def discover_all(
    comms_root: Optional[Path] = None,
    inbox_path: Optional[Path] = None,
    outbox_path: Optional[Path] = None,
    mdns_timeout: float = 3.0,
    skip_mdns: bool = False,
) -> list[PeerInfo]:
    """Run all discovery methods and merge results.

    Args:
        comms_root: Syncthing comms root directory.
        inbox_path: File transport inbox.
        outbox_path: File transport outbox.
        mdns_timeout: mDNS scan duration in seconds.
        skip_mdns: Skip mDNS discovery (faster for non-LAN use).

    Returns:
        Deduplicated list of PeerInfo from all sources.
    """
    merged: dict[str, PeerInfo] = {}

    for peer in discover_syncthing(comms_root):
        if peer.name in merged:
            merged[peer.name] = merged[peer.name].merge(peer)
        else:
            merged[peer.name] = peer

    for peer in discover_file_transport(inbox_path, outbox_path):
        if peer.name in merged:
            merged[peer.name] = merged[peer.name].merge(peer)
        else:
            merged[peer.name] = peer

    if not skip_mdns:
        for peer in discover_mdns(timeout=mdns_timeout):
            if peer.name in merged:
                merged[peer.name] = merged[peer.name].merge(peer)
            else:
                merged[peer.name] = peer

    return sorted(merged.values(), key=lambda p: p.name)


# ---------------------------------------------------------------------------
# Federation addressing (SKFed S5)
# ---------------------------------------------------------------------------


def inbox_url_for(
    fqid: str,
    store: Optional[PeerStore] = None,
    registry: Optional["NodeRegistry"] = None,
) -> Optional[str]:
    """Resolve a reachable ``/api/v1/inbox`` URL for a peer *fqid*.

    Resolution order (durable cross-node addressing):

        1. **Node registry** (:mod:`skcomms.node_registry`) — PREFERRED. Maps the
           peer's short agent name to ``{ts_host|ts_ip, daemon_port}`` and emits
           ``http://<ts-ip-or-host>:<port>/api/v1/inbox``. This is durable across
           tailnet IP changes (the registry is the single place to update).
        2. **Peer transport** — FALLBACK. The ``inbox_url`` carried on the peer's
           ``https-s2s`` transport entry in the :class:`PeerStore` (the legacy
           hardcoded value), kept for back-compat and as a degrade path.
        3. ``None`` — when neither resolves. Never raises.

    The peer is matched by ``fqid`` field first, then by ``name``, then by the
    agent component of the fqid.

    Args:
        fqid: The peer's ``<agent>@<operator>.<realm>`` handle (or bare name).
        store: Optional :class:`PeerStore` (a default one is used otherwise).
        registry: Optional :class:`~skcomms.node_registry.NodeRegistry`. When
            ``None`` a default one is loaded from ``node_registry.yml`` (an empty
            registry if the file is absent — clean fallback to the transport).

    Returns:
        A reachable S2S inbox URL, or ``None`` if the peer is unknown / has no
        resolvable address.
    """
    # 1) Node registry (preferred, durable). Total — any failure -> fallback.
    agent_short = fqid.split("@", 1)[0] if "@" in fqid else fqid
    try:
        from .node_registry import NodeRegistry

        reg = registry if registry is not None else NodeRegistry.load()
        url = reg.inbox_url(agent_short)
        if url:
            return url
    except Exception as exc:  # never let registry resolution break delivery
        logger.debug("node_registry lookup failed for %s: %s", fqid, exc)

    # 2) Peer transport (legacy/back-compat fallback).
    store = store or PeerStore()
    candidates = [fqid]
    if "@" in fqid:
        candidates.append(fqid.split("@", 1)[0])  # bare agent name
    for peer in store.list_all():
        if peer.fqid == fqid or peer.name in candidates or peer.fqid in candidates:
            url = peer.inbox_url()
            if url:
                return url
    return None


def migrate_file_transports(store: Optional[PeerStore] = None) -> list[str]:
    """Strip legacy dead-end ``file://`` transport entries from stored peers.

    The early manual peer-add path recorded ``file`` transports whose
    ``settings.inbox_path`` pointed at a local ``file://`` URI — a dead end for
    federation (the bytes never leave the box). This drops those entries so the
    router falls through to a live rail (``https-s2s``/syncthing/nostr).

    Args:
        store: Optional :class:`PeerStore` (a default one is used otherwise).

    Returns:
        Names of the peers whose stored entry was rewritten.
    """
    store = store or PeerStore()
    migrated: list[str] = []
    for peer in store.list_all():
        kept = [
            t
            for t in peer.transports
            if not (
                t.transport == "file"
                and str(t.settings.get("inbox_path", "")).startswith("file://")
            )
        ]
        if len(kept) != len(peer.transports):
            path = store._peer_path(peer.name)
            cleaned = PeerInfo(
                name=peer.name,
                fqid=peer.fqid,
                fingerprint=peer.fingerprint,
                pubkey=peer.pubkey,
                nostr_pubkey=peer.nostr_pubkey,
                transports=kept,
                rails=peer.rails,
                discovered_via=peer.discovered_via,
                last_seen=peer.last_seen,
            )
            data = cleaned.model_dump(mode="json", exclude_none=True)
            path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
            migrated.append(peer.name)
    return migrated


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _newest_envelope_time(directory: Path) -> Optional[datetime]:
    """Get the modification time of the newest envelope file in a directory."""
    newest = None
    for f in directory.glob(f"*{ENVELOPE_SUFFIX}"):
        mtime = f.stat().st_mtime
        dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        if newest is None or dt > newest:
            newest = dt
    return newest


def _extract_sender_fingerprint(directory: Path) -> Optional[str]:
    """Try to extract a sender fingerprint from the newest envelope file."""
    envelopes = sorted(directory.glob(f"*{ENVELOPE_SUFFIX}"), key=lambda f: f.stat().st_mtime)
    if not envelopes:
        return None
    try:
        data = json.loads(envelopes[-1].read_bytes())
        sender = data.get("sender", "")
        # Reason: fingerprints are 40 hex chars; agent names are shorter
        if len(sender) == 40 and all(c in "0123456789abcdefABCDEF" for c in sender):
            return sender
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _parse_envelope_for_peer(env_file: Path) -> Optional[PeerInfo]:
    """Extract peer info from an envelope JSON file."""
    try:
        data = json.loads(env_file.read_bytes())
        sender = data.get("sender", "")
        if not sender or sender == "unknown":
            return None
        mtime = datetime.fromtimestamp(env_file.stat().st_mtime, tz=timezone.utc)
        fingerprint = None
        if len(sender) == 40 and all(c in "0123456789abcdefABCDEF" for c in sender):
            fingerprint = sender
        return PeerInfo(
            name=sender,
            fingerprint=fingerprint,
            discovered_via="file",
            last_seen=mtime,
            transports=[
                PeerTransport(
                    transport="file",
                    settings={"inbox_path": str(env_file.parent)},
                )
            ],
        )
    except (json.JSONDecodeError, OSError):
        return None
