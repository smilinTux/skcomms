"""Sovereign node registry — durable cross-node inbox addressing.

The cross-node ratchet used to HARDCODE a tailscale IP into each peer file's
``transports[].settings.inbox_url`` (e.g. ``http://100.86.156.5:8765/api/v1/inbox``).
When a node moved (new tailnet IP, re-keyed device) every peer's file went stale
and delivery silently broke. This module makes that addressing **durable**.

A tiny config maps each node's short agent name to *how to reach its daemon*::

    # ~/.skcapstone/skcomms/node_registry.yml
    nodes:
      jarvis:
        ts_ip: 100.86.156.5      # explicit tailnet IP (preferred if set)
        daemon_port: 8765        # optional; defaults to 8765
      lumina:
        ts_host: noroc2027       # magicDNS / tailnet hostname
        # daemon_port omitted -> 8765

A bare top-level mapping (``jarvis: {ts_ip: ...}`` without the ``nodes:`` key)
is also accepted for resilience.

The resolver emits a REACHABLE URL for the :8765 daemon-proxy, which serves
**both** ``/api/v1/inbox`` (S2S envelopes) and ``/api/v1/prekey`` (PQ prekey
fetch). Resolution order for one entry:

    1. ``ts_ip`` present            -> use it verbatim.
    2. ``ts_host`` present          -> optionally derive the tailnet IPv4 from an
                                       INJECTED ``tailscale status --json`` dict;
                                       if no provider / no match / provider error,
                                       fall back to the host literal (magicDNS is
                                       reachable as-is).
    3. neither                      -> ``None`` (degrade gracefully, never crash).

Design notes:
    * All tailscale access is **injected** (``status_provider`` callable) so the
      test suite never shells out. The default registry does NOT auto-shell
      tailscale — the literal-host path keeps the hot path subprocess-free and
      live-safe. Callers that want IP derivation pass
      :func:`default_tailscale_status` (or any fixture) explicitly.
    * Loading is total: a missing or malformed file yields an EMPTY registry, so
      :func:`skcomms.discovery.inbox_url_for` cleanly falls back to the peer's
      existing transport ``inbox_url`` and never raises.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Optional, Union

import yaml
from pydantic import BaseModel, Field

from .home import skcomms_home

logger = logging.getLogger("skcomms.node_registry")

REGISTRY_FILE_NAME = "node_registry.yml"
DEFAULT_DAEMON_PORT = 8765
INBOX_PATH = "/api/v1/inbox"
PREKEY_PATH = "/api/v1/prekey"

# A status provider returns a parsed ``tailscale status --json`` dict.
StatusProvider = Callable[[], dict]


# ---------------------------------------------------------------------------
# Entry model
# ---------------------------------------------------------------------------


class NodeEntry(BaseModel):
    """How to reach one node's skcomms daemon-proxy.

    Attributes:
        ts_ip: Explicit tailnet IPv4 (preferred when set).
        ts_host: Tailnet / magicDNS hostname. Used literally, or resolved to a
            tailnet IP via an injected ``tailscale status`` dict.
        daemon_port: Daemon-proxy port (serves both inbox + prekey).
            Defaults to 8765.
    """

    ts_ip: Optional[str] = None
    ts_host: Optional[str] = None
    daemon_port: int = DEFAULT_DAEMON_PORT


# Either a fully-built entry or the raw dict from YAML.
EntryLike = Union[NodeEntry, dict]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class NodeRegistry:
    """Maps short agent names to reachable daemon-proxy endpoint URLs.

    Args:
        entries: Mapping of ``agent-short -> NodeEntry`` (or raw dicts, which are
            coerced). Invalid entries are skipped, not fatal.
        status_provider: Optional injected callable returning a
            ``tailscale status --json`` dict, used to derive a tailnet IP from a
            node's ``ts_host``. ``None`` (default) means no tailscale call — a
            ``ts_host`` is then used literally.
    """

    def __init__(
        self,
        entries: Optional[dict[str, EntryLike]] = None,
        status_provider: Optional[StatusProvider] = None,
    ):
        self._entries: dict[str, NodeEntry] = {}
        for name, entry in (entries or {}).items():
            coerced = self._coerce(name, entry)
            if coerced is not None:
                self._entries[name] = coerced
        self._status_provider = status_provider

    # --- construction -----------------------------------------------------

    @staticmethod
    def _coerce(name: str, entry: EntryLike) -> Optional[NodeEntry]:
        if isinstance(entry, NodeEntry):
            return entry
        if isinstance(entry, dict):
            try:
                return NodeEntry.model_validate(entry)
            except Exception as exc:  # malformed single entry -> skip, don't crash
                logger.warning("node_registry: bad entry for %r: %s", name, exc)
                return None
        logger.warning("node_registry: ignoring non-mapping entry for %r", name)
        return None

    @classmethod
    def load(
        cls,
        path: Optional[Path] = None,
        status_provider: Optional[StatusProvider] = None,
    ) -> "NodeRegistry":
        """Load a registry from ``node_registry.yml`` (total, never raises).

        Accepts either a ``nodes:`` section or a bare ``agent -> entry`` mapping.
        A missing or malformed file yields an EMPTY registry.

        Args:
            path: Registry file path. Defaults to
                ``${SKCOMMS_HOME}/node_registry.yml``.
            status_provider: Optional injected tailscale-status callable.

        Returns:
            A :class:`NodeRegistry` (possibly empty).
        """
        path = path or (skcomms_home() / REGISTRY_FILE_NAME)
        path = Path(path).expanduser()
        if not path.exists():
            logger.debug("node_registry: no file at %s — empty registry", path)
            return cls(entries={}, status_provider=status_provider)
        try:
            raw = yaml.safe_load(path.read_text()) or {}
        except Exception as exc:  # malformed YAML -> empty, never fatal
            logger.warning("node_registry: failed to parse %s: %s", path, exc)
            return cls(entries={}, status_provider=status_provider)
        if not isinstance(raw, dict):
            logger.warning("node_registry: %s is not a mapping — ignoring", path)
            return cls(entries={}, status_provider=status_provider)
        section = raw.get("nodes") if isinstance(raw.get("nodes"), dict) else raw
        if not isinstance(section, dict):
            section = {}
        return cls(entries=section, status_provider=status_provider)

    # --- resolution -------------------------------------------------------

    def has(self, agent: str) -> bool:
        """True if the registry carries an entry for *agent*."""
        return agent in self._entries

    def resolve_host(self, agent: str) -> Optional[str]:
        """Resolve the reachable host (IP or hostname) for *agent*.

        Returns ``None`` when the agent is unknown or its entry carries neither
        ``ts_ip`` nor ``ts_host``.
        """
        entry = self._entries.get(agent)
        if entry is None:
            return None
        if entry.ts_ip:
            return entry.ts_ip
        if entry.ts_host:
            derived = self._derive_ip(entry.ts_host)
            return derived or entry.ts_host
        return None

    def endpoint_url(self, agent: str, path: str = INBOX_PATH) -> Optional[str]:
        """Build ``http://<host>:<port><path>`` for *agent*, or ``None``."""
        host = self.resolve_host(agent)
        if not host:
            return None
        entry = self._entries[agent]
        if not path.startswith("/"):
            path = "/" + path
        return f"http://{host}:{entry.daemon_port}{path}"

    def inbox_url(self, agent: str) -> Optional[str]:
        """Reachable ``/api/v1/inbox`` URL for *agent* (or ``None``)."""
        return self.endpoint_url(agent, INBOX_PATH)

    def prekey_url(self, agent: str) -> Optional[str]:
        """Reachable ``/api/v1/prekey`` URL for *agent* (or ``None``)."""
        return self.endpoint_url(agent, PREKEY_PATH)

    # --- tailscale derivation (injected; total) ---------------------------

    def _derive_ip(self, ts_host: str) -> Optional[str]:
        """Best-effort tailnet IPv4 for *ts_host* via the injected status dict.

        Returns ``None`` on any failure (no provider, provider error, no match)
        so the caller falls back to the literal host. Never raises.
        """
        if self._status_provider is None:
            return None
        try:
            status = self._status_provider() or {}
        except Exception as exc:  # tailscale down / not installed -> literal host
            logger.warning("node_registry: status provider failed: %s", exc)
            return None
        target = ts_host.rstrip(".").split(".", 1)[0].lower()
        for node in _flatten_status_nodes(status):
            if _node_hostname(node).lower() == target:
                return _node_ipv4(node)
        return None


# ---------------------------------------------------------------------------
# tailscale status helpers (module-level, reusable)
# ---------------------------------------------------------------------------


def _flatten_status_nodes(status: dict) -> list[dict]:
    """Flatten ``Self`` + ``Peer`` entries from a ``tailscale status`` dict."""
    nodes: list[dict] = []
    if isinstance(status.get("Self"), dict):
        nodes.append(status["Self"])
    peers = status.get("Peer")
    if isinstance(peers, dict):
        nodes.extend(p for p in peers.values() if isinstance(p, dict))
    return nodes


def _node_hostname(node: dict) -> str:
    """Best hostname for a node — ``HostName`` else the ``DNSName`` left-label."""
    host = node.get("HostName")
    if host:
        return str(host)
    dns = node.get("DNSName") or ""
    return str(dns).rstrip(".").split(".", 1)[0]


def _node_ipv4(node: dict) -> Optional[str]:
    """First IPv4 in ``TailscaleIPs`` (else first address, else None)."""
    for ip in node.get("TailscaleIPs", []) or []:
        if ":" not in str(ip):
            return str(ip)
    ips = node.get("TailscaleIPs") or []
    return str(ips[0]) if ips else None


def default_tailscale_status() -> dict:
    """Real ``tailscale status --json`` (opt-in; never run by the test suite)."""
    import subprocess

    out = subprocess.run(
        ["tailscale", "status", "--json"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return json.loads(out.stdout)
