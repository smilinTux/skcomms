"""SKFed P7 / A5 — access-plane federation routing.

The access plane is per-node: a file lives on the node where it physically is,
and a knowledge hit carries ``{node, path}``. This module is the thin layer that
makes a tool call for a *remote* file transparently **route to that node's
sk-access server** over the tailnet — no file syncing, capauth-signed end to end.

Three pieces:

* a **node resolver** (:class:`NodeResolver`) — maps a ``node`` id
  (``".158"`` / ``".41"`` / an fqid / a peer name) to that node's sk-access
  **base URL** on the tailnet, reusing the :class:`~skcomms.discovery.PeerStore`.
  :func:`local_node` knows *self* (from :class:`~skcomms.access.config.AccessConfig`
  / ``SKACCESS_NODE``), so a call for the local node never leaves the box.

* a **remote client** (:func:`call_remote`) — POSTs a **capauth-signed** request
  to a peer's sk-access ``/tool`` endpoint over the tailnet. The request is a
  :class:`~skcomms.envelope.SignedEnvelope` whose body carries
  ``{"tool": ..., "arguments": ...}``; we sign with *this* node's capauth key and
  the peer verifies it against its TOFU pinset (the gate already built in
  :meth:`~skcomms.access.server.AccessServer.authenticate`). Returns the tool
  result, or raises :class:`RemoteAccessError`.

* **routing wrappers** (:func:`routed_file_read`, :func:`routed_file_write`,
  :func:`routed_file_patch`, :func:`routed_file_list`, :func:`routed_file_stat`,
  :func:`routed_list_roots`) + :func:`fetch_located` — if ``node`` is ``None`` or
  resolves to the local node, the **local** A4 file tool is called directly (no
  network); otherwise the call routes to the owning node via :func:`call_remote`.
  :func:`fetch_located` takes a ``pg_search`` / ``pg_locate`` hit (``{node, path}``)
  and reads the file from its owning node automatically.

This is intentionally a *thin* layer over A2/A4 — it never duplicates file logic,
it only decides *local vs route* and signs/posts the cross-node hop.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

from ..discovery import PeerInfo, PeerStore
from ..envelope import Envelope
from ..identity import resolve_self_identity
from ..signing import EnvelopeSigner
from . import files as files_mod
from .config import AccessConfig

logger = logging.getLogger("skcomms.access.routing")

#: Content type for a routed access-tool request envelope.
CONTENT_TYPE_ROUTED = "application/skcomms-access-tool+json"

#: Default per-request HTTP timeout (seconds) for a cross-node access call.
DEFAULT_ROUTE_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RoutingError(Exception):
    """Base class for access-plane routing failures."""


class NodeNotFoundError(RoutingError):
    """The requested ``node`` id could not be resolved to a base URL."""


class RemoteAccessError(RoutingError):
    """The remote sk-access node rejected the call or was unreachable.

    Attributes:
        status: HTTP status code, if the failure came back as an HTTP response.
        detail: The peer's error detail (``detail`` field) or transport error.
    """

    def __init__(self, message: str, *, status: Optional[int] = None,
                 detail: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail


# ---------------------------------------------------------------------------
# Node resolver
# ---------------------------------------------------------------------------


def local_node(config: Optional[AccessConfig] = None) -> str:
    """Return this node's id ("self").

    Resolution order:
      1. ``SKACCESS_NODE`` env (the same knob :mod:`skcomms.access.knowledge`
         stamps onto locally-indexed docs, so location ids agree),
      2. the running :class:`AccessConfig`'s ``node_name`` (if not the generic
         ``"local"`` placeholder),
      3. ``".158"`` — the sovereign primary default.
    """
    env_node = os.environ.get("SKACCESS_NODE")
    if env_node:
        return env_node
    cfg = config
    if cfg is not None and cfg.node_name and cfg.node_name != "local":
        return cfg.node_name
    return ".158"


class NodeResolver:
    """Resolve a ``node`` id to that node's sk-access base URL on the tailnet.

    A *node id* may be:
      * a dotted short id (``".158"``, ``".41"``) — the form knowledge hits use,
      * a peer fqid (``lumina@chef.skworld``) or bare peer name (``lumina``),
      * an explicit ``host`` / ``host:port`` (returned verbatim, port defaulted).

    The tailnet address + access port are discovered from the
    :class:`~skcomms.discovery.PeerStore`: a peer's ``access`` transport entry
    (``settings.base_url`` or ``settings.host`` / ``settings.port``) is preferred;
    otherwise we fall back to its ``tailscale`` transport ``tailscale_ip`` (or the
    host of its ``https-s2s`` ``inbox_url``) on the default access port.

    Args:
        config: The local :class:`AccessConfig` (for the default access port +
            knowing self). Defaults to a freshly loaded one.
        peer_store: Peer registry (default: a fresh :class:`PeerStore`).
        node_aliases: Optional ``{node_id: host-or-base-url}`` overrides that
            win over the peer store (config seam / tests).
    """

    def __init__(
        self,
        config: Optional[AccessConfig] = None,
        peer_store: Optional[PeerStore] = None,
        node_aliases: Optional[dict[str, str]] = None,
    ) -> None:
        self.config = config or AccessConfig.load()
        self.peer_store = peer_store if peer_store is not None else PeerStore()
        self.node_aliases = dict(node_aliases or {})

    # -- self ---------------------------------------------------------------

    def local_node(self) -> str:
        """This node's id (see :func:`local_node`)."""
        return local_node(self.config)

    def is_local(self, node: Optional[str]) -> bool:
        """True if ``node`` is unset or refers to this node.

        A ``None`` / empty node means "right here". A node id equal to
        :meth:`local_node` (or to the config's resolved fqid / name) is local.
        """
        if not node:
            return True
        if node == self.local_node():
            return True
        if self.config.node_fqid and node == self.config.node_fqid:
            return True
        if self.config.node_name and node == self.config.node_name:
            return True
        return False

    # -- base-url resolution ------------------------------------------------

    def _default_port(self) -> int:
        return int(self.config.port)

    def _normalize_base(self, host_or_url: str) -> str:
        """Turn a host / ``host:port`` / full URL into a ``http://host:port`` base."""
        s = host_or_url.strip().rstrip("/")
        if s.startswith("http://") or s.startswith("https://"):
            return s
        if ":" in s and not s.startswith("["):
            # host:port
            return f"http://{s}"
        return f"http://{s}:{self._default_port()}"

    def _peer_base_url(self, peer: PeerInfo) -> Optional[str]:
        """Derive a peer's access base URL from its stored transports."""
        # 1. an explicit `access` transport entry (preferred, port-aware).
        for t in peer.transports:
            if t.transport == "access":
                base = t.settings.get("base_url")
                if base:
                    return base.rstrip("/")
                host = t.settings.get("host")
                if host:
                    port = t.settings.get("port", self._default_port())
                    return f"http://{host}:{int(port)}"
        # 2. fall back to the tailscale 100.x address on the default port.
        for t in peer.transports:
            if t.transport == "tailscale":
                ip = t.settings.get("tailscale_ip")
                if ip:
                    return f"http://{ip}:{self._default_port()}"
        # 3. last resort: host of an https-s2s inbox_url on the access port.
        inbox = peer.inbox_url()
        if inbox:
            try:
                from urllib.parse import urlparse

                host = urlparse(inbox).hostname
                if host:
                    return f"http://{host}:{self._default_port()}"
            except Exception:  # pragma: no cover - defensive
                pass
        return None

    def _find_peer(self, node: str) -> Optional[PeerInfo]:
        """Find a peer by node id: dotted-id alias, fqid, or bare name."""
        bare = node.split("@", 1)[0] if "@" in node else node
        for peer in self.peer_store.list_all():
            if peer.fqid == node or peer.name == node or peer.name == bare:
                return peer
            # dotted node id stored on the peer's `access` transport.
            for t in peer.transports:
                if t.transport == "access" and t.settings.get("node") == node:
                    return peer
        return None

    def resolve(self, node: str) -> str:
        """Resolve a node id to its sk-access base URL (``http://host:port``).

        Raises:
            NodeNotFoundError: If the node cannot be mapped to an address.
        """
        if not node:
            raise NodeNotFoundError("empty node id")
        # Explicit alias / config override wins.
        if node in self.node_aliases:
            return self._normalize_base(self.node_aliases[node])
        # A host or URL passed straight through.
        if node.startswith("http://") or node.startswith("https://") or _looks_like_host(node):
            return self._normalize_base(node)
        # Peer-store lookup (dotted id / fqid / name).
        peer = self._find_peer(node)
        if peer is not None:
            base = self._peer_base_url(peer)
            if base:
                return base
            raise NodeNotFoundError(
                f"peer {node!r} has no access/tailscale address in the peer store"
            )
        raise NodeNotFoundError(f"unknown node {node!r}: not in peer store or aliases")


def _looks_like_host(s: str) -> bool:
    """Heuristic: a tailnet IP or ``host:port`` literal (not a dotted node id).

    Dotted node ids like ``".158"`` start with a dot and have no other dots;
    real hosts are ``100.x.y.z`` or ``host:port``.
    """
    if s.startswith("."):
        return False
    if ":" in s:
        return True
    # 100.x.y.z style tailnet IP
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ---------------------------------------------------------------------------
# Signing (this node's capauth key) — monkeypatchable in tests
# ---------------------------------------------------------------------------


def _load_signer(agent: str) -> EnvelopeSigner:
    """Load this node's capauth signing key (reuses the mailbox key layout).

    Kept as a thin indirection so tests can monkeypatch
    :func:`skcomms.access.routing._load_signer` with an in-process key.
    """
    from ..mailbox import _load_signer as mailbox_load_signer

    return mailbox_load_signer(agent)


def _sign_tool_request(
    tool: str,
    arguments: dict,
    *,
    from_fqid: str,
    to_fqid: str,
    agent: str,
) -> bytes:
    """Build + capauth-sign a tool-call envelope; return its wire bytes.

    The :class:`Envelope` body is the JSON ``{"tool": ..., "arguments": ...}``;
    its ``content_type`` marks it as a routed access call. The signature proves
    the caller's identity; freshness + per-envelope nonce bound replay (enforced
    on the peer by :func:`skcomms.federation.accept_signed`).
    """
    env = Envelope(
        from_fqid=from_fqid,
        to_fqid=to_fqid,
        body=json.dumps({"tool": tool, "arguments": arguments or {}}, sort_keys=True),
        content_type=CONTENT_TYPE_ROUTED,
        subject=f"access:{tool}",
    )
    signer = _load_signer(agent)
    signed = signer.sign(env)
    return signed.to_bytes()


# ---------------------------------------------------------------------------
# Remote client
# ---------------------------------------------------------------------------


def _post_tool(base_url: str, signed_bytes: bytes, *, timeout: float) -> Any:
    """POST a signed tool-call to ``<base_url>/tool``; return the result.

    The peer's ``/tool`` endpoint takes ``{"token": <signed-envelope>, "tool":
    ..., "arguments": ...}``. We also send the tool/args plaintext alongside the
    signed token so the existing endpoint can dispatch without re-parsing the
    envelope body (the token still authenticates the *caller*; the peer's gate
    is what enforces scope). The result is unwrapped from ``{"ok", "result"}``.

    Kept import-light (``urllib``) to mirror the http_s2s rail and stay testable
    by patching this function or the urllib seam.
    """
    import urllib.error
    import urllib.request

    signed_text = signed_bytes.decode("utf-8")
    signed_obj = json.loads(signed_text)
    # The plaintext tool/arguments come from the signed body so a peer that
    # dispatches on the top-level fields and one that re-derives from the
    # envelope body agree.
    inner = json.loads(signed_obj["envelope"]["body"])
    payload = json.dumps(
        {
            "token": signed_obj,
            "tool": inner["tool"],
            "arguments": inner.get("arguments", {}),
        }
    ).encode("utf-8")

    url = base_url.rstrip("/") + "/tool"
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = _extract_detail(exc)
        raise RemoteAccessError(
            f"remote access call failed: HTTP {exc.code} {detail}",
            status=exc.code,
            detail=detail,
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RemoteAccessError(
            f"remote access node unreachable ({url}): {exc}",
            detail=str(exc),
        ) from exc

    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RemoteAccessError(f"remote returned non-JSON response: {exc}") from exc
    if isinstance(body, dict) and "result" in body:
        return body["result"]
    return body


def _extract_detail(exc) -> str:
    try:
        raw = exc.read()
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return str(parsed.get("detail") or parsed.get("error") or raw.decode("utf-8", "replace"))
        return str(parsed)
    except Exception:  # pragma: no cover - best-effort
        return str(exc)


def call_remote(
    node: str,
    tool: str,
    arguments: Optional[dict] = None,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> Any:
    """Call ``tool`` on a *remote* node's sk-access over the tailnet.

    Resolves the node's base URL, capauth-signs the request with this node's key,
    POSTs it to the peer's ``/tool`` endpoint, and returns the tool result.

    Args:
        node: Target node id (dotted id / fqid / name / host).
        tool: Registered tool name on the remote node (e.g. ``"file_read"``).
        arguments: Tool arguments.
        resolver: A :class:`NodeResolver` (default: a freshly built one).
        timeout: Per-request HTTP timeout (seconds).
        agent: Override the signing agent (default: resolved self identity).

    Returns:
        The remote tool's result (already unwrapped from ``{"ok","result"}``).

    Raises:
        NodeNotFoundError: The node could not be resolved.
        RemoteAccessError: The peer rejected the call or was unreachable.
    """
    res = resolver or NodeResolver()
    base_url = res.resolve(node)

    ident = resolve_self_identity(agent)
    eff_agent = agent or ident.get("agent") or "local"
    from_fqid = ident.get("fqid") or f"{eff_agent}@local.skworld"
    # The recipient fqid is best-effort (the gate authenticates the *caller*);
    # use the node id so it is meaningful in the peer's audit/logs.
    to_fqid = node if "@" in node else f"access@{node}"

    signed_bytes = _sign_tool_request(
        tool, arguments or {}, from_fqid=from_fqid, to_fqid=to_fqid, agent=eff_agent
    )
    logger.info("routing %s -> node %s (%s)", tool, node, base_url)
    return _post_tool(base_url, signed_bytes, timeout=timeout)


# ---------------------------------------------------------------------------
# Routing wrappers — local-or-route over the A4 file tools
# ---------------------------------------------------------------------------


def _route_or_local(
    node: Optional[str],
    tool: str,
    arguments: dict,
    local_fn,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> Any:
    """Dispatch to the LOCAL callable (no network) or route to ``node``.

    ``local_fn`` is the in-process A4 callable (called with ``**arguments``).
    """
    res = resolver or NodeResolver()
    if res.is_local(node):
        return local_fn(**arguments)
    return call_remote(
        node, tool, arguments, resolver=res, timeout=timeout, agent=agent
    )


def routed_file_read(
    path: str,
    node: Optional[str] = None,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> dict[str, Any]:
    """Read a file from ``node`` (or locally if ``node`` is None/self)."""
    return _route_or_local(
        node, "file_read", {"path": path}, files_mod.file_read,
        resolver=resolver, timeout=timeout, agent=agent,
    )


def routed_file_write(
    path: str,
    content: str,
    node: Optional[str] = None,
    *,
    encoding: str = "utf-8",
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> dict[str, Any]:
    """Write a file on ``node`` (or locally). Routed call requires write scope."""
    def _local(path, content, encoding="utf-8"):
        return files_mod.file_write(path, content, encoding=encoding)

    return _route_or_local(
        node, "file_write",
        {"path": path, "content": content, "encoding": encoding}, _local,
        resolver=resolver, timeout=timeout, agent=agent,
    )


def routed_file_patch(
    path: str,
    unified_diff: str,
    node: Optional[str] = None,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> dict[str, Any]:
    """Apply a unified diff to a file on ``node`` (or locally)."""
    return _route_or_local(
        node, "file_patch", {"path": path, "unified_diff": unified_diff},
        files_mod.file_patch, resolver=resolver, timeout=timeout, agent=agent,
    )


def routed_file_list(
    dir: str,
    node: Optional[str] = None,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> list[dict[str, Any]]:
    """List a directory on ``node`` (or locally)."""
    return _route_or_local(
        node, "file_list", {"dir": dir}, files_mod.file_list,
        resolver=resolver, timeout=timeout, agent=agent,
    )


def routed_file_stat(
    path: str,
    node: Optional[str] = None,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> dict[str, Any]:
    """Stat a file/dir on ``node`` (or locally)."""
    return _route_or_local(
        node, "file_stat", {"path": path}, files_mod.file_stat,
        resolver=resolver, timeout=timeout, agent=agent,
    )


def routed_list_roots(
    node: Optional[str] = None,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> list[str]:
    """List the exposed roots on ``node`` (or locally)."""
    return _route_or_local(
        node, "list_roots", {}, files_mod.list_roots,
        resolver=resolver, timeout=timeout, agent=agent,
    )


def fetch_located(
    hit: dict,
    *,
    resolver: Optional[NodeResolver] = None,
    timeout: float = DEFAULT_ROUTE_TIMEOUT,
    agent: Optional[str] = None,
) -> dict[str, Any]:
    """Read a file straight from a ``pg_search`` / ``pg_locate`` hit.

    The hit carries ``{node, path}`` (the authoritative location). This reads the
    file from its owning node automatically — local if it lives here, routed over
    the tailnet otherwise. This is the "Query → locate → fetch (no sync)" close.

    Args:
        hit: A search/location dict with at least ``path`` (``node`` optional;
            absent / unknown node ⇒ local).

    Returns:
        The ``file_read`` result for the located file.

    Raises:
        RoutingError: If the hit has no ``path``.
    """
    path = hit.get("path")
    if not path:
        raise RoutingError(f"located hit has no path: {hit!r}")
    node = hit.get("node")
    return routed_file_read(
        path, node, resolver=resolver, timeout=timeout, agent=agent
    )
