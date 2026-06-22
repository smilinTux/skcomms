"""sk-access — the SKFed Access Plane (P7).

A per-node, capauth-gated MCP server that turns the fleet into one sovereign
brain + one sovereign disk: semantic search across the whole skmem-pg corpus
(knowledge plane), an authoritative ``{node, path}`` directory of where each
indexed file lives (location plane), and sandboxed file read/write on any node
— no file syncing. A2 = MCP server skeleton; A3 = knowledge tools; A4 = files.

Security posture (see ``docs/access-plane-p7.md`` §Security model):
    * **Tailnet-only bind** — never ``0.0.0.0``/public; default = this node's
      tailscale 100.x; loopback is the only non-tailnet fallback; public refused.
    * **capauth-gated** — every tool call carries a capauth-signed token
      (:class:`~skcomms.envelope.SignedEnvelope`); verified via
      :func:`skcomms.federation.accept_signed` / TOFU.
    * **Scopes / RBAC** — tools declare ``read`` | ``write`` | ``exec``.
    * **Exposed-root allowlist + hard-denied secrets** — enforced by the file tools.

Public surface:
    register_tool / AccessRegistry  — how A3/A4 attach tools
    register_builtin_tools          — wire the knowledge + file tools into a server
    AccessServer / build_app        — the MCP/SSE server skeleton
    AccessConfig / Scope            — config + read|write|exec
    AccessAuthError / AccessScopeError — gate rejections
    knowledge / files               — the A3 / A4 tool modules
"""

from __future__ import annotations

from . import exec as exec_tools  # noqa: F401  (A7 exec tools)
from . import files  # noqa: F401  (A4 file tools)
from . import knowledge  # noqa: F401  (A3 knowledge tools + A1 location index)
from .audit import AccessAuditLog
from .config import AccessConfig
from .exec import register_builtin_exec_tools
from .grants import apply_to_config, load_grants, merge_grants, save_grants
from .registry import AccessRegistry, RegisteredTool, Scope, register_tool
from .routing import (
    NodeNotFoundError,
    NodeResolver,
    RemoteAccessError,
    RoutingError,
    call_remote,
    fetch_located,
    local_node,
    routed_file_list,
    routed_file_patch,
    routed_file_read,
    routed_file_stat,
    routed_file_write,
    routed_list_roots,
)
from .server import (
    AccessAuthError,
    AccessScopeError,
    AccessServer,
    build_app,
)
from .wiring import register_builtin_tools

__all__ = [
    "AccessConfig",
    "AccessRegistry",
    "RegisteredTool",
    "Scope",
    "register_tool",
    "register_builtin_tools",
    "register_builtin_exec_tools",
    "AccessServer",
    "AccessAuthError",
    "AccessScopeError",
    "AccessAuditLog",
    "build_app",
    "apply_to_config",
    "load_grants",
    "save_grants",
    "merge_grants",
    "knowledge",
    "files",
    "exec_tools",
    "register_builtin_exec_tools",
    # A5 — federation routing
    "NodeResolver",
    "local_node",
    "call_remote",
    "fetch_located",
    "routed_file_read",
    "routed_file_write",
    "routed_file_patch",
    "routed_file_list",
    "routed_file_stat",
    "routed_list_roots",
    "RoutingError",
    "NodeNotFoundError",
    "RemoteAccessError",
]
