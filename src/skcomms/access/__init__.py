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

from . import files  # noqa: F401  (A4 file tools)
from . import knowledge  # noqa: F401  (A3 knowledge tools + A1 location index)
from .config import AccessConfig
from .registry import AccessRegistry, RegisteredTool, Scope, register_tool
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
    "AccessServer",
    "AccessAuthError",
    "AccessScopeError",
    "build_app",
    "knowledge",
    "files",
]
