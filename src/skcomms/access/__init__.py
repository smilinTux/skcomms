"""sk-access — the SKFed Access Plane (P7).

A per-node, capauth-gated MCP server that lets any agent on the tailnet
semantically search the sovereign corpus and read/write files on *any* node,
with no file syncing. This package is the **A2 skeleton**: the SSE/HTTP MCP
server + capauth gate + tool-registration interface that the A3 (knowledge)
and A4 (file) tool modules plug into.

Security posture (see ``docs/access-plane-p7.md`` §Security model):
    * **Tailnet-only bind** — never ``0.0.0.0``/public. Default bind is this
      node's tailscale 100.x address; the loopback ``127.0.0.1`` is the only
      non-tailnet fallback. A public bind is refused unless explicitly forced.
    * **capauth-gated** — every tool call must carry a capauth-signed token
      (a :class:`~skcomms.envelope.SignedEnvelope`) from a verified, trusted
      identity. Reuses :func:`skcomms.federation.accept_signed` / TOFU.
    * **Scopes / RBAC** — tools declare ``read`` | ``write`` | ``exec``; an
      identity is granted a scope set; insufficient scope is rejected.
    * **Exposed-root allowlist + hard-denied secrets** — config carries the
      file roots an agent may touch (enforced by the A4 file tools).

Public surface:
    register_tool / AccessRegistry  — how A3/A4 attach tools
    AccessServer                    — the MCP/SSE server skeleton
    AccessConfig                    — config (bind, roots, scopes, dev-bypass)
    Scope                           — read | write | exec
    AccessAuthError / AccessScopeError — gate rejections
"""

from __future__ import annotations

from .config import AccessConfig
from .registry import AccessRegistry, RegisteredTool, Scope, register_tool
from .server import (
    AccessAuthError,
    AccessScopeError,
    AccessServer,
    build_app,
)

__all__ = [
    "AccessConfig",
    "AccessRegistry",
    "RegisteredTool",
    "Scope",
    "register_tool",
    "AccessServer",
    "AccessAuthError",
    "AccessScopeError",
    "build_app",
]
