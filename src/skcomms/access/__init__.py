"""sk-access — the SKFed Access Plane (P7).

A per-node, capauth-gated MCP server that lets any agent on the tailnet
semantically search the sovereign corpus and read/write files on *any* node,
with no file syncing. A2 = the MCP server skeleton (capauth gate +
tool-registration); A3 = knowledge tools; A4 = file tools.

Security posture (see ``docs/access-plane-p7.md`` §Security model):
    * **Tailnet-only bind** — never ``0.0.0.0``/public. Default bind is this
      node's tailscale 100.x address; loopback ``127.0.0.1`` is the only
      non-tailnet fallback. A public bind is refused unless explicitly forced.
    * **capauth-gated** — every tool call carries a capauth-signed token
      (:class:`~skcomms.envelope.SignedEnvelope`) from a verified, trusted
      identity. Reuses :func:`skcomms.federation.accept_signed` / TOFU.
    * **Scopes / RBAC** — tools declare ``read`` | ``write`` | ``exec``.
    * **Exposed-root allowlist + hard-denied secrets** — enforced by the A4
      file tools.

Public surface:
    register_tool / AccessRegistry  — how A3/A4 attach tools
    AccessServer / build_app        — the MCP/SSE server skeleton
    AccessConfig                    — config (bind, roots, scopes, dev-bypass)
    Scope                           — read | write | exec
    AccessAuthError / AccessScopeError — gate rejections
    files                           — A4 file tools module
"""

from __future__ import annotations

from . import files  # noqa: F401  (A4 file tools; re-exported for convenience)
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
    "files",
]
