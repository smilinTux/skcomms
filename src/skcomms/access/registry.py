"""Tool registration interface for the sk-access MCP server.

A3 (knowledge) and A4 (file) modules register their tools here, declaring a
**scope** (``read`` | ``write`` | ``exec``). The :class:`AccessServer` consults
the registry to (a) advertise tools to MCP clients and (b) enforce per-call
scope against the calling identity's granted scopes.

A registered tool is just::

    register_tool("file_read", _file_read, scope="read",
                  description="Read a file under an exposed root",
                  input_schema={...})

where ``_file_read(arguments: dict, ctx: ToolContext) -> Any`` is sync or async.
``ctx`` carries the verified caller identity + the server config so file/exec
tools can apply the exposed-root allowlist and audit-log the caller.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Optional, Union


class Scope(str, Enum):
    """RBAC scope a tool requires / an identity is granted.

    Ordering is meaningful for *grants*: an identity granted ``WRITE`` implicitly
    holds ``READ``; ``EXEC`` implicitly holds ``WRITE`` and ``READ`` (an actor
    who can run commands can already read and write). A tool, by contrast,
    requires *exactly* its declared scope level or higher from the caller.
    """

    READ = "read"
    WRITE = "write"
    EXEC = "exec"

    @property
    def rank(self) -> int:
        return {"read": 0, "write": 1, "exec": 2}[self.value]

    def satisfied_by(self, granted: "set[Scope]") -> bool:
        """True if any granted scope is at least as privileged as ``self``."""
        return any(g.rank >= self.rank for g in granted)


# A tool handler takes (arguments, ctx) and returns JSON-serialisable data.
# ctx is intentionally typed loosely (Any) to avoid an import cycle with server.
ToolHandler = Callable[[dict, Any], Union[Any, Awaitable[Any]]]


@dataclass
class RegisteredTool:
    """A single tool attached to the access server.

    Attributes:
        name: Unique tool name exposed to MCP clients.
        handler: ``(arguments: dict, ctx) -> Any`` (sync or async).
        scope: Minimum :class:`Scope` the caller must hold.
        description: Human/agent-readable description for the MCP catalog.
        input_schema: JSON-schema for the tool's arguments.
    """

    name: str
    handler: ToolHandler
    scope: Scope
    description: str = ""
    input_schema: dict = field(default_factory=lambda: {"type": "object", "properties": {}})

    async def invoke(self, arguments: dict, ctx: Any) -> Any:
        """Call the handler, awaiting it if it is a coroutine."""
        result = self.handler(arguments, ctx)
        if inspect.isawaitable(result):
            return await result
        return result


class AccessRegistry:
    """Registry of access-plane tools, keyed by name.

    A3/A4 modules call :meth:`register` (or the module-level
    :func:`register_tool` against the default registry) to attach their tools.
    The server iterates :meth:`all` to build the MCP tool list and looks tools
    up by name on each call.
    """

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self,
        name: str,
        handler: ToolHandler,
        scope: Union[Scope, str] = Scope.READ,
        *,
        description: str = "",
        input_schema: Optional[dict] = None,
        replace: bool = False,
    ) -> RegisteredTool:
        """Register a tool.

        Args:
            name: Unique tool name.
            handler: ``(arguments, ctx) -> Any`` (sync or async).
            scope: ``"read"`` | ``"write"`` | ``"exec"`` (or :class:`Scope`).
            description: Catalog description.
            input_schema: JSON-schema for arguments.
            replace: Allow overwriting an existing tool of the same name.

        Raises:
            ValueError: On empty name or duplicate name (unless ``replace``).
        """
        if not name or not name.strip():
            raise ValueError("tool name is required")
        if name in self._tools and not replace:
            raise ValueError(f"tool already registered: {name!r}")
        sc = scope if isinstance(scope, Scope) else Scope(str(scope))
        tool = RegisteredTool(
            name=name,
            handler=handler,
            scope=sc,
            description=description,
            input_schema=input_schema or {"type": "object", "properties": {}},
        )
        self._tools[name] = tool
        return tool

    def get(self, name: str) -> Optional[RegisteredTool]:
        """Return the tool by name, or ``None``."""
        return self._tools.get(name)

    def all(self) -> list[RegisteredTool]:
        """Return all registered tools, name-sorted (stable catalog order)."""
        return [self._tools[k] for k in sorted(self._tools)]

    def names(self) -> list[str]:
        """Return all registered tool names, sorted."""
        return sorted(self._tools)

    def clear(self) -> None:
        """Drop all registered tools (test helper)."""
        self._tools.clear()


# A process-wide default registry so A3/A4 can ``register_tool(...)`` at import
# time. An AccessServer can also be handed its own registry for isolation.
DEFAULT_REGISTRY = AccessRegistry()


def register_tool(
    name: str,
    fn: ToolHandler,
    scope: Union[Scope, str] = "read",
    *,
    description: str = "",
    input_schema: Optional[dict] = None,
    replace: bool = False,
    registry: Optional[AccessRegistry] = None,
) -> RegisteredTool:
    """Module-level convenience: register a tool on a registry.

    This is the seam A3/A4 use::

        from skcomms.access import register_tool
        register_tool("pg_search", pg_search, scope="read",
                      description="hybrid vec+BM25 search", input_schema={...})

    Args:
        name: Unique tool name.
        fn: ``(arguments, ctx) -> Any`` handler (sync or async).
        scope: ``"read"`` | ``"write"`` | ``"exec"``.
        description: Catalog description.
        input_schema: JSON-schema for arguments.
        replace: Allow overwriting an existing tool.
        registry: Target registry (defaults to :data:`DEFAULT_REGISTRY`).

    Returns:
        The :class:`RegisteredTool`.
    """
    reg = registry or DEFAULT_REGISTRY
    return reg.register(
        name, fn, scope, description=description, input_schema=input_schema, replace=replace
    )
