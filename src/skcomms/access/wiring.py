"""Integration glue — register the A3 knowledge + A4 file tools into the A2 server.

A3/A4 expose direct-arg callables (``pg_search(query, k, ...)``, ``file_read(path)``);
the A2 registry expects ``(arguments: dict, ctx) -> Any`` handlers. This module
adapts each catalog entry and registers it via :func:`skcomms.access.registry.register_tool`,
so a single :func:`register_builtin_tools` call wires the whole access plane.
"""

from __future__ import annotations

from typing import Any, Optional

from . import files, knowledge
from .registry import register_tool


def _adapt(fn):
    """Wrap a direct-arg tool callable as an ``(arguments, ctx)`` handler.

    ``ctx`` is currently unused by the knowledge/file tools (file tools enforce
    their own exposed-root allowlist + audit identity from config); per-call
    identity threading is A6/F1.
    """
    def handler(arguments: dict, ctx: Any, _fn=fn):
        return _fn(**(arguments or {}))
    return handler


def register_builtin_tools(registry: Optional[Any] = None) -> list[str]:
    """Register all knowledge (A3) + file (A4) tools into the access registry.

    Returns the list of registered tool names. Idempotent via ``replace=True``.
    """
    names: list[str] = []

    # A3 knowledge tools — TOOL_CATALOG = [(name, fn, description, scope), ...]
    for name, fn, description, scope in knowledge.TOOL_CATALOG:
        register_tool(name, _adapt(fn), scope=scope, description=description,
                      replace=True, registry=registry)
        names.append(name)

    # A4 file tools — TOOL_SPECS = [{name, scope, description, inputSchema}], fn = module-level
    for spec in files.TOOL_SPECS:
        name = spec["name"]
        fn = getattr(files, name, None)
        if fn is None:
            continue
        register_tool(name, _adapt(fn), scope=spec.get("scope", "read"),
                      description=spec.get("description", ""),
                      input_schema=spec.get("inputSchema"),
                      replace=True, registry=registry)
        names.append(name)

    return names
