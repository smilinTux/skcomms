"""SKComms Access Plane (P7) — sandboxed file + knowledge tools.

This package holds the per-node ``sk-access`` tool implementations. Each tool
is a plain callable so it can be registered by the A2 MCP server skeleton, or
called directly in tests / scripts without an MCP runtime present.

The file tools (A4) live in :mod:`skcomms.access.files`.
"""

from __future__ import annotations

from . import files  # noqa: F401  (re-export module for convenience)

__all__ = ["files"]
