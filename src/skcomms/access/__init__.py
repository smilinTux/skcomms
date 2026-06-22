"""skcomms access plane (P7).

The access plane turns the fleet into one sovereign brain + one sovereign disk:
semantic search across the whole skmem-pg corpus (knowledge plane) and an
authoritative ``{node, path}`` directory of where each indexed file physically
lives (location plane).

This package currently provides the **knowledge tools** (A3) and the
**file-location index** (A1) as a self-contained module of plain callables.
A2's ``sk-access`` MCP server registers them via :func:`knowledge.register`.
"""

from . import knowledge  # noqa: F401

__all__ = ["knowledge"]
