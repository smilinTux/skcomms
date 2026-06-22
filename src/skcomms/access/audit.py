"""Call-level RBAC audit log for the sk-access plane (P7 / A6).

The A4 file tools already audit *mutations* (write/patch) to their own log; this
module is the **authorization** audit — one structured line per tool *call*,
recording who called what, the scope required, and whether the access plane
**allowed or denied** it. It fires for BOTH the ``/tool`` HTTP path and the
``/sse`` MCP path, so the RBAC decision is always evidenced regardless of
transport.

Log: ``~/.skcapstone/skcomms/logs/access-audit.log`` — one JSON object per line::

    {"ts":"2026-06-22T...Z","transport":"sse","identity":"lumina@chef.skworld",
     "fingerprint":"AAAA...","tool":"file_write","scope":"write",
     "decision":"allow","reason":null,"node":"noroc2027"}

``decision`` ∈ {``allow``, ``deny``}. On deny, ``reason`` carries the cause
(``auth`` / ``scope`` / ``not_found``). An audit-write failure is logged loudly
but never blocks or masks the call decision — but a missing trail is itself a
security event.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("skcomms.access.audit")

_AUDIT_PATH = Path("~/.skcapstone/skcomms/logs/access-audit.log")


def audit_path(path: Optional[Path] = None) -> Path:
    """Resolve the access-audit log path (override-able for tests/config)."""
    return (path or _AUDIT_PATH).expanduser()


class AccessAuditLog:
    """Append-only JSONL writer for access-plane authorization decisions.

    Args:
        path: Log file path (default ``~/.skcapstone/skcomms/logs/access-audit.log``).
        node: This node's name, stamped on every line for fleet-wide collation.
    """

    def __init__(self, path: Optional[Path] = None, node: Optional[str] = None) -> None:
        self.path = audit_path(path)
        self.node = node

    def record(
        self,
        *,
        transport: str,
        identity: Optional[str],
        tool: str,
        scope: Optional[str],
        decision: str,
        reason: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> dict:
        """Append one audit line and return the recorded entry.

        Args:
            transport: ``"tool"`` (HTTP) or ``"sse"`` (MCP) — which path called.
            identity: Verified caller fqid (or ``None`` if auth failed first).
            tool: Tool name requested.
            scope: The tool's required scope value (or ``None`` if unknown).
            decision: ``"allow"`` or ``"deny"``.
            reason: On deny, the cause (``auth`` | ``scope`` | ``not_found``).
            fingerprint: Verified signer fingerprint, if known.
        """
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "transport": transport,
            "identity": identity,
            "fingerprint": fingerprint,
            "tool": tool,
            "scope": scope,
            "decision": decision,
            "reason": reason,
            "node": self.node,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            # Never let an audit-log failure block the decision, but shout —
            # a missing authorization trail is itself a security event.
            logger.exception("FAILED to write access-audit entry: %s", entry)
        return entry
