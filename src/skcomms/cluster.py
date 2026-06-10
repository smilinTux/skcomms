"""cluster.json schema + reader helper.

Implementation lands in coord task T1 (``76d9b519``).

Expected schema::

    {
      "realm": "skworld",
      "operator": "chef",
      "operator_pubkey_fingerprint": "<40-hex>",
      "created_at": "<iso8601>"
    }

Lookup order:
1. ``/etc/skcapstone/cluster.json``
2. ``~/.skcapstone/cluster.json``
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("skcomms.cluster")

_CLUSTER_LOOKUP = [
    Path("/etc/skcapstone/cluster.json"),
    Path.home() / ".skcapstone" / "cluster.json",
]


def load_cluster() -> Optional[dict]:
    """Load the cluster.json from the standard search path.

    Returns:
        Parsed cluster dict, or ``None`` if no cluster.json is found.

    Examples:
        >>> data = load_cluster()
        >>> data["realm"] if data else "skworld"
        'skworld'
    """
    for path in _CLUSTER_LOOKUP:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("cluster.json parse error at %s: %s", path, exc)
    return None


def get_realm() -> str:
    """Return the realm name (default: ``"skworld"``)."""
    data = load_cluster()
    if data:
        return str(data.get("realm", "skworld"))
    return "skworld"


def get_operator() -> str:
    """Return the operator name (default: ``"chef"``)."""
    data = load_cluster()
    if data:
        return str(data.get("operator", "chef"))
    return "chef"
