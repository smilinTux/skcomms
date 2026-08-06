"""skcomms operator-facet probe: the explain / observe / act contract (R2.12).

This is the canonical operator contract for skcomms, the module the
`skcomms operator` CLI is built over and the exact shape Atlas's skcomms adapter
(`skcapstone/src/skcapstone/operator_seat/skcomms_adapter.py`) mirrors. One
operator, many apps: skcomms conforms by exposing the same three verbs the fleet
does. The explain/observe output is byte-compatible in shape with that adapter
(the sk-standards schema is the shared source of truth).

The observe probes are REAL and injectable (tests never touch a live skcomms):

  * ``PathHealthy``   the skcomms API health endpoint (:9384/health by default),
    the discovery/transport path. ``status: ok`` reads healthy; ``degraded`` (a
    node missing its CapAuth key, for instance) reads unhealthy.
  * ``QueueDrained``  the real pending count under the PersistentOutbox retry
    store, compared against the outbox depth threshold (the flood detector that
    would have caught the 140k-file outbox leak).

Every probe fails SAFE (reports healthy) rather than raising a false alarm when
skcomms is unreachable, matching the adapter's fail-safe posture and the
operator facet's failure semantics.

The act verb maps the one reversible standard action (restart_service) onto
``systemctl --user restart <unit>`` through an injectable runner.
``failover_discovery`` is declared non-standard (fleet_restart blast radius) and
refuses at the act verb: it is human-approval-only and escalates as MAJOR by
construction (it never actuates here).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

#: The two operator conditions, matching Atlas's skcomms_adapter and the manifest.
CONDITIONS = ["PathHealthy", "QueueDrained"]

#: The kinds skcomms exposes to the operator plane (mirrors the adapter exactly).
KINDS = ["path", "queue"]

#: skcomms conditions are health-type (they fire when status is False), so they
#: are NOT problem-when-true. Queue over its bound -> QueueDrained False -> firing.
_ACTIONS = [
    {
        "name": "restart_service",
        "standard": True,
        "reversible": True,
        "blast_radius": "low",
        "runbook": "restart the wedged skcomms service",
        "kedb_refs": [],
    },
    {
        "name": "failover_discovery",
        "standard": False,
        "reversible": True,
        "blast_radius": "fleet_restart",
        "runbook": "fail service discovery over to a healthy path (major: escalates)",
        "kedb_refs": [],
    },
]

#: Default queue bound, matching OutboxConfig.outbox_depth_threshold and the
#: adapter's _QUEUE_LIMIT.
_QUEUE_LIMIT = 1000

_HEALTH_URL = "http://localhost:9384/health"

#: The systemd unit the reversible standard restart actuates. The skcomms-api
#: unit serves the :9384 /health path that PathHealthy probes; override with
#: SKCOMMS_OPERATOR_UNIT (or the CLI --unit flag) to target another unit.
_UNIT_RESTART_SERVICE = "skcomms-api.service"


def _b(value: bool) -> str:
    return "True" if value else "False"


# --- real signal readers (each fails safe = healthy) -------------------------


def _probe_path_healthy() -> bool:
    """Read the skcomms API health endpoint. ``status: ok`` -> healthy.

    Fails SAFE: an unreachable endpoint reports healthy (True) so a probe
    failure never raises a false 'path down' alarm. A reachable endpoint that
    reports ``degraded`` (e.g. a node missing its CapAuth private key) reads
    unhealthy so the operator sees real degradation.
    """
    try:
        import json
        import urllib.request

        url = os.environ.get("SKCOMMS_HEALTH_URL", _HEALTH_URL)
        with urllib.request.urlopen(url, timeout=8) as r:  # noqa: S310
            body = json.loads(r.read())
        if isinstance(body, dict) and "status" in body:
            return str(body.get("status", "ok")).lower() == "ok"
        return True
    except Exception:
        return True


def _pending_dir() -> Path:
    """The PersistentOutbox pending directory (honors SKCOMMS_OUTBOX_DIR)."""
    try:
        from . import paths

        return paths.retry_outbox_dir() / "pending"
    except Exception:
        return Path.home() / ".skcapstone" / "skcomms" / "outbox" / "pending"


def _count_queue(pending_dir) -> int:
    """Count queued envelopes in the pending dir. Missing dir is zero (drained)."""
    p = Path(pending_dir)
    if not p.is_dir():
        return 0
    return sum(1 for f in p.glob("*.json") if f.is_file())


def queue_depth() -> int:
    """The unified PersistentOutbox pending depth: the ONE backlog metric.

    This is the single canonical outbox-depth probe (coord eb659f61 / roadmap
    CR-5.3). It counts pending entries under the consolidated skcomms
    :class:`~skcomms.outbox.PersistentOutbox` retry store
    (``skcomms.paths.retry_outbox_dir()/pending``, honoring the
    ``SKCOMMS_OUTBOX_DIR`` override). Both this module's ``QueueDrained``
    condition and the skchat ``OutboxBounded`` condition (the skchat operator
    CLI and Atlas's skchat adapter, "one probe, two consumers") read this same
    function, so outbox depth is a single source of truth across the fleet.

    Fails SAFE (returns 0 = drained) when the store cannot be read, so a probe
    failure never raises a false 'outbox flooded' alarm.

    Returns:
        int: Number of pending entries in the unified retry store.
    """
    try:
        return _count_queue(_pending_dir())
    except Exception:
        return 0


def _default_probe() -> dict:
    """Best-effort skcomms health from real signals. Fails SAFE (healthy) when
    skcomms is unreachable, so an inability to probe never raises a false alarm."""
    return {
        "path_healthy": _probe_path_healthy(),
        "queue_depth": queue_depth(),
        "queue_limit": _QUEUE_LIMIT,
    }


# --- contract verbs ----------------------------------------------------------


def explain() -> dict:
    """skcomms' self-description in the operator-contract shape."""
    return {
        "kinds": list(KINDS),
        "conditions": list(CONDITIONS),
        "actions": [dict(a) for a in _ACTIONS],
    }


def observe(probe: Optional[Callable[[], dict]] = None) -> dict:
    """Read-only skcomms health snapshot in the operator-contract shape.

    ``probe`` is injectable so tests are hermetic; the default reads real
    signals and fails safe.
    """
    st = (probe or _default_probe)()
    depth = int(st.get("queue_depth", 0))
    limit = int(st.get("queue_limit", _QUEUE_LIMIT))
    return {
        "conditions": [
            {
                "type": "PathHealthy",
                "status": _b(bool(st.get("path_healthy"))),
                "object": "discovery-path",
            },
            {"type": "QueueDrained", "status": _b(depth <= limit), "object": "queue"},
        ]
    }


def _action_meta(action: str) -> Optional[dict]:
    for a in _ACTIONS:
        if a["name"] == action:
            return a
    return None


def _unit_for(action: str) -> Optional[str]:
    """The systemd unit a reversible standard action restarts."""
    if action == "restart_service":
        return os.environ.get("SKCOMMS_OPERATOR_UNIT", _UNIT_RESTART_SERVICE)
    return None


def _default_runner(cmd) -> dict:
    """Run a systemd command, capturing the result. Never invoked under test."""
    import subprocess

    proc = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def act(
    action: str,
    *,
    runner: Optional[Callable[[list], dict]] = None,
    unit: Optional[str] = None,
) -> dict:
    """Perform a reversible standard skcomms action, or refuse.

    ``restart_service`` (standard, reversible, low blast) runs
    ``systemctl --user restart <unit>`` through the injected ``runner``
    (defaults to a real subprocess). ``failover_discovery`` is declared
    non-standard (fleet_restart blast radius) and is NOT performed here: it is
    human-approval-only and escalates as MAJOR by construction. An unknown
    action is refused.
    """
    meta = _action_meta(action)
    if meta is None:
        raise ValueError(f"unknown skcomms operator action {action!r}")
    if not meta.get("standard"):
        # failover_discovery and any future non-standard action: refuse here.
        return {
            "action": action,
            "performed": False,
            "escalate": "MAJOR",
            "reason": (
                "non-standard: human-approval-only, escalates as MAJOR by "
                "construction (policy.classify_change, fleet_restart blast "
                "radius) and never actuates here"
            ),
        }
    target_unit = unit or _unit_for(action)
    if target_unit is None:  # pragma: no cover - standard actions always map
        raise ValueError(f"no systemd unit mapping for skcomms action {action!r}")
    cmd = ["systemctl", "--user", "restart", target_unit]
    result = (runner or _default_runner)(cmd)
    return {
        "action": action,
        "performed": True,
        "unit": target_unit,
        "command": cmd,
        "result": result,
    }


__all__ = [
    "CONDITIONS",
    "KINDS",
    "explain",
    "observe",
    "act",
    "queue_depth",
]
