"""skcomms' SKWorld module manifest (sk-standards manifest schema v1.1).

skcomms is a first-class SKWorld subapp like skchat and skcode, but it is a
backend transport service, not a UI surface: there is no Flutter module and no
chrome the shell mounts. So its manifest declares ONLY the operator facet and
marks itself a service (grade "service", no UI entry, no nav). The shell reads
the manifest to discover skcomms and learn its health and operator contract; it
never tries to render a pane for it.

The manifest is built as a pure dict from the serving origin, so the served URLs
are origin-relative (they resolve against wherever the api actually answers,
avoiding host/port drift). The api serves it unauthenticated at
/.well-known/skworld-module.json (public discovery metadata, no secrets), the
same way skchat's webui and skcode's hostd serve theirs.

The operator block mirrors operator_seat/skcomms_adapter.py in skcapstone AND
the canonical operator_probe.py in this repo (the CLI `skcomms operator` is built
over it). The three live in separate places, so the shared sk-standards manifest
schema is the source of truth; keep them in sync when any changes. The conditions
order here MUST match the adapter's CONDITIONS exactly ([PathHealthy,
QueueDrained]), and proposedStandardActions carries only the adapter's
standard+reversible action (restart_service); failover_discovery is non-standard
(fleet_restart blast radius, human-approval-only) so it is not proposed here.
"""

from __future__ import annotations

#: sk-standards manifest schema version (v1.1, with the operator block).
SCHEMA_VERSION = "1.1"
#: The audience skcomms tokens are minted for.
AUDIENCE = "skcomms"


def skcomms_module_manifest(base_url: str) -> dict:
    """Build skcomms' skworld.module.json for a given serving origin.

    skcomms is a UI-less backend transport service, so the manifest declares no
    Flutter package and no nav entry: grade is "service", entry is null, and the
    ``service`` flag makes the intent machine-readable. The only facet is the
    operator block Atlas's skcomms adapter mirrors.

    Args:
        base_url: The origin the api answers on (e.g. the request base URL,
            "http://100.x.x.x:9384/"). The health URL is built relative to it so
            it never hardcodes a host or port.

    Returns:
        The manifest dict (service marker + operator facet).
    """
    base = base_url.rstrip("/")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "id": "skcomms",
        "name": "Comms",
        # A backend transport service: no UI module the shell could mount, so no
        # grade-A/B UI facet. grade "service" + null entry + service flag mark it.
        "grade": "service",
        "service": True,
        "entry": None,
        # No nav: a backend service has nothing the shell puts in the app rail.
        "auth": {
            "audience": AUDIENCE,
            "scopes": ["comms.send", "comms.receive"],
        },
        "memory": {"opt_in": False},
        "health": f"{base}/health",
        # Operator facet: what Atlas's skcomms adapter observes and may act on.
        # Mirrors operator_seat/skcomms_adapter.py CONDITIONS + operator_probe.py.
        "operator": {
            "contractVersion": 1,
            "cli": "skcomms operator",
            "repos": ["skcomms"],
            "conditions": ["PathHealthy", "QueueDrained"],
            # Only the standard + reversible action is proposed; failover_discovery
            # is non-standard (fleet_restart blast, human-approval-only, escalates
            # as MAJOR) so it is deliberately absent here.
            "proposedStandardActions": ["restart_service"],
        },
    }


__all__ = ["skcomms_module_manifest", "SCHEMA_VERSION", "AUDIENCE"]
