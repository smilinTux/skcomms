"""skcomms' SKWorld module manifest: service shape, operator facet, served unauth.

skcomms is a UI-less backend transport service, so its manifest declares NO UI
module (grade "service", null entry, no nav) and only the operator facet. The
operator block must mirror Atlas's skcomms adapter and this repo's canonical
operator_probe.py; the sk-standards manifest schema is the shared source of truth.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from skcomms.skworld_manifest import (
    AUDIENCE,
    SCHEMA_VERSION,
    skcomms_module_manifest,
)


def test_manifest_is_a_ui_less_service():
    m = skcomms_module_manifest("http://localhost:9384/")
    assert m["schemaVersion"] == SCHEMA_VERSION == "1.1"
    assert m["id"] == "skcomms"
    assert m["name"] == "Comms"
    # A backend transport service: no UI module the shell could mount.
    assert m["grade"] == "service"
    assert m["service"] is True
    assert m["entry"] is None
    # No nav for a backend service (nothing in the app rail).
    assert "nav" not in m
    # And no invented Flutter package.
    assert "flutter_package" not in m


def test_auth_facet_declares_audience():
    m = skcomms_module_manifest("http://host/")
    assert m["auth"]["audience"] == AUDIENCE == "skcomms"
    assert m["auth"]["scopes"] == ["comms.send", "comms.receive"]
    assert m["memory"] == {"opt_in": False}


def test_health_is_origin_relative():
    assert (
        skcomms_module_manifest("http://host:9384/")["health"]
        == "http://host:9384/health"
    )
    # No trailing-slash base yields the same (no double/missing slash).
    assert (
        skcomms_module_manifest("http://host:9384")["health"]
        == "http://host:9384/health"
    )


def test_operator_facet_matches_the_skcomms_adapter_contract():
    op = skcomms_module_manifest("http://host/")["operator"]
    assert op["contractVersion"] == 1
    assert op["cli"] == "skcomms operator"
    assert op["repos"] == ["skcomms"]
    # Mirrors the skcomms adapter CONDITIONS exactly, in order.
    assert op["conditions"] == ["PathHealthy", "QueueDrained"]
    # Only the standard + reversible action is proposed (restart_service);
    # failover_discovery is non-standard and deliberately absent.
    assert op["proposedStandardActions"] == ["restart_service"]


def test_operator_conditions_equal_the_probe_conditions():
    """The manifest's operator conditions must equal this repo's canonical
    operator_probe.CONDITIONS (the module the CLI + adapter both mirror)."""
    from skcomms.operator_probe import CONDITIONS

    op = skcomms_module_manifest("http://host/")["operator"]
    assert op["conditions"] == list(CONDITIONS)


def test_operator_conditions_equal_the_atlas_adapter_conditions():
    """When the skcapstone adapter is importable, the manifest conditions must
    equal its CONDITIONS exactly (the sk-standards schema is the shared truth)."""
    adapter = pytest.importorskip("skcapstone.operator_seat.skcomms_adapter")

    op = skcomms_module_manifest("http://host/")["operator"]
    assert op["conditions"] == list(adapter.CONDITIONS)


def test_operator_standard_actions_are_the_probe_standard_actions():
    """proposedStandardActions must be exactly the probe's standard+reversible
    action names (restart_service), not the non-standard failover_discovery."""
    from skcomms import operator_probe

    standard = [
        a["name"]
        for a in operator_probe._ACTIONS
        if a.get("standard") and a.get("reversible")
    ]
    op = skcomms_module_manifest("http://host/")["operator"]
    assert op["proposedStandardActions"] == standard == ["restart_service"]


def test_manifest_served_unauthenticated_from_api():
    """The /.well-known route is public (no auth gate): a fresh TestClient with
    no credential gets the service manifest with its operator block."""
    from skcomms import api

    client = TestClient(api.app)
    r = client.get("/.well-known/skworld-module.json")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "skcomms"
    assert body["grade"] == "service"
    assert body["entry"] is None
    assert body["operator"]["conditions"] == ["PathHealthy", "QueueDrained"]
    assert body["operator"]["proposedStandardActions"] == ["restart_service"]
    # Origin-relative health resolves against the serving origin.
    assert body["health"].endswith("/health")
