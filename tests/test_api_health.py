"""Liveness probe tests for the FastAPI app (``/health`` and ``/healthz``).

The app serves ``/health`` (its historical liveness alias). The SKStacks v2
descriptor and the shipped Dockerfile HEALTHCHECK probe ``/healthz``, so we serve
both to reconcile the mismatch: any probe path returns 200 with the same body.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient over the reloaded app bound to an isolated SKCOMMS_HOME."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))

    import skcomms.api as api

    importlib.reload(api)
    return TestClient(api.app)


@pytest.mark.parametrize("path", ["/health", "/healthz"])
def test_liveness_probe_ok(client, path):
    resp = client.get(path)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "SKComms API"
