"""Liveness probe tests for the FastAPI app (``/health`` and ``/healthz``).

The app serves ``/health`` (its historical liveness alias). The SKStacks v2
descriptor and the shipped Dockerfile HEALTHCHECK probe ``/healthz``, so we serve
both to reconcile the mismatch: any probe path returns 200 with the same body.

Identity honesty (coord 7d5344f2): the probe always returns HTTP 200 (the
process IS alive) but the body degrades when the CapAuth private key is
absent, so a cold bootstrap with dead crypto can never report a clean green.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch, with_key: bool):
    """A TestClient over the reloaded app bound to an isolated HOME + SKCOMMS_HOME."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    if with_key:
        keydir = home / ".capauth" / "identity"
        keydir.mkdir(parents=True)
        (keydir / "private.asc").write_text("-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake\n")

    import skcomms.api as api

    importlib.reload(api)
    return TestClient(api.app)


@pytest.mark.parametrize("path", ["/health", "/healthz"])
def test_liveness_probe_ok(tmp_path, monkeypatch, path):
    client = _client(tmp_path, monkeypatch, with_key=True)
    resp = client.get(path)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "SKComms API"
    assert body["identity"]["private_key_present"] is True


@pytest.mark.parametrize("path", ["/health", "/healthz"])
def test_liveness_probe_degraded_without_identity(tmp_path, monkeypatch, path):
    """No CapAuth private key: still HTTP 200 (alive) but honestly degraded."""
    client = _client(tmp_path, monkeypatch, with_key=False)
    resp = client.get(path)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["identity"]["private_key_present"] is False
    assert "restore" in body["identity"]["detail"].lower()
