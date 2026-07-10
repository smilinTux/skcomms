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


def test_liveness_probe_never_walks_outbox(tmp_path, monkeypatch):
    """The probe is an O(1) key-path stat. It must never expand the backup
    set (which globs + sorts + stats every pending-outbox entry; the fleet
    has seen 140k-file pileups, and an O(n) probe would restart-loop the
    degraded node)."""
    client = _client(tmp_path, monkeypatch, with_key=True)

    import skcomms.trustbackup as tb

    def _boom(*args, **kwargs):
        raise AssertionError("/health must not walk the backup set")

    monkeypatch.setattr(tb, "backup_set", _boom)
    monkeypatch.setattr(tb, "identity_check", _boom)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["identity"]["private_key_present"] is True


def test_liveness_probe_check_failure_is_explicit_unknown(tmp_path, monkeypatch):
    """If the identity check itself blows up, the probe must NOT fail open
    to a plain green: it stays 200 (alive) but degrades with an explicit
    identity: unknown marker."""
    client = _client(tmp_path, monkeypatch, with_key=True)

    import skcomms.trustbackup as tb

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated identity-check failure")

    monkeypatch.setattr(tb, "private_key_present", _boom)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["identity"]["status"] == "unknown"
    assert body["identity"]["private_key_present"] is None
    assert "failed" in body["identity"]["detail"].lower()
