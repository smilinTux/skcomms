"""CORS lockdown on the Funnel-mounted ``skcomms.api`` app (coord 1044fafa).

The app carries loopback-gated operator surfaces (``POST /mcp`` fires desktop
notifications, ``POST /api/v1/send`` sends as the agent, the consent endpoints
trust client IP) on the SAME FastAPI instance that Tailscale Funnel mounts to
the public internet (SOP.md section 5). Wildcard CORS let any web page the
operator visits drive those cross-origin. CORS is now an explicit, empty-by-
default allowlist read from ``SKCOMMS_CORS_ORIGINS``.

The browser enforces CORS by refusing to expose a cross-origin response that
lacks a matching ``Access-Control-Allow-Origin`` header, and by refusing the
actual request when its preflight is not approved. So the server-side contract
under test is exactly: the header is present (and equals the origin) only for a
listed origin, and absent for an unlisted one.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


UNLISTED = "https://evil.example"
ALLOWED = "https://hub.skworld.io"

# Every operator surface named in the task, exercised by CORS preflight.
OPERATOR_ROUTES = ["/mcp", "/api/v1/send"]


def _reload_api(monkeypatch, tmp_path, origins):
    """Reload ``skcomms.api`` so the module-load CORS config picks up the env."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.delenv("SKCOMMS_CORS_ORIGINS", raising=False)
    if origins is not None:
        monkeypatch.setenv("SKCOMMS_CORS_ORIGINS", origins)

    import skcomms.api as api

    importlib.reload(api)
    return api


def _preflight(client, path, origin):
    """A CORS preflight for a POST to ``path`` from ``origin``."""
    return client.options(
        path,
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
        },
    )


# --- default (empty allowlist): everything cross-origin is blocked -----------


@pytest.mark.parametrize("path", OPERATOR_ROUTES)
def test_default_blocks_operator_routes(monkeypatch, tmp_path, path):
    """With no SKCOMMS_CORS_ORIGINS set, no origin is approved for /mcp or /send."""
    api = _reload_api(monkeypatch, tmp_path, origins=None)
    resp = _preflight(TestClient(api.app), path, UNLISTED)
    assert "access-control-allow-origin" not in resp.headers


def test_default_blocks_simple_request(monkeypatch, tmp_path):
    """A simple (non-preflight) cross-origin GET is not exposed either."""
    api = _reload_api(monkeypatch, tmp_path, origins=None)
    resp = TestClient(api.app).get("/health", headers={"Origin": UNLISTED})
    assert "access-control-allow-origin" not in resp.headers


# --- explicit allowlist: only listed origins are approved --------------------


@pytest.mark.parametrize("path", OPERATOR_ROUTES)
def test_unlisted_origin_blocked_with_allowlist(monkeypatch, tmp_path, path):
    """A configured allowlist still blocks an origin that is not on it."""
    api = _reload_api(monkeypatch, tmp_path, origins=ALLOWED)
    resp = _preflight(TestClient(api.app), path, UNLISTED)
    assert "access-control-allow-origin" not in resp.headers


@pytest.mark.parametrize("path", OPERATOR_ROUTES)
def test_listed_origin_allowed(monkeypatch, tmp_path, path):
    """A listed origin gets an approving preflight for the operator routes."""
    api = _reload_api(monkeypatch, tmp_path, origins=ALLOWED)
    resp = _preflight(TestClient(api.app), path, ALLOWED)
    assert resp.headers.get("access-control-allow-origin") == ALLOWED


def test_allowlist_parses_multiple_and_trims(monkeypatch, tmp_path):
    """Comma-separated origins are split, whitespace-trimmed, blanks dropped."""
    api = _reload_api(
        monkeypatch, tmp_path, origins=f" {ALLOWED} , https://second.skworld.io ,"
    )
    assert api._cors_allow_origins() == [ALLOWED, "https://second.skworld.io"]
    client = TestClient(api.app)
    assert (
        _preflight(client, "/api/v1/send", "https://second.skworld.io").headers.get(
            "access-control-allow-origin"
        )
        == "https://second.skworld.io"
    )
