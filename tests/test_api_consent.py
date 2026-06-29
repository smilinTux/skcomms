"""Tests for the operator consent surface (``/api/v1/consent/*``).

These are the LOCAL/OPERATOR endpoints the recipient agent uses to drive its OWN
first-contact message-request queue (skfed-consent-design gate 5): review the
quarantine, accept (promote + mint a per-contact token), decline, block, unblock,
and list the known-contact roster.

The endpoints are gated to loopback (or the existing ``SKCOMMS_DEV_AUTH`` escape
hatch) so the public federation funnel can never drive accept/block — only the
node's own operator can. The recipient agent is the node's self identity (the same
resolution the rest of ``api.py`` uses); the fixture pins it via ``api._self_agent``
so the queue we seed and the endpoints under test target the same agent.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


SELF_AGENT = "lumina"
SENDER = "jarvis@chef.skworld"


@pytest.fixture
def api_mod(tmp_path, monkeypatch):
    """The reloaded api module bound to an isolated SKCOMMS_HOME + fixed self agent."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.delenv("SKCOMMS_CONSENT_MODE", raising=False)
    monkeypatch.delenv("SKCOMMS_DEV_AUTH", raising=False)

    import skcomms.api as api

    importlib.reload(api)
    api._fed_nonce_cache = None
    api._fed_rate_limiter = None
    # Pin the node's self identity so the endpoints and the seeded queue agree.
    monkeypatch.setattr(api, "_self_agent", lambda: SELF_AGENT)
    return api


@pytest.fixture
def client(api_mod):
    """Loopback TestClient — exercises the allowed (local) path of the gate."""
    return TestClient(api_mod.app, client=("127.0.0.1", 51000))


def _enqueue(sender: str = SENDER, body: bytes = b"knock knock", envelope_id: str = "env-1"):
    """Seed a first-contact knock straight into the recipient's request queue."""
    from skcomms.consent import RequestQueue

    RequestQueue(SELF_AGENT).enqueue(sender, body, envelope_id=envelope_id)


# --- GET /api/v1/consent/requests -----------------------------------------


def test_requests_empty(client):
    resp = client.get("/api/v1/consent/requests")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent"] == SELF_AGENT
    assert body["requests"] == []


def test_requests_lists_enqueued(client):
    _enqueue()
    resp = client.get("/api/v1/consent/requests")
    assert resp.status_code == 200, resp.text
    reqs = resp.json()["requests"]
    assert len(reqs) == 1
    assert reqs[0]["sender"] == SENDER
    assert reqs[0]["envelope_id"] == "env-1"


# --- POST /api/v1/consent/accept ------------------------------------------


def test_accept_mints_token_and_promotes_to_known(client):
    _enqueue()
    resp = client.post("/api/v1/consent/accept", json={"sender": SENDER})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sender"] == SENDER
    assert isinstance(body["token"], str) and body["token"]

    # Now a known contact.
    known = client.get("/api/v1/consent/known")
    assert known.status_code == 200, known.text
    assert SENDER in known.json()["known"]


# --- POST /api/v1/consent/decline -----------------------------------------


def test_decline_without_block_returns_to_unknown(client):
    _enqueue()
    resp = client.post("/api/v1/consent/decline", json={"sender": SENDER})
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] == "declined"

    # Queue cleared, not promoted, not blocked.
    assert client.get("/api/v1/consent/requests").json()["requests"] == []
    assert SENDER not in client.get("/api/v1/consent/known").json()["known"]


def test_decline_with_block(client):
    _enqueue()
    resp = client.post("/api/v1/consent/decline", json={"sender": SENDER, "block": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] == "blocked"

    from skcomms.consent import ContactStore

    assert ContactStore(SELF_AGENT).is_blocked(SENDER)


# --- POST /api/v1/consent/block + /unblock ---------------------------------


def test_block_then_unblock(client):
    resp = client.post("/api/v1/consent/block", json={"sender": SENDER})
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] == "blocked"

    from skcomms.consent import ContactStore

    assert ContactStore(SELF_AGENT).is_blocked(SENDER)

    un = client.post("/api/v1/consent/unblock", json={"sender": SENDER})
    assert un.status_code == 200, un.text
    assert un.json()["result"] == "unblocked"
    assert not ContactStore(SELF_AGENT).is_blocked(SENDER)


# --- loopback / operator gating -------------------------------------------


def test_non_local_caller_is_forbidden(api_mod):
    """A non-loopback caller cannot drive the operator surface."""
    remote = TestClient(api_mod.app, client=("203.0.113.7", 40000))
    for method, path in [
        ("get", "/api/v1/consent/requests"),
        ("get", "/api/v1/consent/known"),
    ]:
        resp = getattr(remote, method)(path)
        assert resp.status_code == 403, (path, resp.text)
    for path in [
        "/api/v1/consent/accept",
        "/api/v1/consent/decline",
        "/api/v1/consent/block",
        "/api/v1/consent/unblock",
    ]:
        resp = remote.post(path, json={"sender": SENDER})
        assert resp.status_code == 403, (path, resp.text)


def test_dev_auth_allows_non_local(api_mod, monkeypatch):
    """The existing dev-auth escape hatch opens the gate for non-loopback callers."""
    monkeypatch.setenv("SKCOMMS_DEV_AUTH", "1")
    remote = TestClient(api_mod.app, client=("203.0.113.7", 40000))
    resp = remote.get("/api/v1/consent/requests")
    assert resp.status_code == 200, resp.text
