"""Tests for the P9 access-token mint endpoint — POST /api/v1/access/token.

The Flutter skos surfaces can't produce the OpenPGP detached signature the
sk-access gate requires (their in-app crypto is RSA/PKCS#1, not OpenPGP), so the
daemon mints the token on their behalf using this node's CapAuth PGP key. These
tests prove:

  * the minted token is a well-formed :class:`~skcomms.envelope.SignedEnvelope`
    carrying the requested {tool, arguments} in its Envelope-v1 body;
  * a REAL :class:`~skcomms.access.server.AccessServer` capauth gate ACCEPTS the
    minted token (full signature round-trip via the TOFU-pinned verifier) — i.e.
    the token the app would forward to a node's /tool is genuinely valid;
  * when no signing key is available the endpoint fails 503 (not 500/200).
"""

from __future__ import annotations

import importlib
import json

import pytest
from fastapi.testclient import TestClient


def _gen_key(uid: str):
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey)


CALLER_FQID = "lumina@chef.skworld"


@pytest.fixture(scope="module")
def caller_keys():
    return _gen_key(f"caller <{CALLER_FQID}>")


@pytest.fixture
def client(tmp_path, monkeypatch, caller_keys):
    """A TestClient whose daemon identity is a known in-process key."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))

    import skcomms.api as api

    importlib.reload(api)

    priv, _pub = caller_keys
    from skcomms.access import routing
    from skcomms.signing import EnvelopeSigner

    # The daemon signs with our in-process key (no real ~/.capauth needed).
    monkeypatch.setattr(routing, "_load_signer", lambda agent: EnvelopeSigner(priv))
    # Pin a stable self-identity so from_fqid is deterministic.
    monkeypatch.setattr(
        api,
        "resolve_self_identity",
        lambda *a, **k: {"agent": "lumina", "fqid": CALLER_FQID},
        raising=False,
    )
    # api imports resolve_self_identity lazily inside the handler, so patch the
    # source module too.
    import skcomms.identity as ident_mod

    monkeypatch.setattr(
        ident_mod,
        "resolve_self_identity",
        lambda *a, **k: {"agent": "lumina", "fqid": CALLER_FQID},
    )
    return TestClient(api.app)


def test_mint_token_is_signed_envelope_with_tool_body(client):
    resp = client.post(
        "/api/v1/access/token",
        json={"node": ".41", "tool": "file_read", "arguments": {"path": "/x"}},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["from_fqid"] == CALLER_FQID
    assert len(data["fingerprint"]) == 40

    # The token is a SignedEnvelope JSON string the /tool endpoint accepts.
    token = json.loads(data["token"])
    assert token["signature"]  # detached PGP signature present
    assert token["signer_fingerprint"] == data["fingerprint"]
    env = token["envelope"]
    assert env["from_fqid"] == CALLER_FQID
    body = json.loads(env["body"])
    assert body["tool"] == "file_read"
    assert body["arguments"] == {"path": "/x"}


def test_minted_token_accepted_by_real_access_gate(client, caller_keys):
    """End-to-end: the token the daemon mints is accepted by a real sk-access
    capauth gate (TOFU-pinned caller pubkey + signature + freshness + replay)."""
    from skcomms.access.server import AccessError, AccessServer
    from skcomms.access.config import AccessConfig

    _priv, pub = caller_keys

    resp = client.post(
        "/api/v1/access/token",
        json={"node": ".158", "tool": "health", "arguments": {}},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]

    # Stand up a real server gate and pin the caller's pubkey (TOFU).
    srv = AccessServer(config=AccessConfig(node_name="testnode"))
    srv.trust_key(CALLER_FQID, pub)

    # authenticate() runs accept_signed (sig + freshness + replay). A valid
    # token yields a ToolContext; a bad one raises AccessError.
    ctx = srv.authenticate(token)
    assert ctx.identity == CALLER_FQID

    # Replay of the SAME token is rejected (nonce already seen).
    with pytest.raises(AccessError):
        srv.authenticate(token)


def test_mint_token_no_key_returns_503(client, monkeypatch):
    from skcomms.access import routing

    def _no_key(agent):
        raise FileNotFoundError(f"no PGP private key for {agent!r}")

    monkeypatch.setattr(routing, "_load_signer", _no_key)
    resp = client.post(
        "/api/v1/access/token",
        json={"node": ".41", "tool": "file_read", "arguments": {}},
    )
    assert resp.status_code == 503, resp.text
    assert "CapAuth signing key" in resp.json()["detail"]
