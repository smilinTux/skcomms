"""Tests for the federation S2S inbox (SKFed S2) + peer addressing (S5).

Covers ``POST /api/v1/inbox`` — the receive gate that parses a
:class:`skcomms.envelope.SignedEnvelope`, runs
:func:`skcomms.federation.accept_signed` (signature -> freshness -> replay),
and stores the verified envelope in the recipient's file-transport inbox so the
existing ``comm.receive()`` path delivers it.

Reject mapping under test: 403 (untrusted/bad sig), 409 (replay), 422 (stale /
unparseable). Also covers ``discovery.inbox_url_for`` resolution.

PGP keys are generated in-process via pgpy (no live CapAuth), and the signer's
pubkey is pinned in the TOFU store so the inbox verifier trusts it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


# --- key fixture (mirrors tests/test_federation.py) ------------------------


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


@pytest.fixture(scope="module")
def jarvis_keys():
    return _gen_key("jarvis <jarvis@chef.skworld>")


@pytest.fixture(scope="module")
def evil_keys():
    return _gen_key("evil <evil@attacker.realm>")


JARVIS_FQID = "jarvis@chef.skworld"
LUMINA_FQID = "lumina@chef.skworld"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient with an isolated SKCOMMS_HOME and fresh federation state."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))

    import importlib

    import skcomms.api as api

    importlib.reload(api)
    # Reset per-process federation state so each test starts clean.
    api._fed_nonce_cache = None
    api._fed_rate_limiter = None
    return TestClient(api.app)


def _signed_bytes(priv_armor: str, *, from_fqid=JARVIS_FQID, to_fqid=LUMINA_FQID,
                  body="hello over the wire", created_at=None) -> bytes:
    from skcomms.envelope import Envelope
    from skcomms.signing import EnvelopeSigner

    kw = {}
    if created_at is not None:
        kw["created_at"] = created_at
    env = Envelope(from_fqid=from_fqid, to_fqid=to_fqid, body=body, **kw)
    signed = EnvelopeSigner(priv_armor).sign(env)
    return signed.to_bytes()


def _pin(from_fqid: str, pub_armor: str) -> None:
    """Pin a peer's pubkey in the TOFU store so the inbox verifier trusts it."""
    from skcomms import tofu

    tofu.record_fingerprint(from_fqid, "0" * 40, pubkey=pub_armor)
    # Overwrite the placeholder fp with the real one (record keeps pubkey).
    from skcomms.peers import fingerprint_from_pubkey

    fp = fingerprint_from_pubkey(pub_armor)
    tofu.record_fingerprint(from_fqid, fp, pubkey=pub_armor)


# --- POST /api/v1/inbox ----------------------------------------------------


def test_inbox_happy_path_stores_and_200(client, jarvis_keys, tmp_path):
    priv, pub = jarvis_keys
    _pin(JARVIS_FQID, pub)

    raw = _signed_bytes(priv)
    resp = client.post(
        "/api/v1/inbox",
        content=raw,
        headers={"Content-Type": "application/skcomms-signed-envelope+json"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    env_id = body["id"]

    # Verified envelope was written to the file-transport inbox dir.
    inbox = tmp_path / "inbox"
    files = list(inbox.glob("*.skc.json"))
    assert len(files) == 1
    assert files[0].name == f"{env_id}.skc.json"

    from skcomms.models import MessageEnvelope

    stored = MessageEnvelope.from_bytes(files[0].read_bytes())
    assert stored.envelope_id == env_id
    assert stored.sender == JARVIS_FQID
    assert stored.recipient == LUMINA_FQID
    assert stored.payload.content == "hello over the wire"


def test_inbox_untrusted_signer_403(client, jarvis_keys):
    priv, _pub = jarvis_keys
    # Note: we DO NOT pin the pubkey -> unknown signer -> signature fails closed.
    raw = _signed_bytes(priv)
    resp = client.post("/api/v1/inbox", content=raw)
    assert resp.status_code == 403, resp.text


def test_inbox_bad_signature_403(client, jarvis_keys, evil_keys):
    """Pinned key for the fqid, but the envelope was signed by a different key."""
    _priv_j, pub_j = jarvis_keys
    priv_e, _pub_e = evil_keys
    _pin(JARVIS_FQID, pub_j)  # trust jarvis's key

    # Sign as jarvis's fqid but with the EVIL key -> sig won't verify.
    raw = _signed_bytes(priv_e, from_fqid=JARVIS_FQID)
    resp = client.post("/api/v1/inbox", content=raw)
    assert resp.status_code == 403, resp.text


def test_inbox_replay_409(client, jarvis_keys):
    priv, pub = jarvis_keys
    _pin(JARVIS_FQID, pub)

    raw = _signed_bytes(priv)
    first = client.post("/api/v1/inbox", content=raw)
    assert first.status_code == 200, first.text
    # Same bytes (same nonce) again -> replay.
    second = client.post("/api/v1/inbox", content=raw)
    assert second.status_code == 409, second.text


def test_inbox_stale_422(client, jarvis_keys):
    priv, pub = jarvis_keys
    _pin(JARVIS_FQID, pub)

    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    raw = _signed_bytes(priv, created_at=old)
    resp = client.post("/api/v1/inbox", content=raw)
    assert resp.status_code == 422, resp.text


def test_inbox_unparseable_422(client):
    resp = client.post("/api/v1/inbox", content=b"this is not a signed envelope")
    assert resp.status_code == 422, resp.text


def test_messages_endpoint_replaces_get_inbox(client):
    """The old GET /inbox local poll now lives at GET /api/v1/messages."""
    # GET on the federation /inbox is method-not-allowed (it's POST only).
    assert client.get("/api/v1/inbox").status_code == 405
    # The renamed local poll exists (may 500 without a full config, but routed).
    assert client.get("/api/v1/messages").status_code != 404


# --- S5 peer addressing: inbox_url_for -------------------------------------


def test_inbox_url_for_resolves_https_s2s(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.discovery import (
        PeerInfo,
        PeerStore,
        PeerTransport,
        inbox_url_for,
    )

    store = PeerStore(peers_dir=tmp_path / "peers")
    url = "https://noroc2027.ts.net/api/v1/inbox"
    store.add(
        PeerInfo(
            name="jarvis",
            fqid=JARVIS_FQID,
            rails=["https-s2s", "nostr"],
            transports=[
                PeerTransport(transport="https-s2s", settings={"inbox_url": url})
            ],
        )
    )

    assert inbox_url_for(JARVIS_FQID, store=store) == url
    # Bare agent-name fallback also resolves.
    assert inbox_url_for("jarvis", store=store) == url
    # Unknown peer -> None.
    assert inbox_url_for("nobody@nowhere.realm", store=store) is None


def test_migrate_file_transports_drops_dead_ends(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.discovery import (
        PeerInfo,
        PeerStore,
        PeerTransport,
        migrate_file_transports,
    )

    store = PeerStore(peers_dir=tmp_path / "peers")
    store.add(
        PeerInfo(
            name="legacy",
            transports=[
                PeerTransport(transport="file", settings={"inbox_path": "file:///dead/end"}),
                PeerTransport(transport="https-s2s", settings={"inbox_url": "https://x/api/v1/inbox"}),
            ],
        )
    )

    migrated = migrate_file_transports(store=store)
    assert "legacy" in migrated

    peer = store.get("legacy")
    transports = {t.transport for t in peer.transports}
    assert "file" not in transports
    assert "https-s2s" in transports
