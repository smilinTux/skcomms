"""Tests for the SKFed directory service endpoints.

* ``GET /.well-known/skfed/directory`` — serve THIS realm's signed directory.
* ``POST /api/v1/skfed/announce`` — capauth-gated: an agent announces its
  current endpoints; the node upserts the entry, re-signs the directory with the
  node/operator key, and persists it.

PGP keys are generated in-process; the node signer is injected (monkeypatch) so
the test never touches a real on-disk key.
"""

from __future__ import annotations

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


@pytest.fixture(scope="module")
def operator_keys():
    return _gen_key("chef <chef@chef.skworld>")


@pytest.fixture(scope="module")
def jarvis_keys():
    return _gen_key("jarvis <jarvis@chef.skworld>")


REALM = "skworld"
OPERATOR = "chef"
JARVIS_FQID = "jarvis@chef.skworld"


@pytest.fixture
def client(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))

    import importlib

    import skcomms.api as api
    import skcomms.skfed_directory as sfd

    importlib.reload(sfd)
    importlib.reload(api)
    api._fed_nonce_cache = None
    api._fed_rate_limiter = None

    # Inject the node signer (the directory's re-signing key) so we don't touch
    # a real on-disk key.
    from skcomms.signing import EnvelopeSigner

    priv, _pub = operator_keys
    monkeypatch.setattr(api.skfed_directory, "load_node_signer", lambda agent=None: EnvelopeSigner(priv))

    return TestClient(api.app)


def _pin(from_fqid, pub_armor):
    from skcomms import tofu
    from skcomms.peers import fingerprint_from_pubkey

    fp = fingerprint_from_pubkey(pub_armor)
    tofu.record_fingerprint(from_fqid, fp, pubkey=pub_armor)


def _signed_announce(priv, *, fqid=JARVIS_FQID, inbox="https://jarvis.ts.net/api/v1/inbox",
                     prekey="https://jarvis.ts.net/api/v1/prekey", from_fqid=None):
    from skcomms.envelope import Envelope
    from skcomms.signing import EnvelopeSigner

    body = json.dumps({
        "fqid": fqid,
        "inbox_url": inbox,
        "prekey_url": prekey,
        "did": f"did:skfed:{fqid}",
        "caps": ["dm", "files"],
    })
    env = Envelope(
        from_fqid=from_fqid or fqid,
        to_fqid="directory@chef.skworld",
        body=body,
        content_type="application/skfed-announce+json",
    )
    return EnvelopeSigner(priv).sign(env).to_bytes()


# --- announce + serve ------------------------------------------------------


def test_announce_then_serve_directory(client, operator_keys, jarvis_keys, tmp_path):
    op_priv, op_pub = operator_keys
    j_priv, j_pub = jarvis_keys
    _pin(JARVIS_FQID, j_pub)

    resp = client.post("/api/v1/skfed/announce", content=_signed_announce(j_priv))
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert resp.json()["fqid"] == JARVIS_FQID

    # The persisted directory is now served at the well-known path.
    served = client.get("/.well-known/skfed/directory")
    assert served.status_code == 200, served.text

    from skcomms.signing import EnvelopeVerifier
    from skcomms.skfed_directory import SignedDirectory

    sd = SignedDirectory.from_bytes(served.content)
    entry = [e for e in sd.entries if e.fqid == JARVIS_FQID][0]
    assert entry.inbox_url == "https://jarvis.ts.net/api/v1/inbox"

    # Served directory is signed by the node/operator key.
    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, op_pub)
    assert sd.verify(verifier) is True


def test_announce_upsert_replaces(client, jarvis_keys):
    j_priv, j_pub = jarvis_keys
    _pin(JARVIS_FQID, j_pub)

    client.post("/api/v1/skfed/announce", content=_signed_announce(j_priv, inbox="https://a/api/v1/inbox"))
    client.post("/api/v1/skfed/announce", content=_signed_announce(j_priv, inbox="https://b/api/v1/inbox"))

    served = client.get("/.well-known/skfed/directory")
    from skcomms.skfed_directory import SignedDirectory

    sd = SignedDirectory.from_bytes(served.content)
    jarvis = [e for e in sd.entries if e.fqid == JARVIS_FQID]
    assert len(jarvis) == 1
    assert jarvis[0].inbox_url == "https://b/api/v1/inbox"


def test_announce_unsigned_rejected(client):
    resp = client.post("/api/v1/skfed/announce", content=b"not a signed envelope")
    assert resp.status_code == 422, resp.text


def test_announce_untrusted_signer_rejected(client, jarvis_keys):
    j_priv, _j_pub = jarvis_keys
    # Do NOT pin jarvis's key -> unknown signer -> fail closed.
    resp = client.post("/api/v1/skfed/announce", content=_signed_announce(j_priv))
    assert resp.status_code == 403, resp.text


def test_announce_cannot_announce_other_agent(client, jarvis_keys):
    """An agent may only announce its OWN fqid (signed-by == announced fqid)."""
    j_priv, j_pub = jarvis_keys
    _pin(JARVIS_FQID, j_pub)

    # Signed by jarvis but the body announces lumina -> 403.
    raw = _signed_announce(j_priv, fqid="lumina@chef.skworld", from_fqid=JARVIS_FQID)
    resp = client.post("/api/v1/skfed/announce", content=raw)
    assert resp.status_code == 403, resp.text


def test_serve_directory_absent_404(client):
    assert client.get("/.well-known/skfed/directory").status_code == 404
