"""Wire-level regression tests for sign-at-send (coord 9b882450).

The outage: ``SKComms.send`` (behind ``POST /api/v1/send`` and the presence
heartbeat broadcast) serialized a legacy unsigned MessageEnvelope while the
federation rail chain led with https-s2s, whose receiving gate
(``POST /api/v1/inbox``) parses ONLY a SignedEnvelope. Every plain send 422'd
permanently on the primary rail and burned up to a 10s round trip per message
before falling back to the file rail.

These tests capture the EXACT bytes the plain send path emits and POST them
into the REAL inbox handler via the FastAPI TestClient, asserting 200 (not
422), end to end for both ``POST /api/v1/send`` and the presence heartbeat.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from skcomms import identity as identity_mod
from skcomms.core import SKComms, WIRE_HEADER_MESSAGE_TYPE
from skcomms.crypto import EnvelopeCrypto
from skcomms.envelope import SignedEnvelope
from skcomms.router import Router
from skcomms.transport import (
    HealthStatus, SendResult, Transport, TransportCategory, TransportStatus,
)

JARVIS_FQID = "jarvis@chef.skworld"
LUMINA_FQID = "lumina@chef.skworld"


def _gen_key(uid: str):
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm, HashAlgorithm, KeyFlags,
        PubKeyAlgorithm, SymmetricKeyAlgorithm,
    )
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey), str(key.fingerprint).replace(" ", "")


@pytest.fixture(scope="module")
def jarvis_keys():
    return _gen_key("jarvis <jarvis@chef.skworld>")


class CaptureTransport(Transport):
    """Fake https-s2s rail recording the exact wire bytes handed to it."""

    name = "https-s2s"
    priority = 1
    category = TransportCategory.REALTIME

    def __init__(self):
        self.sent: list[tuple[str, bytes]] = []

    def configure(self, c): pass
    def is_available(self): return True
    def send(self, envelope_bytes, recipient):
        self.sent.append((recipient, envelope_bytes))
        return SendResult(success=True, transport_name=self.name,
                          envelope_id="", latency_ms=0.0, error=None)
    def receive(self): return []
    def health_check(self):
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


@pytest.fixture
def api_env(tmp_path, monkeypatch, jarvis_keys):
    """Isolated api module + TestClient + a signing SKComms on a capture rail."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    import importlib

    import skcomms.api as api

    importlib.reload(api)
    api._fed_nonce_cache = None
    api._fed_rate_limiter = None

    priv, pub, fp = jarvis_keys
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"agent": "jarvis", "fqid": JARVIS_FQID,
                                         "fingerprint": fp})

    rail = CaptureTransport()
    comm = SKComms(router=Router(transports=[rail]),
                   crypto=EnvelopeCrypto(priv, "", fp))
    monkeypatch.setattr(api, "get_skcomms", lambda: comm)

    # Pin jarvis's pubkey (TOFU) so the inbox verifier trusts the sender.
    from skcomms import tofu
    from skcomms.peers import fingerprint_from_pubkey

    tofu.record_fingerprint(JARVIS_FQID, fingerprint_from_pubkey(pub), pubkey=pub)

    return TestClient(api.app), api, comm, rail


def test_plain_send_wire_bytes_are_accepted_by_the_inbox_gate(api_env):
    """THE regression: the exact bytes plain send emits must 200 at the peer
    inbox (they used to be a legacy MessageEnvelope and a guaranteed 422)."""
    client, _api, comm, rail = api_env

    report = comm.send(LUMINA_FQID, "plain send over the primary rail")
    assert report.delivered is True
    _recipient, wire = rail.sent[0]

    # Sanity: the wire is a SignedEnvelope, the shape the gate hard-requires.
    signed = SignedEnvelope.from_bytes(wire)
    assert signed.is_signed

    resp = client.post(
        "/api/v1/inbox",
        content=wire,
        headers={"Content-Type": "application/skcomms-signed-envelope+json"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["id"] == report.envelope_id

    # The 200 is backed by a real per-recipient inbox file on disk.
    assert _recipient_inbox_file(LUMINA_FQID, report.envelope_id).exists()


def _recipient_inbox_file(fqid: str, envelope_id: str):
    """Path the inbox handler writes a delivered envelope to.

    Resolved through ``skcomms.paths.fed_inbox_dir``: the SAME single resolver
    ``api._write_to_recipient_inbox`` uses (coord 119b49f1), so this helper can
    never drift from the writer. Under the fixture's SKCOMMS_HOME the inbox
    lives inside that home, not under the per-user HOME.
    """
    from skcomms.paths import fed_inbox_dir
    from skcomms.transports.file import ENVELOPE_SUFFIX

    agent = fqid.split("@")[0]
    return fed_inbox_dir(agent) / f"{envelope_id}{ENVELOPE_SUFFIX}"


def test_send_federated_wire_bytes_are_accepted_by_the_inbox_gate(api_env, monkeypatch):
    """Contract for the node-to-node federation path: the exact bytes
    ``SKComms.send_federated`` hands to the https-s2s rail must 200 at the peer
    inbox AND land as the per-recipient inbox file (never a legacy 422)."""
    client, _api, comm, rail = api_env

    # send_federated auto-discovers unknown fqids off the Nostr directory; keep
    # that best-effort lookup off the network in the test.
    from skcomms import nostr_discovery

    monkeypatch.setattr(nostr_discovery, "ensure_peer", lambda *a, **k: None)

    report = comm.send_federated(LUMINA_FQID, "federated node-to-node hello")
    assert report.delivered is True
    _recipient, wire = rail.sent[0]

    # The federation rail carries a signed canonical Envelope v1, the only shape
    # the receiving gate parses.
    signed = SignedEnvelope.from_bytes(wire)
    assert signed.is_signed

    resp = client.post(
        "/api/v1/inbox",
        content=wire,
        headers={"Content-Type": "application/skcomms-signed-envelope+json"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["id"] == report.envelope_id

    # The 200 is backed by a real per-recipient inbox file on disk.
    inbox_file = _recipient_inbox_file(LUMINA_FQID, report.envelope_id)
    assert inbox_file.exists(), f"expected inbox file at {inbox_file}"


def test_api_send_end_to_end_reaches_peer_inbox_with_200(api_env):
    """POST /api/v1/send -> wire bytes -> peer's POST /api/v1/inbox -> 200."""
    client, _api, _comm, rail = api_env

    resp = client.post(
        "/api/v1/send",
        json={"recipient": LUMINA_FQID, "message": "hello via the REST seam"},
    )
    assert resp.status_code == 200, resp.text
    sent = resp.json()
    assert sent["delivered"] is True
    assert sent["transport_used"] == "https-s2s"

    _recipient, wire = rail.sent[0]
    inbox_resp = client.post(
        "/api/v1/inbox",
        content=wire,
        headers={"Content-Type": "application/skcomms-signed-envelope+json"},
    )
    assert inbox_resp.status_code == 200, inbox_resp.text
    assert inbox_resp.json()["ok"] is True
    assert inbox_resp.json()["id"] == sent["envelope_id"]


def test_presence_heartbeat_broadcast_emits_signed_envelopes(api_env, monkeypatch):
    """The presence heartbeat broadcast puts SignedEnvelope bytes on the rail
    (it used to be the highest-volume legacy 422 source: one per peer/minute)."""
    client, api, _comm, rail = api_env

    # Keep the heartbeat-file phase off the real filesystem.
    class _StubPublisher:
        def __init__(self, *a, **k): pass
        def publish(self): return "stub-heartbeat-path"

    monkeypatch.setattr(api, "HeartbeatPublisher", _StubPublisher)

    # A known peer so phase 2 broadcasts to someone.
    from skcomms.discovery import PeerInfo, PeerStore

    PeerStore().add(PeerInfo(name="lumina"))

    resp = client.post("/api/v1/presence", json={"status": "online"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["broadcast"] and body["broadcast"][0]["delivered"] is True

    _recipient, wire = rail.sent[0]
    signed = SignedEnvelope.from_bytes(wire)
    assert signed.is_signed
    assert signed.envelope.body.startswith("status:online")
    assert signed.envelope.headers[WIRE_HEADER_MESSAGE_TYPE] == "heartbeat"

    # And the signed heartbeat is accepted by a peer inbox gate, not 422'd.
    inbox_resp = client.post(
        "/api/v1/inbox",
        content=wire,
        headers={"Content-Type": "application/skcomms-signed-envelope+json"},
    )
    assert inbox_resp.status_code == 200, inbox_resp.text
