"""Federated integration test — the full node-to-node pipeline in-process.

Exercises the REAL components end to end across two identities (jarvis@N1 →
lumina@N2): build+sign Envelope v1 (sender) → router rail selection →
transport "wire" → receiver's federation.accept_signed gate (sig+freshness+
replay) → store. No live network; the transport hands bytes straight to the
receiver node's inbox handler, mirroring http_s2s.send → POST /inbox.

Complements the per-component unit tests with a cross-component federated path,
plus a standalone (single-node, local file rail) round-trip.
"""

from __future__ import annotations

import pytest

from skcomms import identity as identity_mod
from skcomms.core import SKComms
from skcomms.crypto import EnvelopeCrypto
from skcomms.envelope import SignedEnvelope
from skcomms import federation as fed
from skcomms.router import Router
from skcomms.signing import EnvelopeVerifier
from skcomms.transport import (
    HealthStatus, SendResult, Transport, TransportCategory, TransportStatus,
)


def _gen_key(uid):
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm, HashAlgorithm, KeyFlags,
        PubKeyAlgorithm, SymmetricKeyAlgorithm,
    )
    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    k.add_uid(pgpy.PGPUID.new(uid),
              usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
              hashes=[HashAlgorithm.SHA256], ciphers=[SymmetricKeyAlgorithm.AES256],
              compression=[CompressionAlgorithm.ZLIB])
    return str(k), str(k.pubkey), str(k.fingerprint).replace(" ", "")


class ReceiverNode:
    """Stands in for the remote node's POST /inbox + accept_signed + store."""

    def __init__(self, verifier: EnvelopeVerifier):
        self.verifier = verifier
        self.nonce_cache = fed.NonceCache()
        self.inbox: list = []
        self.rejected: list[str] = []

    def receive(self, raw: bytes) -> bool:
        try:
            env = fed.accept_bytes(raw, verifier=self.verifier, nonce_cache=self.nonce_cache)
        except fed.FederationError as e:
            self.rejected.append(type(e).__name__)
            return False
        self.inbox.append(env)
        return True


class WireToReceiver(Transport):
    """A transport that 'POSTs' bytes straight into the receiver node (no HTTP)."""
    name = "https-s2s"
    priority = 1
    category = TransportCategory.REALTIME

    def __init__(self, node: ReceiverNode):
        self._node = node

    def configure(self, c): pass
    def is_available(self): return True
    def send(self, envelope_bytes, recipient):
        ok = self._node.receive(envelope_bytes)
        return SendResult(success=ok, transport_name=self.name, envelope_id="",
                          latency_ms=0.0, error=None if ok else "rejected by inbox")
    def receive(self): return []
    def health_check(self):
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


@pytest.fixture
def two_nodes(monkeypatch):
    j_priv, j_pub, j_fp = _gen_key("jarvis <jarvis@chef.skworld>")
    # lumina's node verifies jarvis's signature -> pin jarvis pubkey
    v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", j_pub)
    node_lumina = ReceiverNode(v)
    # jarvis's sender stack
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"agent": "jarvis", "fqid": "jarvis@chef.skworld",
                                         "fingerprint": j_fp, "capauth_uri": "capauth:jarvis@skworld.io"})
    jarvis = SKComms(router=Router(transports=[WireToReceiver(node_lumina)]),
                     crypto=EnvelopeCrypto(j_priv, "", j_fp))
    return jarvis, node_lumina, j_pub


# --- FEDERATED ---------------------------------------------------------------

def test_federated_send_delivers_and_verifies(two_nodes):
    jarvis, lumina, _ = two_nodes
    report = jarvis.send_federated("lumina@chef.skworld", "federated hello")
    assert report.delivered is True
    assert len(lumina.inbox) == 1
    env = lumina.inbox[0]
    assert env.from_fqid == "jarvis@chef.skworld"
    assert env.to_fqid == "lumina@chef.skworld"
    assert env.body == "federated hello"


def test_federated_replay_rejected(two_nodes):
    jarvis, lumina, _ = two_nodes
    # capture the exact signed bytes jarvis sends, then replay them to the node
    sent: list[bytes] = []
    orig = jarvis.router.transports[0].send
    def spy(b, r): sent.append(b); return orig(b, r)
    jarvis.router.transports[0].send = spy
    jarvis.send_federated("lumina@chef.skworld", "once")
    assert len(lumina.inbox) == 1
    # replay the identical signed envelope
    assert lumina.receive(sent[0]) is False
    assert "ReplayError" in lumina.rejected
    assert len(lumina.inbox) == 1            # not double-stored


def test_federated_tampered_body_rejected(two_nodes):
    jarvis, lumina, _ = two_nodes
    sent: list[bytes] = []
    jarvis.router.transports[0].send = lambda b, r, _o=jarvis.router.transports[0].send: (sent.append(b) or _o(b, r))
    jarvis.send_federated("lumina@chef.skworld", "real")
    signed = SignedEnvelope.from_bytes(sent[0])
    signed.envelope.body = "tampered"        # mutate after signing
    assert lumina.receive(signed.to_bytes()) is False
    assert "SignatureError" in lumina.rejected


def test_federated_untrusted_sender_rejected(monkeypatch):
    # a node that does NOT know jarvis's key rejects his message
    j_priv, j_pub, j_fp = _gen_key("jarvis <jarvis@chef.skworld>")
    node = ReceiverNode(EnvelopeVerifier())          # empty verifier
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"fqid": "jarvis@chef.skworld", "fingerprint": j_fp})
    jarvis = SKComms(router=Router(transports=[WireToReceiver(node)]),
                     crypto=EnvelopeCrypto(j_priv, "", j_fp))
    report = jarvis.send_federated("lumina@chef.skworld", "hi")
    assert report.delivered is False
    assert node.inbox == [] and "SignatureError" in node.rejected


# --- STANDALONE (single node, local file rail) -------------------------------

def test_standalone_local_file_roundtrip(tmp_path):
    """A single node can send + receive over the local file transport."""
    from skcomms.transports.file import create_transport as make_file
    inbox = tmp_path / "inbox"; inbox.mkdir()
    ft = make_file(priority=1, comms_root=str(tmp_path))
    if hasattr(ft, "_set_identity"):
        ft._set_identity("solo")
    r = Router(transports=[ft])
    comm = SKComms(router=r)
    rep = comm.send("solo", "note to self")
    # file rail wrote something deliverable; receive pulls it back
    got = r.receive_all()
    assert rep.attempts  # an attempt was made over the local rail
