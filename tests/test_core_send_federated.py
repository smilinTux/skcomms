"""Test SKComms.send_federated — the S4b canonical federation send path.

Builds + signs an Envelope v1 and routes the SignedEnvelope bytes over the
selected rail (here a fake https-s2s), addressed by to_fqid.
"""

from __future__ import annotations

import pytest

from skcomms import identity as identity_mod
from skcomms.core import SKComms
from skcomms.crypto import EnvelopeCrypto
from skcomms.envelope import SignedEnvelope
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


class CapTransport(Transport):
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


def test_send_federated_builds_signs_routes(monkeypatch):
    priv, pub, fp = _gen_key("jarvis <jarvis@chef.skworld>")
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"agent": "jarvis", "fqid": "jarvis@chef.skworld",
                                         "fingerprint": fp, "capauth_uri": "capauth:jarvis@skworld.io"})
    t = CapTransport()
    comm = SKComms(router=Router(transports=[t]),
                   crypto=EnvelopeCrypto(priv, "", fp))

    report = comm.send_federated("lumina@chef.skworld", "hi over s2s")

    assert report.delivered is True
    recipient, wire = t.sent[0]
    assert recipient == "lumina@chef.skworld"               # routed by to_fqid
    # wire bytes are a real SignedEnvelope from jarvis, verifiable with jarvis's pubkey
    signed = SignedEnvelope.from_bytes(wire)
    assert signed.envelope.from_fqid == "jarvis@chef.skworld"
    assert signed.envelope.to_fqid == "lumina@chef.skworld"
    assert signed.envelope.body == "hi over s2s"
    assert signed.envelope.nonce                            # anti-replay nonce present
    v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", pub)
    assert v.verify(signed).valid is True                   # signature valid


def test_send_federated_no_key_raises(monkeypatch):
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"fqid": "jarvis@chef.skworld"})
    monkeypatch.setattr(EnvelopeCrypto, "from_capauth", classmethod(lambda cls, *a, **k: None))
    comm = SKComms(router=Router(transports=[CapTransport()]), crypto=None)
    with pytest.raises(RuntimeError):
        comm.send_federated("lumina@chef.skworld", "hi")
