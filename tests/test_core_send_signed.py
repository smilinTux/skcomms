"""SKComms.send sign-at-send tests (coord 9b882450).

The plain send path used to serialize a legacy unsigned MessageEnvelope while
the federation rail chain led with https-s2s, whose receiving gate
(``POST /api/v1/inbox``) parses ONLY a SignedEnvelope: every plain send 422'd
permanently on the primary rail and burned the round trip before falling back.

Sign-at-send unifies the wire format: ``SKComms.send`` now signs with the
per-agent capauth key exactly like ``send_federated``, so every rail carries
SignedEnvelope bytes. The legacy payload metadata rides in the ``x-skcomms-*``
Envelope v1 headers and is restored on receive. A keyless node falls back to
the explicit legacy local-only path (``Router.route``), which never offers
signed-envelope-only rails.
"""

from __future__ import annotations

import pytest

from skcomms import identity as identity_mod
from skcomms.core import (
    SKComms,
    WIRE_HEADER_ACK_REQUESTED,
    WIRE_HEADER_MESSAGE_TYPE,
    WIRE_HEADER_URGENCY,
    envelope_v1_to_message,
)
from skcomms.crypto import EnvelopeCrypto
from skcomms.envelope import SignedEnvelope
from skcomms.models import MessageEnvelope, MessageType, Urgency
from skcomms.outbox import PersistentOutbox, classify_envelope_json
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


class CaptureTransport(Transport):
    """A fake rail that records the exact wire bytes it is handed."""

    def __init__(self, name="https-s2s", priority=1, succeed=True):
        self.name = name
        self.priority = priority
        self.category = TransportCategory.REALTIME
        self._succeed = succeed
        self.sent: list[tuple[str, bytes]] = []

    def configure(self, c): pass
    def is_available(self): return True
    def send(self, envelope_bytes, recipient):
        self.sent.append((recipient, envelope_bytes))
        return SendResult(success=self._succeed, transport_name=self.name,
                          envelope_id="", latency_ms=0.0,
                          error=None if self._succeed else "rail down")
    def receive(self): return []
    def health_check(self):
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


@pytest.fixture
def keyed_comm(monkeypatch, tmp_path):
    """An SKComms with a real in-process signing key and a capture rail."""
    priv, pub, fp = _gen_key("jarvis <jarvis@chef.skworld>")
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"agent": "jarvis", "fqid": "jarvis@chef.skworld",
                                         "fingerprint": fp})
    t = CaptureTransport()
    comm = SKComms(router=Router(transports=[t]), crypto=EnvelopeCrypto(priv, "", fp))
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=comm._router)
    return comm, t, pub


# --- the wire format ---------------------------------------------------------


def test_plain_send_emits_signed_envelope_wire(keyed_comm):
    """SKComms.send puts SignedEnvelope bytes on the wire: the format the
    federation inbox gate parses (acceptance: SignedEnvelope.from_bytes)."""
    comm, t, pub = keyed_comm

    report = comm.send("lumina@chef.skworld", "hello over the primary rail")

    assert report.delivered is True
    recipient, wire = t.sent[0]
    assert recipient == "lumina@chef.skworld"

    # The exact bytes on the wire parse as a SignedEnvelope, classify as
    # "signed" (so https-s2s's structural gate admits them), and verify.
    signed = SignedEnvelope.from_bytes(wire)
    assert classify_envelope_json(wire.decode("utf-8")) == "signed"
    assert signed.envelope.from_fqid == "jarvis@chef.skworld"
    assert signed.envelope.to_fqid == "lumina@chef.skworld"
    assert signed.envelope.body == "hello over the primary rail"
    assert signed.envelope.nonce
    v = EnvelopeVerifier(); v.add_key("jarvis@chef.skworld", pub)
    assert v.verify(signed).valid is True

    # Delivery report keeps the legacy envelope_id (= Envelope v1 id).
    assert report.envelope_id == signed.envelope.id


def test_plain_send_metadata_rides_in_headers_and_round_trips(keyed_comm):
    """Legacy payload metadata survives the signed wire and converts back."""
    comm, t, _pub = keyed_comm

    comm.send("lumina@chef.skworld", "typed", message_type=MessageType.COMMAND,
              thread_id="th-1", in_reply_to="orig-1", urgency=Urgency.HIGH)

    signed = SignedEnvelope.from_bytes(t.sent[0][1])
    headers = signed.envelope.headers
    assert headers[WIRE_HEADER_MESSAGE_TYPE] == "command"
    assert headers[WIRE_HEADER_URGENCY] == "high"
    assert headers[WIRE_HEADER_ACK_REQUESTED] in ("0", "1")
    assert signed.envelope.thread_id == "th-1"
    assert signed.envelope.reply_to == "orig-1"

    # Receiving side: the shared converter restores the local model.
    msg = envelope_v1_to_message(signed.envelope)
    assert isinstance(msg, MessageEnvelope)
    assert msg.envelope_id == signed.envelope.id
    assert msg.payload.content == "typed"
    assert msg.payload.content_type is MessageType.COMMAND
    assert msg.metadata.urgency is Urgency.HIGH
    assert msg.metadata.thread_id == "th-1"
    assert msg.metadata.in_reply_to == "orig-1"


def test_plain_send_heartbeat_is_signed(keyed_comm):
    """The presence-heartbeat kind of send also emits SignedEnvelope bytes."""
    comm, t, _pub = keyed_comm

    comm.send("lumina", "status:online", message_type=MessageType.HEARTBEAT,
              urgency=Urgency.LOW)

    signed = SignedEnvelope.from_bytes(t.sent[0][1])
    assert signed.is_signed
    assert signed.envelope.body == "status:online"
    assert signed.envelope.headers[WIRE_HEADER_MESSAGE_TYPE] == "heartbeat"
    assert signed.envelope.headers[WIRE_HEADER_URGENCY] == "low"


def test_plain_send_failure_enqueues_signed_wire_to_outbox(monkeypatch, tmp_path):
    """A failed signed send queues the SIGNED wire shape (outbox owns retry)."""
    priv, _pub, fp = _gen_key("jarvis <jarvis@chef.skworld>")
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"agent": "jarvis", "fqid": "jarvis@chef.skworld",
                                         "fingerprint": fp})
    t = CaptureTransport(succeed=False)
    comm = SKComms(router=Router(transports=[t]), crypto=EnvelopeCrypto(priv, "", fp))
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=comm._router)

    report = comm.send("lumina@chef.skworld", "will fail")

    assert report.delivered is False
    assert comm._outbox.pending_count == 1
    entry = comm._outbox.list_pending()[0]
    assert classify_envelope_json(entry.envelope_json) == "signed"


# --- keyless fallback (explicit legacy local-only path) -----------------------


def test_keyless_send_falls_back_to_legacy_and_skips_https_s2s(monkeypatch, tmp_path):
    """Without a signing key the send stays unsigned AND stays off https-s2s."""
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"agent": "solo"})
    monkeypatch.setattr(EnvelopeCrypto, "from_capauth",
                        classmethod(lambda cls, *a, **k: None))

    s2s = CaptureTransport(name="https-s2s", priority=1)
    file_rail = CaptureTransport(name="file", priority=5)
    comm = SKComms(router=Router(transports=[s2s, file_rail]), crypto=None)
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=comm._router)

    report = comm.send("lumina", "unsigned local note")

    assert report.delivered is True
    assert s2s.sent == []                       # signed-only rail never offered
    _recipient, wire = file_rail.sent[0]
    legacy = MessageEnvelope.from_bytes(wire)   # legacy wire shape preserved
    assert legacy.payload.content == "unsigned local note"


# --- receive-side compatibility ----------------------------------------------


def test_receive_parses_signed_wire_from_local_rails(monkeypatch, tmp_path):
    """A signed plain send over the file rail still delivers via receive()."""
    from skcomms.transports.file import create_transport as make_file

    priv, _pub, fp = _gen_key("solo <solo@chef.skworld>")
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **k: {"agent": "solo", "fqid": "solo@chef.skworld",
                                         "fingerprint": fp})

    # One shared drop dir: what send writes is exactly what receive reads.
    drop = tmp_path / "drop"
    ft = make_file(priority=1, outbox_path=str(drop), inbox_path=str(drop),
                   archive=False)
    comm = SKComms(router=Router(transports=[ft]), crypto=EnvelopeCrypto(priv, "", fp))
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=comm._router)

    report = comm.send("solo", "note to self, now signed")
    assert report.attempts

    envelopes = comm.receive()
    assert any(e.payload.content == "note to self, now signed" for e in envelopes)
    got = next(e for e in envelopes if e.payload.content == "note to self, now signed")
    assert got.sender == "solo@chef.skworld"
    assert got.recipient == "solo"
