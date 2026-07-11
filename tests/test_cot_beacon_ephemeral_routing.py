"""Ephemeral CoT beacon: short-TTL + no-ack wire + CoT peer-capability gate.

The strategic fix for the CoT presence-beacon durable-inbox flood. Ephemeral
position beacons (atoms, ``a-*``) are continuously re-beaconed, so on EVERY
receiver they must (a) carry a short TTL + ``ack_requested=False`` so they never
become long-lived durable inbox files, and (b) only be federated to peers that
advertise a CoT/TAK consumer capability -- a human / no-consumer peer (e.g.
``chef@chef.skworld``) must never receive PLI at all. Durable CoT events
(GeoChat / markers, ``b-*``) and real messages are unaffected: full peer set,
default TTL, ack requested.

Covers, bottom-up:

  * ``send_federated`` accepts ``ttl`` / ``ack_requested`` overrides and stamps
    them onto the Envelope v1 wire headers (backward-compatible: ``None`` leaves
    the envelope byte-identical to before);
  * ``envelope_v1_to_message`` restores the short TTL + no-ack on the receiver
    (absent headers keep the historical durable defaults);
  * ``_cot_peer_fqids`` fail-closed gate: only CoT-capable peers (advertised
    capability OR ``SKCOMMS_COT_PEERS`` allowlist), default empty;
  * ``federation_ingest`` hook: ephemeral beacon -> short ttl + ack False +
    supersede_key + CoT-gated peer set; durable event -> unchanged.
"""

from __future__ import annotations

import skcomms.discovery as discovery_mod
from skcomms.core import (
    WIRE_HEADER_ACK_REQUESTED,
    WIRE_HEADER_TTL,
    envelope_v1_to_message,
)
from skcomms.cot import parse_cot
from skcomms.cot_server import _cot_peer_fqids, federation_ingest
from skcomms.discovery import PeerInfo, PeerTransport
from skcomms.envelope import Envelope

PLI = (  # a CoT atom -> ephemeral position beacon (PLI). stale = time + 5 min.
    '<event version="2.0" uid="ANDROID-1" type="a-f-G-U-C" how="m-g"'
    ' time="2026-06-22T03:00:00.000Z" start="2026-06-22T03:00:00.000Z"'
    ' stale="2026-06-22T03:05:00.000Z">'
    '<point lat="38.8895" lon="-77.0353" hae="50.0" ce="9.0" le="9.0"/>'
    '<detail><contact callsign="JARVIS-1"/></detail></event>'
)
GEOCHAT = (  # a CoT bit -> durable GeoChat event
    '<event version="2.0" uid="GeoChat.ANDROID-1.All.123" type="b-t-f" how="h-g-i-g-o"'
    ' time="2026-06-22T03:01:00.000Z" start="2026-06-22T03:01:00.000Z"'
    ' stale="2026-06-22T03:11:00.000Z">'
    '<point lat="38.8895" lon="-77.0353" hae="9999999.0" ce="9999999.0" le="9999999.0"/>'
    '<detail><remarks>contact rear, moving to RP</remarks></detail></event>'
)


# --------------------------------------------------------------------------
# federation_ingest hook: ephemeral -> short ttl + no ack + CoT-gated peers
# --------------------------------------------------------------------------
class _RecordingSk:
    """Captures every send_federated call incl. the new ttl / ack kwargs."""

    def __init__(self):
        self.calls = []

    def send_federated(self, to_fqid, message, *, content_type="text/plain",
                       supersede_key=None, ttl=None, ack_requested=None, **kw):
        self.calls.append({
            "to_fqid": to_fqid, "supersede_key": supersede_key,
            "ttl": ttl, "ack_requested": ack_requested,
        })


def test_hook_ephemeral_beacon_short_ttl_and_no_ack():
    sk = _RecordingSk()
    hook = federation_ingest(
        sk, from_fqid="jarvis@chef.skworld",
        peers_provider=lambda: ["lumina@chef.skworld"],
    )
    hook(parse_cot(PLI))
    assert len(sk.calls) == 1
    call = sk.calls[0]
    assert call["ack_requested"] is False
    assert call["supersede_key"] == "cot-beacon:lumina@chef.skworld:ANDROID-1"
    # short ttl: positive and well under the 86400 durable default.
    assert isinstance(call["ttl"], int)
    assert 0 < call["ttl"] <= 300


def test_hook_durable_event_unchanged_ttl_ack():
    sk = _RecordingSk()
    hook = federation_ingest(
        sk, from_fqid="jarvis@chef.skworld",
        peers_provider=lambda: ["lumina@chef.skworld"],
    )
    hook(parse_cot(GEOCHAT))
    assert len(sk.calls) == 1
    call = sk.calls[0]
    assert call["supersede_key"] is None       # durable: reliably queued
    assert call["ttl"] is None                 # no override -> config default
    assert call["ack_requested"] is None       # no override -> ack requested


def test_hook_ephemeral_gated_to_cot_peers_only():
    """Beacons use the CoT-capable provider; durable events use the full set."""
    sk = _RecordingSk()
    hook = federation_ingest(
        sk, from_fqid="jarvis@chef.skworld",
        peers_provider=lambda: ["chef@chef.skworld", "lumina@chef.skworld"],
        cot_peers_provider=lambda: ["lumina@chef.skworld"],  # chef has no CoT consumer
    )
    hook(parse_cot(PLI))
    recipients = {c["to_fqid"] for c in sk.calls}
    assert recipients == {"lumina@chef.skworld"}  # chef excluded from beacons

    sk.calls.clear()
    hook(parse_cot(GEOCHAT))  # durable: full peer set, chef included
    recipients = {c["to_fqid"] for c in sk.calls}
    assert recipients == {"chef@chef.skworld", "lumina@chef.skworld"}


# --------------------------------------------------------------------------
# _cot_peer_fqids: fail-closed CoT-capability gate
# --------------------------------------------------------------------------
def _peer(name, fqid, caps=None):
    return PeerInfo(
        name=name, fqid=fqid,
        capabilities=list(caps or []),
        transports=[PeerTransport(
            transport="https-s2s",
            settings={"inbox_url": f"https://{name}.example/api/v1/inbox"},
        )],
    )


def _patch_peers(monkeypatch, peers):
    class _FakeStore:
        def __init__(self, *a, **kw):
            pass

        def list_all(self):
            return peers

    monkeypatch.setattr(discovery_mod, "PeerStore", _FakeStore)


def test_cot_gate_default_empty_excludes_all(monkeypatch):
    """No advertised capability + no allowlist -> nobody gets beacons."""
    monkeypatch.delenv("SKCOMMS_COT_PEERS", raising=False)
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),
        _peer("lumina", "lumina@chef.skworld"),
    ])
    assert _cot_peer_fqids() == []


def test_cot_gate_includes_capability_peer_excludes_others(monkeypatch):
    monkeypatch.delenv("SKCOMMS_COT_PEERS", raising=False)
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),                       # human, no CoT
        _peer("atak", "atak@chef.skworld", caps=["cot"]),         # advertises CoT
        _peer("wintak", "wintak@chef.skworld", caps=["TAK"]),     # advertises TAK (any case)
    ])
    assert set(_cot_peer_fqids()) == {"atak@chef.skworld", "wintak@chef.skworld"}


def test_cot_gate_env_allowlist(monkeypatch):
    monkeypatch.setenv("SKCOMMS_COT_PEERS", "lumina@chef.skworld , opus@chef.skworld")
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),
        _peer("lumina", "lumina@chef.skworld"),
    ])
    assert _cot_peer_fqids() == ["lumina@chef.skworld"]  # only the reachable, allowlisted peer


# --------------------------------------------------------------------------
# Wire round-trip: envelope_v1_to_message restores short ttl + no ack
# --------------------------------------------------------------------------
def test_receiver_restores_short_ttl_and_no_ack():
    env = Envelope(
        from_fqid="jarvis@chef.skworld", to_fqid="lumina@chef.skworld",
        content_type="application/cot+xml", body="<event/>",
        headers={WIRE_HEADER_TTL: "120", WIRE_HEADER_ACK_REQUESTED: "0"},
    )
    msg = envelope_v1_to_message(env)
    assert msg.routing.ttl == 120
    assert msg.routing.ack_requested is False


def test_receiver_keeps_durable_defaults_without_headers():
    env = Envelope(
        from_fqid="jarvis@chef.skworld", to_fqid="lumina@chef.skworld",
        body="hello",
    )
    msg = envelope_v1_to_message(env)
    assert msg.routing.ttl == 86400          # historical durable default preserved
    assert msg.routing.ack_requested is True


# --------------------------------------------------------------------------
# send_federated stamps ttl / ack overrides onto the Envelope v1 wire headers
# --------------------------------------------------------------------------
def _fail_comm(monkeypatch, tmp_path):
    """SKComms whose only rail fails, so send_federated enqueues to a tmp outbox."""
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm, HashAlgorithm, KeyFlags,
        PubKeyAlgorithm, SymmetricKeyAlgorithm,
    )

    from skcomms import identity as identity_mod
    from skcomms.core import SKComms
    from skcomms.crypto import EnvelopeCrypto
    from skcomms.outbox import PersistentOutbox
    from skcomms.router import Router
    from skcomms.transport import (
        HealthStatus, SendResult, Transport, TransportCategory, TransportStatus,
    )

    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    k.add_uid(pgpy.PGPUID.new("jarvis <jarvis@chef.skworld>"),
              usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
              hashes=[HashAlgorithm.SHA256], ciphers=[SymmetricKeyAlgorithm.AES256],
              compression=[CompressionAlgorithm.ZLIB])
    priv, fp = str(k), str(k.fingerprint).replace(" ", "")
    monkeypatch.setattr(identity_mod, "resolve_self_identity",
                        lambda *a, **kw: {"agent": "jarvis", "fqid": "jarvis@chef.skworld",
                                          "fingerprint": fp})

    class FailTransport(Transport):
        name = "fail-rail"
        priority = 1
        category = TransportCategory.REALTIME

        def configure(self, c): pass
        def is_available(self): return True
        def send(self, envelope_bytes, recipient):
            return SendResult(success=False, transport_name=self.name,
                              envelope_id="", latency_ms=0.0, error="rail down")
        def receive(self): return []
        def health_check(self):
            return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)

    comm = SKComms(router=Router(transports=[FailTransport()]),
                   crypto=EnvelopeCrypto(priv, "", fp))
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path, router=comm._router)
    return comm


def _pending_envelope(comm):
    from skcomms.envelope import SignedEnvelope
    pending = comm._outbox.list_pending()
    assert len(pending) == 1
    return SignedEnvelope.from_bytes(pending[0].envelope_json.encode("utf-8")).envelope


def test_send_federated_stamps_ttl_and_ack_headers(monkeypatch, tmp_path):
    comm = _fail_comm(monkeypatch, tmp_path)
    comm.send_federated(
        "lumina@chef.skworld", "<event/>",
        content_type="application/cot+xml",
        supersede_key="cot-beacon:lumina@chef.skworld:ANDROID-1",
        ttl=120, ack_requested=False,
    )
    env = _pending_envelope(comm)
    assert env.headers.get(WIRE_HEADER_TTL) == "120"
    assert env.headers.get(WIRE_HEADER_ACK_REQUESTED) == "0"


def test_send_federated_no_overrides_leaves_headers_empty(monkeypatch, tmp_path):
    """Backward-compatible: a plain federation send stamps no ttl/ack headers."""
    comm = _fail_comm(monkeypatch, tmp_path)
    comm.send_federated("lumina@chef.skworld", "hi")
    env = _pending_envelope(comm)
    assert WIRE_HEADER_TTL not in env.headers
    assert WIRE_HEADER_ACK_REQUESTED not in env.headers
