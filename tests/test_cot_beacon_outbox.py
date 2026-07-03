"""Ephemeral CoT position-beacon outbox handling (coord b1633666).

CoT position beacons (atoms, ``a-*``) are continuously re-beaconed, so an
undelivered one has no value once superseded -- it must NOT accumulate in the
durable federation outbox. Durable CoT events (GeoChat / markers, ``b-*``) must
still be reliably queued + delivered. Covers, bottom-up:

  * ``is_ephemeral_beacon`` discriminates atoms (PLI) from bits (chat/markers);
  * ``PersistentOutbox`` supersede_key evicts older undelivered ephemeral
    entries for the same key, but never touches durable (keyless) entries;
  * ``SKComms.send_federated`` threads supersede_key -> outbox on delivery
    failure (ephemeral superseded; non-ephemeral persisted + retriable);
  * ``federation_ingest`` tags beacons with a per-(peer, entity) supersede_key
    and leaves durable events keyless.
"""

from __future__ import annotations

from skcomms.cot import is_ephemeral_beacon, parse_cot
from skcomms.cot_server import federation_ingest
from skcomms.envelope import Envelope, SignedEnvelope
from skcomms.outbox import PersistentOutbox

PLI = (  # a CoT atom -> ephemeral position beacon (PLI)
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
MARKER = (  # a CoT bit -> durable dropped marker
    '<event version="2.0" uid="marker-9f" type="b-m-p-s-m" how="h-e"'
    ' time="2026-06-22T03:02:00.000Z" start="2026-06-22T03:02:00.000Z"'
    ' stale="2026-06-23T03:02:00.000Z">'
    '<point lat="39.0" lon="-77.5" hae="100.0" ce="5.0" le="5.0"/>'
    '<detail><remarks>rally point</remarks></detail></event>'
)


def _signed(to_fqid: str = "lumina@chef.skworld", body: str = "x") -> SignedEnvelope:
    """A (fake-signed) SignedEnvelope; each call gets a fresh envelope id."""
    env = Envelope(from_fqid="jarvis@chef.skworld", to_fqid=to_fqid, body=body)
    return SignedEnvelope(envelope=env, signature="-----FAKE SIG-----")


# --------------------------------------------------------------------------
# is_ephemeral_beacon
# --------------------------------------------------------------------------
def test_is_ephemeral_beacon_atom_true():
    assert is_ephemeral_beacon(parse_cot(PLI)) is True


def test_is_ephemeral_beacon_bits_false():
    assert is_ephemeral_beacon(parse_cot(GEOCHAT)) is False
    assert is_ephemeral_beacon(parse_cot(MARKER)) is False


# --------------------------------------------------------------------------
# PersistentOutbox supersede semantics
# --------------------------------------------------------------------------
def test_ephemeral_beacon_does_not_accumulate(tmp_path):
    """Re-beaconing the same entity keeps the outbox bounded at one entry."""
    ob = PersistentOutbox(outbox_dir=tmp_path)
    key = "cot-beacon:lumina@chef.skworld:ANDROID-1"
    for i in range(5):
        ob.enqueue_signed(_signed(body=f"pos-{i}"), error="all rails down", supersede_key=key)
    assert ob.pending_count == 1  # only the latest survives; no bloat


def test_superseding_beacon_evicts_older(tmp_path):
    """A newer beacon replaces the older undelivered one for the same key."""
    ob = PersistentOutbox(outbox_dir=tmp_path)
    key = "cot-beacon:lumina@chef.skworld:ANDROID-1"
    first = ob.enqueue_signed(_signed(body="pos-1"), error="down", supersede_key=key)
    second = ob.enqueue_signed(_signed(body="pos-2"), error="down", supersede_key=key)
    pending = ob.list_pending()
    assert len(pending) == 1
    assert pending[0].envelope_id == second.envelope_id       # newest retained
    assert not (tmp_path / "pending" / f"{first.envelope_id}.json").exists()  # older evicted


def test_distinct_keys_coexist(tmp_path):
    """Per-(peer, entity) scoping: different peers/entities never evict each other."""
    ob = PersistentOutbox(outbox_dir=tmp_path)
    ob.enqueue_signed(_signed(), error="d", supersede_key="cot-beacon:lumina@x:A")
    ob.enqueue_signed(_signed(), error="d", supersede_key="cot-beacon:opus@x:A")   # other peer
    ob.enqueue_signed(_signed(), error="d", supersede_key="cot-beacon:lumina@x:B")  # other entity
    assert ob.pending_count == 3


def test_durable_events_never_superseded(tmp_path):
    """Keyless (durable) entries are reliable: never evicted, even by beacons."""
    ob = PersistentOutbox(outbox_dir=tmp_path)
    ob.enqueue_signed(_signed(body="chat-1"), error="d")   # no supersede_key -> durable
    ob.enqueue_signed(_signed(body="chat-2"), error="d")
    ob.enqueue_signed(_signed(), error="d", supersede_key="cot-beacon:lumina@x:A")  # ephemeral
    assert ob.pending_count == 3  # both durable events preserved + the beacon


# --------------------------------------------------------------------------
# SKComms.send_federated -> outbox threading (delivery-failure path)
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
    # Redirect the outbox to a throwaway dir -- never touch the real outbox.
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path, router=comm._router)
    return comm


def test_send_federated_beacon_supersedes_in_outbox(monkeypatch, tmp_path):
    """Repeated undelivered beacons for one entity keep the outbox at size 1."""
    comm = _fail_comm(monkeypatch, tmp_path)
    key = "cot-beacon:lumina@chef.skworld:ANDROID-1"
    for i in range(4):
        rep = comm.send_federated("lumina@chef.skworld", f"<event>pos-{i}</event>",
                                  content_type="application/cot+xml", supersede_key=key)
        assert rep.delivered is False   # rail down -> queued
    assert comm._outbox.pending_count == 1


def test_send_federated_durable_event_accumulates(monkeypatch, tmp_path):
    """Non-ephemeral CoT events (no supersede_key) are each reliably queued."""
    comm = _fail_comm(monkeypatch, tmp_path)
    for i in range(3):
        comm.send_federated("lumina@chef.skworld", f"<event>chat-{i}</event>",
                            content_type="application/cot+xml")  # durable: no key
    assert comm._outbox.pending_count == 3


# --------------------------------------------------------------------------
# federation_ingest hook: beacon -> ephemeral key, durable event -> keyless
# --------------------------------------------------------------------------
class _RecordingSk:
    def __init__(self):
        self.calls = []

    def send_federated(self, to_fqid, message, *, content_type="text/plain",
                       supersede_key=None, **kw):
        self.calls.append((to_fqid, supersede_key))


def test_hook_tags_beacon_with_per_peer_key():
    sk = _RecordingSk()
    hook = federation_ingest(sk, from_fqid="jarvis@chef.skworld",
                             peers_provider=lambda: ["lumina@chef.skworld", "opus@chef.skworld"])
    hook(parse_cot(PLI))
    keys = {peer: key for peer, key in sk.calls}
    assert keys["lumina@chef.skworld"] == "cot-beacon:lumina@chef.skworld:ANDROID-1"
    assert keys["opus@chef.skworld"] == "cot-beacon:opus@chef.skworld:ANDROID-1"


def test_hook_leaves_durable_event_keyless():
    sk = _RecordingSk()
    hook = federation_ingest(sk, from_fqid="jarvis@chef.skworld",
                             peers_provider=lambda: ["lumina@chef.skworld"])
    hook(parse_cot(GEOCHAT))
    assert sk.calls == [("lumina@chef.skworld", None)]  # durable: no supersede_key
