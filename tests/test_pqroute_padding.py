"""RFC-0001 P2×P3 — padding ladder composed into the gated pqroute path.

The transport-level pqroute wrapper (:mod:`skcomms.pqroute_transport`) seals the
sensitive routing metadata + the signed envelope into a hybrid-KEM INNER blob.
On its own that still leaks the *length* of the body (an AEAD ciphertext is the
same length as its plaintext), which fingerprints content for a passive observer.

These tests assert the **additive** composition of the P2 size-class padding
ladder (:mod:`skcomms.padding`) UNDER the pqroute seal:

    * when the pqroute path is taken, the body is length-normalised to a coarse
      bucket *before* sealing, so two different small bodies produce an
      identical on-wire length (the size-hiding property) and still round-trip;
    * the OFF / classical path is byte-for-byte unchanged (no padding, no magic);
    * an escape hatch (``pad=False``) keeps the un-padded wrapped behaviour for
      callers / legacy blobs that do not want length normalisation.

These tests REQUIRE the liboqs hybrid KEM; they skip if it is unavailable.
"""

from __future__ import annotations

import pytest

pqkem = pytest.importorskip("skcomms.pqkem")
pqrt = pytest.importorskip("skcomms.pqroute_transport")

if not pqkem.is_available():
    pytest.skip("liboqs/oqs backend unavailable", allow_module_level=True)

from skcomms.envelope import Envelope, SignedEnvelope  # noqa: E402
from skcomms.padding import PAD_LADDER, PAD_SUITE  # noqa: E402
from skcomms.pqroute_transport import (  # noqa: E402
    PQROUTE_ENV,
    is_pqrouted,
    unwrap_signed,
    wrap_signed,
)


def _keypair():
    kp = pqkem.hybrid_keypair()
    return kp.public_key, kp.private_key


def _signed(to_fqid="bob@chef.skworld", body="x") -> SignedEnvelope:
    env = Envelope(from_fqid="alice@chef.skworld", to_fqid=to_fqid, body=body)
    return SignedEnvelope(envelope=env, signature="sig", signer_fingerprint="FP")


# ---------------------------------------------------------------------------
# Padding is composed UNDER the seal by default in the wrapped path
# ---------------------------------------------------------------------------


def test_wrapped_body_is_length_normalised_to_a_bucket():
    """Two different small bodies (same metadata) -> identical wire length.

    Without padding the wire length tracks the body length (an AEAD ciphertext
    is the size of its plaintext). With the ladder composed under the seal, both
    bodies land in the same coarse bucket and the wire lengths are equal — the
    size-hiding property, end to end.
    """
    pub, _ = _keypair()
    short = _signed(to_fqid="bob@chef.skworld", body="hi")
    longer = _signed(to_fqid="bob@chef.skworld", body="a" * 1000)
    # sanity: the un-padded envelope bytes differ a lot in length
    assert abs(len(longer.to_bytes()) - len(short.to_bytes())) > 500

    w_short = wrap_signed(short, dest_hybrid_pub=pub, next_hop="r", enabled=True)
    w_long = wrap_signed(longer, dest_hybrid_pub=pub, next_hop="r", enabled=True)
    assert is_pqrouted(w_short) and is_pqrouted(w_long)
    # both bodies sit inside the first ladder bucket -> identical on-wire length
    assert len(w_short) == len(w_long)


def test_wrapped_padded_roundtrips_and_records_suite():
    """Padding under the seal still recovers the exact signed envelope, and the
    sealed inner metadata advertises the pad suite (self-describing)."""
    pub, priv = _keypair()
    signed = _signed(to_fqid="bob@chef.skworld", body="sensitive body")
    wire = wrap_signed(
        signed, dest_hybrid_pub=pub, next_hop="relay-1", enabled=True,
        flags=["urgent"],
    )
    inner_meta, recovered = unwrap_signed(wire, priv)
    assert recovered.to_bytes() == signed.to_bytes()
    assert inner_meta["final_dest"] == "bob@chef.skworld"
    assert inner_meta["flags"] == ["urgent"]
    # self-describing: the inner advertises that the content was padded
    assert inner_meta["pad"] == PAD_SUITE


def test_oversize_body_pads_to_next_bucket_multiple_and_roundtrips():
    """A body larger than the first bucket pads up to the next ladder rung and
    still round-trips byte-for-byte."""
    pub, priv = _keypair()
    big_body = "Z" * (PAD_LADDER[0] + 5_000)  # > first bucket
    signed = _signed(to_fqid="bob@chef.skworld", body=big_body)
    wire = wrap_signed(signed, dest_hybrid_pub=pub, next_hop="r", enabled=True)
    _meta, recovered = unwrap_signed(wire, priv)
    assert recovered.to_bytes() == signed.to_bytes()


# ---------------------------------------------------------------------------
# OFF path byte-identical; pad=False escape hatch keeps un-padded wrap
# ---------------------------------------------------------------------------


def test_off_path_unchanged_no_padding(monkeypatch):
    monkeypatch.delenv(PQROUTE_ENV, raising=False)
    pub, _ = _keypair()
    signed = _signed(body="body")
    wire = wrap_signed(signed, dest_hybrid_pub=pub, next_hop="r", enabled=False)
    assert wire == signed.to_bytes()  # no padding, no magic, nothing new
    assert not is_pqrouted(wire)


def test_pad_false_escape_hatch_does_not_normalise():
    """``pad=False`` keeps the un-padded wrapped behaviour: different body sizes
    yield different wire lengths, and the inner records no pad suite."""
    pub, priv = _keypair()
    short = _signed(body="hi")
    longer = _signed(body="a" * 1000)
    w_short = wrap_signed(short, dest_hybrid_pub=pub, next_hop="r",
                          enabled=True, pad=False)
    w_long = wrap_signed(longer, dest_hybrid_pub=pub, next_hop="r",
                         enabled=True, pad=False)
    assert len(w_short) != len(w_long)
    inner_meta, recovered = unwrap_signed(w_short, priv)
    assert recovered.to_bytes() == short.to_bytes()
    assert "pad" not in inner_meta


# ---------------------------------------------------------------------------
# Router-level gated send/recv integration (route_signed) with padding
# ---------------------------------------------------------------------------


class _FakeTransport:
    """Minimal transport double capturing (recipient, wire) sent."""

    def __init__(self, name="https-s2s", priority=1):
        from skcomms.transport import TransportCategory

        self.name = name
        self.priority = priority
        self.category = TransportCategory.REALTIME
        self.sent: list[tuple[str, bytes]] = []

    def configure(self, config):
        pass

    def is_available(self):
        return True

    def send(self, envelope_bytes, recipient):
        from skcomms.transport import SendResult

        self.sent.append((recipient, envelope_bytes))
        return SendResult(success=True, transport_name=self.name,
                          envelope_id="", latency_ms=0.0)

    def receive(self):
        return []

    def health_check(self):
        from skcomms.transport import HealthStatus, TransportStatus

        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


@pytest.fixture
def _isolate_retry_queue(tmp_path, monkeypatch):
    from skcomms import router as router_mod

    monkeypatch.setattr(router_mod, "RETRY_QUEUE_PATH", tmp_path / "rq.jsonl", raising=True)
    yield


def test_router_route_signed_off_path_byte_identical(monkeypatch, _isolate_retry_queue):
    """Gate OFF -> route_signed emits verbatim signed bytes (no padding, no
    magic), addressed by the inner to_fqid. The classical path is unchanged."""
    monkeypatch.delenv(PQROUTE_ENV, raising=False)
    from skcomms.router import Router

    t = _FakeTransport()
    signed = _signed(to_fqid="bob@chef.skworld", body="hello")
    report = Router(transports=[t]).route_signed(signed)
    assert report.delivered is True
    recipient, wire = t.sent[0]
    assert recipient == "bob@chef.skworld"
    assert wire == signed.to_bytes()
    assert not is_pqrouted(wire)


def test_router_route_signed_pqroute_pads_and_recovers(_isolate_retry_queue):
    """Gate ON through the router: two different-length bodies are length-hidden
    to the same on-wire size, addressed only to the relay, and the destination
    recovers the exact signed envelope."""
    from skcomms.router import Router

    pub, priv = _keypair()
    short = _signed(to_fqid="SECRET-bob@chef.skworld", body="hi")
    longer = _signed(to_fqid="SECRET-bob@chef.skworld", body="a" * 1000)

    t1, t2 = _FakeTransport(), _FakeTransport()
    Router(transports=[t1]).route_signed(
        short, pqroute=True, dest_hybrid_pub=pub, next_hop="relay-1.skworld.io",
    )
    Router(transports=[t2]).route_signed(
        longer, pqroute=True, dest_hybrid_pub=pub, next_hop="relay-1.skworld.io",
    )
    (r1, w1), (r2, w2) = t1.sent[0], t2.sent[0]

    # relay-only addressing; final destination + body never on the wire
    assert r1 == r2 == "relay-1.skworld.io"
    assert b"SECRET-bob" not in w1 and b"SECRET-bob" not in w2
    assert is_pqrouted(w1) and is_pqrouted(w2)
    # padding under the seal -> identical on-wire length (size-hiding)
    assert len(w1) == len(w2)

    # destination recovers the exact signed envelope
    _meta, recovered = unwrap_signed(w1, priv)
    assert recovered.to_bytes() == short.to_bytes()


def test_router_route_signed_pqroute_pad_false(_isolate_retry_queue):
    """``pqroute_pad=False`` keeps the un-padded wrapped form (different body
    sizes -> different wire lengths) but still seals + relay-routes."""
    from skcomms.router import Router

    pub, _ = _keypair()
    short = _signed(body="hi")
    longer = _signed(body="a" * 1000)
    t1, t2 = _FakeTransport(), _FakeTransport()
    Router(transports=[t1]).route_signed(
        short, pqroute=True, dest_hybrid_pub=pub, next_hop="r", pqroute_pad=False,
    )
    Router(transports=[t2]).route_signed(
        longer, pqroute=True, dest_hybrid_pub=pub, next_hop="r", pqroute_pad=False,
    )
    assert is_pqrouted(t1.sent[0][1]) and is_pqrouted(t2.sent[0][1])
    assert len(t1.sent[0][1]) != len(t2.sent[0][1])
