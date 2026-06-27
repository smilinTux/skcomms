"""PQC P3 wiring — transport-level pqroute1 wrapper (skcomms.pqroute_transport).

This layer wires the vetted ``skcomms.pqroute`` metadata-sealing envelope into
the outbound transport path as an **additive, flag-gated** wrapper:

    * Default OFF -> the wire bytes are EXACTLY ``SignedEnvelope.to_bytes()``
      today (byte-for-byte identical; nothing new on the wire).
    * Opt-in ON (``SKCOMMS_PQROUTE=1`` env, or a per-send ``enabled=True``) AND a
      destination hybrid prekey present -> the envelope's *sensitive* metadata
      (final destination FQID + flags) plus the whole signed envelope move into
      the hybrid-sealed INNER blob; only a minimal next-hop header
      (``{"to_relay": ..., "v": 1}``) stays outer/relay-readable.

The win over a classical relay layer: an intermediate relay learns only the
next hop — the FINAL destination + flags are hybrid-sealed (X25519 + ML-KEM-768),
confidential against a harvest-now-decrypt-later recorder if EITHER leg holds.

These tests REQUIRE the liboqs hybrid KEM; they skip if it is unavailable.
"""

from __future__ import annotations

import pytest

pqkem = pytest.importorskip("skcomms.pqkem")
pqrt = pytest.importorskip("skcomms.pqroute_transport")

if not pqkem.is_available():
    pytest.skip("liboqs/oqs backend unavailable", allow_module_level=True)

from skcomms.envelope import Envelope, SignedEnvelope  # noqa: E402
from skcomms.pqroute import PqRouteOpenError  # noqa: E402
from skcomms.pqroute_transport import (  # noqa: E402
    PQROUTE_ENV,
    is_pqrouted,
    pqroute_enabled,
    read_next_hop,
    unwrap_signed,
    wrap_signed,
)


def _keypair():
    kp = pqkem.hybrid_keypair()
    return kp.public_key, kp.private_key


def _signed(to_fqid="bob@chef.skworld", body="sensitive body bytes") -> SignedEnvelope:
    env = Envelope(from_fqid="alice@chef.skworld", to_fqid=to_fqid, body=body)
    return SignedEnvelope(envelope=env, signature="sig", signer_fingerprint="FP")


# ---------------------------------------------------------------------------
# Flag gate
# ---------------------------------------------------------------------------


def test_pqroute_enabled_default_off(monkeypatch):
    monkeypatch.delenv(PQROUTE_ENV, raising=False)
    assert pqroute_enabled() is False


def test_pqroute_enabled_env_on(monkeypatch):
    monkeypatch.setenv(PQROUTE_ENV, "1")
    assert pqroute_enabled() is True


def test_pqroute_enabled_override_wins(monkeypatch):
    monkeypatch.setenv(PQROUTE_ENV, "1")
    assert pqroute_enabled(override=False) is False
    monkeypatch.delenv(PQROUTE_ENV, raising=False)
    assert pqroute_enabled(override=True) is True


# ---------------------------------------------------------------------------
# Flag OFF -> byte-identical to today
# ---------------------------------------------------------------------------


def test_flag_off_byte_identical(monkeypatch):
    monkeypatch.delenv(PQROUTE_ENV, raising=False)
    pub, _ = _keypair()
    signed = _signed()
    wire = wrap_signed(signed, dest_hybrid_pub=pub, next_hop="relay-1", enabled=False)
    assert wire == signed.to_bytes()  # nothing new on the wire
    assert not is_pqrouted(wire)


def test_enabled_but_no_prekey_falls_back(monkeypatch):
    # Honest fallback: cannot hybrid-seal without a destination prekey, so the
    # classical (byte-identical) path is kept rather than silently downgrading.
    monkeypatch.setenv(PQROUTE_ENV, "1")
    signed = _signed()
    wire = wrap_signed(signed, dest_hybrid_pub=None, next_hop="relay-1")
    assert wire == signed.to_bytes()
    assert not is_pqrouted(wire)


# ---------------------------------------------------------------------------
# Flag ON -> routed seal/open roundtrip through the wrapper
# ---------------------------------------------------------------------------


def test_routed_roundtrip_through_wrapper():
    pub, priv = _keypair()
    signed = _signed(to_fqid="bob@chef.skworld", body="sensitive body bytes")
    wire = wrap_signed(
        signed, dest_hybrid_pub=pub, next_hop="relay-1.skworld.io",
        enabled=True, flags=["urgent", "e2e"],
    )
    assert is_pqrouted(wire)
    assert wire != signed.to_bytes()

    inner_meta, recovered = unwrap_signed(wire, priv)
    # the whole signed envelope is recovered byte-for-byte
    assert recovered.to_bytes() == signed.to_bytes()
    # the sensitive metadata is what was sealed inside
    assert inner_meta["final_dest"] == "bob@chef.skworld"
    assert inner_meta["flags"] == ["urgent", "e2e"]


# ---------------------------------------------------------------------------
# An intermediate relay reads ONLY the outer next-hop header
# ---------------------------------------------------------------------------


def test_relay_reads_only_next_hop():
    pub, priv = _keypair()
    signed = _signed(to_fqid="SECRET-bob@chef.skworld", body="SECRET-BODY")
    wire = wrap_signed(
        signed, dest_hybrid_pub=pub, next_hop="relay-1.skworld.io", enabled=True,
    )

    # Relay (blob, no dest key) reads the next hop to forward...
    hdr = read_next_hop(wire)
    assert hdr["to_relay"] == "relay-1.skworld.io"
    assert "final_dest" not in hdr

    # ...but the FINAL destination + body never appear in the wire plaintext.
    assert b"SECRET-bob" not in wire
    assert b"SECRET-BODY" not in wire
    assert b"final_dest" not in wire

    # ...and it has no key to open the inner.
    with pytest.raises(PqRouteOpenError):
        unwrap_signed(wire, bytes(len(priv)))


def test_wrong_key_cannot_unwrap():
    pub, _ = _keypair()
    _, other_priv = _keypair()
    wire = wrap_signed(_signed(), dest_hybrid_pub=pub, next_hop="r", enabled=True)
    with pytest.raises(PqRouteOpenError):
        unwrap_signed(wire, other_priv)


# ---------------------------------------------------------------------------
# Router integration — opt-in route_signed(pqroute=...) path
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


def test_router_route_signed_default_unchanged(monkeypatch, _isolate_retry_queue):
    """Flag OFF -> route_signed still puts verbatim signed bytes on the wire,
    addressed by the inner to_fqid (no regression)."""
    monkeypatch.delenv(PQROUTE_ENV, raising=False)
    from skcomms.router import Router

    t = _FakeTransport()
    signed = _signed(to_fqid="bob@chef.skworld")
    report = Router(transports=[t]).route_signed(signed)
    assert report.delivered is True
    recipient, wire = t.sent[0]
    assert recipient == "bob@chef.skworld"        # routed by inner to_fqid
    assert wire == signed.to_bytes()              # verbatim bytes


def test_router_route_signed_pqroute_seals_and_routes_to_next_hop(_isolate_retry_queue):
    """Flag ON + prekey + next_hop -> wire is sealed (final dest hidden) and the
    transport is addressed to the RELAY, not the final destination."""
    from skcomms.router import Router

    pub, priv = _keypair()
    t = _FakeTransport()
    signed = _signed(to_fqid="SECRET-bob@chef.skworld", body="SECRET-BODY")
    report = Router(transports=[t]).route_signed(
        signed, pqroute=True, dest_hybrid_pub=pub,
        next_hop="relay-1.skworld.io", pqroute_flags=["urgent"],
    )
    assert report.delivered is True
    recipient, wire = t.sent[0]
    # relay addressing only — final destination never on the wire
    assert recipient == "relay-1.skworld.io"
    assert b"SECRET-bob" not in wire
    assert b"SECRET-BODY" not in wire
    assert is_pqrouted(wire)
    assert read_next_hop(wire)["to_relay"] == "relay-1.skworld.io"
    # destination can recover everything
    inner_meta, recovered = unwrap_signed(wire, priv)
    assert recovered.to_bytes() == signed.to_bytes()
    assert inner_meta["final_dest"] == "SECRET-bob@chef.skworld"
    assert inner_meta["flags"] == ["urgent"]
