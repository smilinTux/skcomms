"""Tests for Router.route_anon / Router.parse_anon_inbound — RFC-0001 P5.

Wires the no-identity anon-transport framing (:mod:`skcomms.anon_transport`)
into a real flag-gated send/recv PATH through the router:

    * ``route_anon`` — frame a payload for an ``aqid:`` address + hand the opaque
      wire frame to the transport, addressed to the relay (no identity on the
      wire). Flag-gated: OFF raises ``AnonDisabledError`` and emits nothing.
    * ``parse_anon_inbound`` — parse + deniably-authenticate an inbound frame.

Additive guarantee: with anon OFF the classical / sovereign / pqroute paths are
byte-identical (this is a brand-new method that does not touch them).
"""

from __future__ import annotations

import pytest

from skcomms import router as router_mod
from skcomms.anon_transport import (
    AnonAuthError,
    AnonChannel,
    AnonDisabledError,
    is_anon_frame,
)
from skcomms.envelope import Envelope, SignedEnvelope
from skcomms.router import Router
from skcomms.transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

SECRET = b"q" * 32
OTHER_SECRET = b"z" * 32
RELAY = "relay.skworld.io:7447"


class FakeTransport(Transport):
    def __init__(self, name, priority, log, *, succeed=True, available=True):
        self.name = name
        self.priority = priority
        self.category = TransportCategory.REALTIME
        self._log = log
        self._succeed = succeed
        self._available = available
        self.sent: list[tuple[str, bytes]] = []

    def configure(self, config):
        pass

    def is_available(self):
        return self._available

    def send(self, envelope_bytes, recipient):
        self._log.append(self.name)
        self.sent.append((recipient, envelope_bytes))
        return SendResult(
            success=self._succeed,
            transport_name=self.name,
            envelope_id="",
            latency_ms=0.0,
            error=None if self._succeed else "forced",
        )

    def receive(self):
        return []

    def health_check(self):
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


@pytest.fixture(autouse=True)
def isolate_retry_queue(tmp_path, monkeypatch):
    monkeypatch.setattr(router_mod, "RETRY_QUEUE_PATH", tmp_path / "rq.jsonl", raising=True)
    yield


@pytest.fixture(autouse=True)
def anon_env_off(monkeypatch):
    # Default OFF unless a test opts in.
    monkeypatch.delenv("SKCOMMS_ANON", raising=False)
    yield


# ---------------------------------------------------------------------------
# Gate OFF: emits nothing, classical path byte-identical
# ---------------------------------------------------------------------------


def test_route_anon_gate_off_raises_and_emits_nothing():
    log: list[str] = []
    t = FakeTransport("nostr", 1, log)
    r = Router(transports=[t])
    chan = AnonChannel.create(RELAY, SECRET)
    with pytest.raises(AnonDisabledError):
        r.route_anon(b"hello", chan.address, SECRET)  # no enabled=, env unset
    assert log == []          # nothing put on the wire
    assert t.sent == []


def test_route_signed_byte_identical_even_with_anon_env_on(monkeypatch):
    # Anon being globally enabled must NOT change the classical sovereign path.
    monkeypatch.setenv("SKCOMMS_ANON", "1")
    log: list[str] = []
    t = FakeTransport("https-s2s", 1, log)
    r = Router(transports=[t])
    env = Envelope(from_fqid="jarvis@chef.skworld", to_fqid="lumina@chef.skworld", body="hi")
    signed = SignedEnvelope(envelope=env, signature="sig", signer_fingerprint="FP")
    report = r.route_signed(signed)
    assert report.delivered is True
    recipient, wire = t.sent[0]
    assert recipient == "lumina@chef.skworld"
    assert wire == signed.to_bytes()            # verbatim — anon never leaks in


# ---------------------------------------------------------------------------
# Gate ON: framed + routed to relay, no identity on the wire, round-trips
# ---------------------------------------------------------------------------


def test_route_anon_frames_to_relay_no_identity():
    log: list[str] = []
    t = FakeTransport("nostr", 1, log)
    r = Router(transports=[t])
    chan = AnonChannel.create(RELAY, SECRET)
    report = r.route_anon(b"opaque-sealed-body", chan.address, SECRET, enabled=True)
    assert report.delivered is True
    assert log == ["nostr"]
    recipient, wire = t.sent[0]
    assert recipient == RELAY                    # routed to the relay, not an fqid
    assert is_anon_frame(wire)                    # an anon frame on the wire
    # No identity material as a wire FIELD: the only relay-readable routing token
    # is the opaque 16-byte sender_id (structural — random tag/body bytes may of
    # course coincidentally contain any byte value).
    assert chan.sender_id in wire                 # relay routes on the opaque id
    from skcomms.anon_transport import read_sender_id
    assert read_sender_id(wire) == chan.sender_id


def test_route_anon_env_gate_on(monkeypatch):
    monkeypatch.setenv("SKCOMMS_ANON", "1")
    log: list[str] = []
    t = FakeTransport("nostr", 1, log)
    r = Router(transports=[t])
    chan = AnonChannel.create(RELAY, SECRET)
    report = r.route_anon(b"x", chan.address, SECRET)   # gated ON via env only
    assert report.delivered is True
    assert log == ["nostr"]


def test_route_anon_roundtrip_through_router():
    log: list[str] = []
    t = FakeTransport("nostr", 1, log)
    r = Router(transports=[t])
    chan = AnonChannel.create(RELAY, SECRET)            # recipient mints the queue
    payload = b"already-pqdm-sealed-ciphertext"         # confidentiality composed upstream
    r.route_anon(payload, chan.address, SECRET, enabled=True)
    _recipient, wire = t.sent[0]
    # Recipient side parses + deniably-authenticates the inbound frame.
    frame = r.parse_anon_inbound(wire, SECRET, expected_sender_id=chan.sender_id)
    assert frame.payload == payload
    assert frame.sender_id == chan.sender_id


def test_route_anon_honors_preferred_rail_order():
    log: list[str] = []
    a = FakeTransport("https-s2s", 1, log)
    b = FakeTransport("nostr", 2, log)
    r = Router(transports=[a, b])
    chan = AnonChannel.create(RELAY, SECRET)
    r.route_anon(b"x", chan.address, SECRET, enabled=True,
                 preferred_transports=["nostr", "https-s2s"])
    assert log[0] == "nostr"


# ---------------------------------------------------------------------------
# Deniable-auth reject
# ---------------------------------------------------------------------------


def test_parse_anon_inbound_wrong_secret_rejected():
    log: list[str] = []
    t = FakeTransport("nostr", 1, log)
    r = Router(transports=[t])
    chan = AnonChannel.create(RELAY, SECRET)
    r.route_anon(b"secret-body", chan.address, SECRET, enabled=True)
    _recipient, wire = t.sent[0]
    with pytest.raises(AnonAuthError):
        r.parse_anon_inbound(wire, OTHER_SECRET, expected_sender_id=chan.sender_id)


def test_route_anon_is_anon_inbound_detection():
    log: list[str] = []
    t = FakeTransport("nostr", 1, log)
    r = Router(transports=[t])
    chan = AnonChannel.create(RELAY, SECRET)
    r.route_anon(b"x", chan.address, SECRET, enabled=True)
    _recipient, wire = t.sent[0]
    assert r.is_anon_inbound(wire) is True
    assert r.is_anon_inbound(b'{"envelope_id": "x"}') is False
