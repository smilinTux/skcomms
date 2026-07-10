"""Broker server mounts the relay endpoint + relays signals end-to-end (live).

Spins the real FastAPI broker app with a TestClient WebSocket, connects two
peers in a room, and confirms a signal relays through it, the in-process analog
of the live validation (BrokerSignaling against a real signaling server).

Also covers the fail-closed identity contract (coord 8e57a48a):

- the deployable broker now REQUIRES auth by default; a tokenless client is
  closed with 4401 instead of silently authenticating as its claimed ``?peer=``,
- in an explicitly permissive broker WITHOUT the ``SKCOMMS_DEV_AUTH`` gate,
  anonymous peers get random ``anonymous-<hex>`` pseudo-ids; the
  client-controlled ``?peer=<fp>`` claim is never used as the room identity,
- the claimed-peer convenience survives only behind the explicit
  ``SKCOMMS_DEV_AUTH`` dev gate.
"""
import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import skcomms.transports.broker_server as broker_server
from skcomms.signaling import SignalingBroker
from skcomms.transports.broker_server import app

VICTIM_FP = "A" * 40


def test_health():
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200 and r.json()["service"] == "signaling-broker"


def test_default_broker_requires_auth():
    """SECURITY: a tokenless connection to the default broker must be
    rejected (4401), not authenticated as its claimed ?peer= fingerprint."""
    assert broker_server._require_auth is True
    c = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with c.websocket_connect(f"/webrtc/ws?room=r&peer={VICTIM_FP}") as ws:
            ws.receive_text()
    assert exc_info.value.code == 4401


def test_permissive_anonymous_cannot_claim_fingerprint(monkeypatch):
    """SECURITY: permissive mode WITHOUT SKCOMMS_DEV_AUTH must not honor the
    client-controlled ?peer= claim; anonymous peers get random pseudo-ids."""
    monkeypatch.delenv("SKCOMMS_DEV_AUTH", raising=False)
    monkeypatch.setattr(broker_server, "broker", SignalingBroker(require_auth=False))
    c = TestClient(app)
    room = "skcomms-test-room"
    with c.websocket_connect(f"/webrtc/ws?room={room}&peer={VICTIM_FP}") as wa:
        assert json.loads(wa.receive_text())["type"] == "welcome"
        with c.websocket_connect(f"/webrtc/ws?room={room}&peer={'B' * 40}") as wb:
            welcome = json.loads(wb.receive_text())
            assert welcome["type"] == "welcome"
            # The already-connected peer is a random pseudo-id, NOT the victim
            # fingerprint it claimed via the URL.
            assert len(welcome["peers"]) == 1
            (peer_a_id,) = welcome["peers"]
            assert peer_a_id != VICTIM_FP
            assert peer_a_id.startswith("anonymous-")
            # And the joiner announced to A is a pseudo-id too.
            joined = json.loads(wa.receive_text())
            assert joined["type"] == "peer_joined"
            assert joined["peer"] != "B" * 40
            assert joined["peer"].startswith("anonymous-")


def test_relays_signal_between_two_peers(monkeypatch):
    """Relay E2E. Claimed ?peer= identities require the explicit dev gate now."""
    monkeypatch.setenv("SKCOMMS_DEV_AUTH", "1")
    monkeypatch.setattr(broker_server, "broker", SignalingBroker(require_auth=False))
    c = TestClient(app)
    room = "skcomms-test-room"
    a_fp, b_fp = "A" * 40, "B" * 40
    with c.websocket_connect(f"/webrtc/ws?room={room}&peer={a_fp}") as wa, \
         c.websocket_connect(f"/webrtc/ws?room={room}&peer={b_fp}") as wb:
        # a sends a signal addressed to b
        wa.send_text(json.dumps({"type": "signal", "to": b_fp, "data": {"kind": "offer", "x": 1}}))
        # b receives frames (welcome/peer_joined first); loop until the signal arrives.
        got = None
        for _ in range(6):
            msg = json.loads(wb.receive_text())
            if msg.get("type") == "signal":
                got = msg
                break
        assert got is not None, "signal was not relayed"
        assert got["from"] == a_fp
        assert got["data"] == {"kind": "offer", "x": 1}
