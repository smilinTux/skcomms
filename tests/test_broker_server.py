"""Broker server mounts the relay endpoint + relays signals end-to-end (live).

Spins the real FastAPI broker app with a TestClient WebSocket, connects two
peers in a room, and confirms a signal relays through it — the in-process analog
of the live validation (BrokerSignaling ↔ real signaling server)."""
import json

from fastapi.testclient import TestClient

from skcomms.transports.broker_server import app


def test_health():
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200 and r.json()["service"] == "signaling-broker"


def test_relays_signal_between_two_peers():
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
