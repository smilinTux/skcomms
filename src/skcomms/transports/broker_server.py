"""Deployable WebRTC signaling broker server (sub-project B fast path).

Mounts the relay broker (:mod:`skcomms.signaling`) as a runnable WebSocket server so
the low-latency broker signaling path (``BrokerSignaling``) has a real endpoint. The
broker relays SDP/ICE between peers in a room; **no media passes through it**.

Run:
    uvicorn skcomms.transports.broker_server:app --host 0.0.0.0 --port 9384
    # or: python -m skcomms.transports.broker_server   (defaults to 127.0.0.1:9384)

Auth: by default the broker is anonymous (``SKCOMM_BROKER_REQUIRE_AUTH`` unset). Set
``SKCOMM_BROKER_REQUIRE_AUTH=1`` to require a CapAuth bearer token per connection.
The endpoint path is ``/webrtc/ws?room=<room>&peer=<fingerprint>`` — matching
``DEFAULT_SIGNALING_URL`` (``wss://localhost:9384/webrtc/ws``).
"""

from __future__ import annotations

import os

from fastapi import FastAPI, WebSocket

from ..signaling import SignalingBroker, signaling_ws_endpoint

_require_auth = os.getenv("SKCOMM_BROKER_REQUIRE_AUTH", "").lower() in ("1", "true", "yes")

app = FastAPI(title="skcomms-signaling-broker")
broker = SignalingBroker(require_auth=_require_auth)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "signaling-broker", "require_auth": _require_auth}


@app.websocket("/webrtc/ws")
async def webrtc_ws(ws: WebSocket, room: str, peer: str) -> None:
    await signaling_ws_endpoint(ws=ws, room=room, peer=peer, broker=broker)


def main() -> None:  # pragma: no cover - thin runner
    import uvicorn

    host = os.getenv("SKCOMM_BROKER_HOST", "127.0.0.1")
    port = int(os.getenv("SKCOMM_BROKER_PORT", "9384"))
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    main()
