"""BrokerSignaling adapter mechanics (against the documented broker wire format).

Tested with a mock websocket — proves send formats correctly, the reader maps
inbound signals fp->fqid, poll drains, and is_reachable tracks state. Live-broker
validation (connecting to the running signaling.py relay) is a follow-up.
"""
import asyncio
import json

import pytest

from skcomms.transports.signaling_base import SignalingChannel
from skcomms.transports.signaling_broker import BrokerSignaling

_FP = {"opus@chef.skworld": "OPUSFP", "lumina@chef.skworld": "LUMFP"}
_FQID = {v: k for k, v in _FP.items()}


class _MockWS:
    def __init__(self) -> None:
        self.sent: list = []
        self._inbox: asyncio.Queue = asyncio.Queue()

    async def send(self, text: str) -> None:
        self.sent.append(json.loads(text))

    async def recv(self) -> str:
        return await self._inbox.get()

    def inject(self, msg: dict) -> None:
        self._inbox.put_nowait(json.dumps(msg))


def _make(ws):
    return BrokerSignaling(
        ws=ws, fqid_to_fp=lambda f: _FP[f], fp_to_fqid=lambda fp: _FQID.get(fp, fp)
    )


def test_conforms_to_protocol():
    assert isinstance(_make(_MockWS()), SignalingChannel)


@pytest.mark.asyncio
async def test_send_formats_broker_message():
    ws = _MockWS()
    chan = _make(ws)
    await chan.send_signal("lumina@chef.skworld", "offer", {"sdp": "A"})
    assert ws.sent == [
        {"type": "signal", "to": "LUMFP", "data": {"kind": "offer", "payload": {"sdp": "A"}}}
    ]


@pytest.mark.asyncio
async def test_reader_maps_inbound_and_poll_drains():
    ws = _MockWS()
    chan = _make(ws)
    await chan.start()
    assert chan.is_reachable() is True
    ws.inject({"type": "signal", "from": "OPUSFP", "data": {"kind": "answer", "payload": {"sdp": "B"}}})
    ws.inject({"type": "peer_joined", "peer": "OPUSFP"})  # ignored

    async def _wait():
        for _ in range(50):
            sigs = chan.poll_signals()
            if sigs:
                return sigs
            await asyncio.sleep(0.02)
        return []

    sigs = await _wait()
    assert len(sigs) == 1
    assert sigs[0]["from_fqid"] == "opus@chef.skworld"
    assert sigs[0]["kind"] == "answer"
    assert sigs[0]["payload"] == {"sdp": "B"}
    # drained
    assert chan.poll_signals() == []
    await chan.close()
    assert chan.is_reachable() is False
