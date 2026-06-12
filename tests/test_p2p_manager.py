"""P2PSessionManager: a home for long-lived P2P sessions + auto-answer.

Two managers over a shared signaling bus: one calls the other, the callee's
route loop auto-answers an incoming offer, a direct data channel opens, and they
exchange both ways. This is what skchat's initiate_call/accept_call drive.
"""
from collections import defaultdict

import pytest

from skcomms.transports.p2p_manager import P2PSessionManager


class _Bus:
    def __init__(self) -> None:
        self.inboxes: dict[str, list] = defaultdict(list)


class _FakeSignaling:
    def __init__(self, me: str, bus: _Bus) -> None:
        self.me, self.bus, self._n = me, bus, 0

    def send_signal(self, to_fqid: str, kind: str, payload: dict) -> dict:
        self._n += 1
        self.bus.inboxes[to_fqid].append(
            {"from_fqid": self.me, "kind": kind, "payload": payload, "id": f"{self.me}-{self._n}"}
        )
        return {"id": f"{self.me}-{self._n}"}

    def poll_signals(self) -> list:
        return list(self.bus.inboxes[self.me])


@pytest.mark.asyncio
async def test_manager_call_and_auto_answer():
    bus = _Bus()
    incoming: list = []
    opus = P2PSessionManager(
        signaling=_FakeSignaling("opus@chef.skworld", bus), poll_interval=0.1
    )
    lumina = P2PSessionManager(
        signaling=_FakeSignaling("lumina@chef.skworld", bus), poll_interval=0.1,
        on_session=lambda peer, s: incoming.append(peer),
    )
    try:
        await lumina.start()                       # lumina listening (auto-answer)
        sess_o = await opus.call("lumina@chef.skworld")   # opus dials
        sess_l_peer = "opus@chef.skworld"

        await sess_o.wait_open(timeout=20)
        # lumina auto-created an answering session for opus
        await _until(lambda: lumina.get(sess_l_peer) is not None, 20)
        sess_l = lumina.get(sess_l_peer)
        await sess_l.wait_open(timeout=20)

        sess_o.send("ping")
        assert await sess_l.recv(timeout=20) == "ping"
        sess_l.send("pong")
        assert await sess_o.recv(timeout=20) == "pong"

        assert "opus@chef.skworld" in incoming     # on_session fired for the incoming call
        assert "lumina@chef.skworld" in opus.active()
    finally:
        await opus.close()
        await lumina.close()


async def _until(pred, timeout):
    import asyncio
    end = timeout / 0.1
    i = 0
    while not pred() and i < end:
        await asyncio.sleep(0.1)
        i += 1
    assert pred(), "condition not met in time"
