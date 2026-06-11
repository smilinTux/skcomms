"""Glue test: P2PConnector drives a P2PSession over a polling signaling backend.

Two connectors (offerer + answerer) over a shared in-memory signaling bus open a
real direct data channel — proving the poll-loop + de-dup + offer/answer wiring
that ties MailboxSignaling to P2PSession (the live path is opus↔lumina over the
signed mailbox; crypto + session are proven separately).
"""
from collections import defaultdict

import pytest

from skcomms.transports.p2p_connector import P2PConnector


class _Bus:
    def __init__(self) -> None:
        self.inboxes: dict[str, list] = defaultdict(list)


class _FakeSignaling:
    """Minimal MailboxSignaling-shaped double over a shared bus.

    poll_signals returns the *cumulative* inbox (like read_inbox does), so the
    connector must de-dup by signal id — exactly the real-world condition.
    """

    def __init__(self, me: str, bus: _Bus) -> None:
        self.me = me
        self.bus = bus
        self._n = 0

    def send_signal(self, to_fqid: str, kind: str, payload: dict) -> dict:
        self._n += 1
        sid = f"{self.me}-{self._n}"
        self.bus.inboxes[to_fqid].append(
            {"from_fqid": self.me, "kind": kind, "payload": payload, "id": sid}
        )
        return {"id": sid}

    def poll_signals(self) -> list:
        return list(self.bus.inboxes[self.me])


@pytest.mark.asyncio
async def test_connectors_establish_data_channel_over_signaling():
    bus = _Bus()
    opus = P2PConnector(
        peer_fqid="lumina@chef.skworld",
        signaling=_FakeSignaling("opus@chef.skworld", bus),
        poll_interval=0.1,
    )
    lumina = P2PConnector(
        peer_fqid="opus@chef.skworld",
        signaling=_FakeSignaling("lumina@chef.skworld", bus),
        poll_interval=0.1,
    )
    try:
        await lumina.start(role="answer")   # poll-only, waits for the offer
        await opus.start(role="offer")      # creates channel + sends offer
        await opus.wait_open(timeout=20)
        await lumina.wait_open(timeout=20)

        opus.send("ping")
        assert await lumina.recv(timeout=20) == "ping"
        lumina.send("pong")
        assert await opus.recv(timeout=20) == "pong"
    finally:
        await opus.close()
        await lumina.close()
