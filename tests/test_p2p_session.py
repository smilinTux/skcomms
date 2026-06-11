"""Integration test for the P2P data-channel session (sub-project B).

Two in-process P2PSessions negotiate over an in-memory signaling shim, open a
direct WebRTC data channel (aiortc, host candidates on localhost — no SFU, no
broker), and exchange messages both directions. This is the sovereign P2P link
that seeds the agent-native-comms-language north star.
"""
import asyncio

import pytest

from skcomms.transports.p2p_session import P2PSession


@pytest.mark.asyncio
async def test_two_peers_open_data_channel_and_exchange():
    sessions: dict[str, P2PSession] = {}

    def make_send(target_key: str):
        async def _send(kind: str, payload: dict) -> None:
            # deliver the signal straight to the peer session (in-memory shim)
            await sessions[target_key].handle_signal(kind, payload)
        return _send

    a = P2PSession(send_signal=None)
    b = P2PSession(send_signal=None)
    sessions["a"], sessions["b"] = a, b
    a._send_signal = make_send("b")
    b._send_signal = make_send("a")

    try:
        # a is the offerer; the offer→answer chain runs through handle_signal
        await a.call()

        # both data channels open once ICE/DTLS settles
        await a.wait_open(timeout=20)
        await b.wait_open(timeout=20)

        # exchange both directions
        a.send("hello-from-a")
        assert await b.recv(timeout=20) == "hello-from-a"
        b.send("hi-from-b")
        assert await a.recv(timeout=20) == "hi-from-b"
    finally:
        await a.close()
        await b.close()


@pytest.mark.asyncio
async def test_send_before_open_raises():
    s = P2PSession(send_signal=None)
    with pytest.raises(RuntimeError):
        s.send("nope")
    await s.close()
