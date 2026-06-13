import asyncio

import pytest

from skcomms.transports.lora.interface import FakeLoRaInterface, FakeLoRaMedium


@pytest.mark.asyncio
async def test_two_nodes_exchange_a_frame():
    medium = FakeLoRaMedium()
    a = FakeLoRaInterface("node-a", medium)
    b = FakeLoRaInterface("node-b", medium)
    got = []
    b.on_receive(lambda data, src: got.append((data, src)))
    await a.start()
    await b.start()

    await a.send_frame(b"hello-lora", dest=None)  # broadcast
    await asyncio.sleep(0.01)
    assert got == [(b"hello-lora", "node-a")]


@pytest.mark.asyncio
async def test_airtime_is_accounted():
    medium = FakeLoRaMedium()
    a = FakeLoRaInterface("node-a", medium, airtime_budget_bytes=100)
    await a.start()
    assert a.airtime_used == 0
    await a.send_frame(b"x" * 40, dest=None)
    assert a.airtime_used == 40
    assert a.can_send(50) is True       # 40+50 <= 100
    assert a.can_send(70) is False      # 40+70 > 100


@pytest.mark.asyncio
async def test_directed_frame_only_reaches_dest():
    medium = FakeLoRaMedium()
    a = FakeLoRaInterface("node-a", medium)
    b = FakeLoRaInterface("node-b", medium)
    c = FakeLoRaInterface("node-c", medium)
    bgot, cgot = [], []
    b.on_receive(lambda d, s: bgot.append(d))
    c.on_receive(lambda d, s: cgot.append(d))
    await a.start()
    await b.start()
    await c.start()
    await a.send_frame(b"for-b", dest="node-b")
    await asyncio.sleep(0.01)
    assert bgot == [b"for-b"]
    assert cgot == []
