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
async def test_bytes_sent_is_accounted_as_telemetry():
    # The fake tracks raw bytes-sent telemetry only; it does NOT enforce a cap.
    # Duty-cycle enforcement now lives in the transport's AirtimeBudget (C1),
    # so the fake exposes no second cap (no can_send / airtime_budget).
    medium = FakeLoRaMedium()
    a = FakeLoRaInterface("node-a", medium)
    await a.start()
    assert a.bytes_sent == 0
    await a.send_frame(b"x" * 40, dest=None)
    assert a.bytes_sent == 40
    await a.send_frame(b"x" * 60, dest=None)
    assert a.bytes_sent == 100          # raw telemetry keeps accumulating
    assert not hasattr(a, "can_send")   # no second enforcement path
    assert not hasattr(a, "airtime_budget")


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
