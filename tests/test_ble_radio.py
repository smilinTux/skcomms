import asyncio

import pytest

from skcomms.transports.ble.radio import FakeMedium, FakeRadio


@pytest.mark.asyncio
async def test_direct_neighbors_receive_broadcast():
    medium = FakeMedium()
    a = FakeRadio("a", medium)
    b = FakeRadio("b", medium)
    medium.link("a", "b")  # a and b can hear each other

    got: list[bytes] = []
    b.on_receive(lambda data, src: got.append(data))
    await a.start()
    await b.start()

    await a.broadcast(b"ping")
    await asyncio.sleep(0.01)
    assert got == [b"ping"]


@pytest.mark.asyncio
async def test_non_neighbors_do_not_hear_directly():
    medium = FakeMedium()
    a = FakeRadio("a", medium)
    c = FakeRadio("c", medium)
    # no link between a and c
    got: list[bytes] = []
    c.on_receive(lambda data, src: got.append(data))
    await a.start()
    await c.start()
    await a.broadcast(b"ping")
    await asyncio.sleep(0.01)
    assert got == []


@pytest.mark.asyncio
async def test_source_id_is_passed_to_callback():
    medium = FakeMedium()
    a = FakeRadio("a", medium)
    b = FakeRadio("b", medium)
    medium.link("a", "b")
    seen = []
    b.on_receive(lambda data, src: seen.append(src))
    await a.start()
    await b.start()
    await a.broadcast(b"x")
    await asyncio.sleep(0.01)
    assert seen == ["a"]
