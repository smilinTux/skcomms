import pytest

from skcomms.adapters.fake import FakeAdapter


@pytest.mark.asyncio
async def test_fake_connects_and_reports_healthy():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    assert a.adapter_name == "fake-1"
    await a.connect()
    h = await a.health()
    assert h.connected is True
    await a.disconnect()
    h2 = await a.health()
    assert h2.connected is False


@pytest.mark.asyncio
async def test_fake_send_returns_id_and_records():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    await a.connect()
    mid = await a.send(a.make_message("hello"))
    assert isinstance(mid, str) and mid
    assert a.sent and a.sent[-1] is not None


@pytest.mark.asyncio
async def test_fake_inbound_yields_injected_messages():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    await a.connect()
    a.inject(a.make_message("ping"))
    got = []
    async for m in a.inbound():
        got.append(m)
        break
    assert got
