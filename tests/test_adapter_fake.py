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


@pytest.mark.asyncio
async def test_fake_default_adapter_name_when_no_config():
    a = FakeAdapter()
    assert a.adapter_name == "fake"


@pytest.mark.asyncio
async def test_fake_bind_then_resolve_fqid_roundtrip():
    from skcomms.adapters.models import ChannelType, PlatformIdentity

    a = FakeAdapter(config={"adapter_name": "fake-1"})
    pid = PlatformIdentity(
        channel=ChannelType.CUSTOM,
        platform_id="user-42",
        platform_name="User 42",
        room_id="room-1",
    )
    # Unknown before binding.
    assert await a.resolve_fqid(pid) is None
    await a.bind_fqid(pid, "lumina@chef.skworld", "trusted")
    assert await a.resolve_fqid(pid) == "lumina@chef.skworld"


@pytest.mark.asyncio
async def test_fake_health_reports_queued_inbound_depth():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    await a.connect()
    a.inject(a.make_message("one"))
    a.inject(a.make_message("two"))
    h = await a.health()
    assert h.queued_outbound == 2  # two messages waiting on the inbound queue
    assert h.adapter_name == "fake-1"


@pytest.mark.asyncio
async def test_fake_reconnect_cycle():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    await a.connect()
    await a.disconnect()
    await a.connect()
    h = await a.health()
    assert h.connected is True


@pytest.mark.asyncio
async def test_fake_records_multiple_sends_in_order():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    await a.connect()
    await a.send(a.make_message("first"))
    await a.send(a.make_message("second"))
    assert [m.text for m in a.sent] == ["first", "second"]
