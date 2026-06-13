import asyncio

import pytest

from skcomms.transports.ble.identity import MeshIdentity
from skcomms.transports.lora import framing
from skcomms.transports.lora.interface import FakeLoRaInterface, FakeLoRaMedium
from skcomms.transports.lora.store import AirtimeBudget
from skcomms.transports.lora.transport import LoRaTransport


def _transport(fqid, iface):
    return LoRaTransport(identity=MeshIdentity.generate(fqid), interface=iface)


class _SendTracker:
    """Wraps an iface's send_frame to record every frame that reaches the bus."""

    def __init__(self, iface):
        self.iface = iface
        self.frames: list[bytes] = []
        self._orig = iface.send_frame

        async def _wrapped(data, *, dest):
            self.frames.append(data)
            await self._orig(data, dest=dest)

        iface.send_frame = _wrapped


@pytest.mark.asyncio
async def test_envelope_round_trips_between_two_nodes():
    medium = FakeLoRaMedium()
    ia = FakeLoRaInterface("node-a", medium)
    ib = FakeLoRaInterface("node-b", medium)
    a = _transport("a@x.y", ia)
    b = _transport("b@x.y", ib)
    await a.start()
    await b.start()

    await a.send_async(b"sovereign-message-over-lora", recipient="b@x.y")
    await asyncio.sleep(0.05)

    got = b.receive()
    assert b"sovereign-message-over-lora" in got


@pytest.mark.asyncio
async def test_large_envelope_fragments_and_reassembles():
    medium = FakeLoRaMedium()
    ia = FakeLoRaInterface("node-a", medium)
    ib = FakeLoRaInterface("node-b", medium)
    a = _transport("a@x.y", ia)
    b = _transport("b@x.y", ib)
    await a.start()
    await b.start()
    payload = bytes(range(256)) * 3  # 768 bytes -> multi-frame
    await a.send_async(payload, recipient="b@x.y")
    await asyncio.sleep(0.05)
    assert payload in b.receive()


def test_transport_metadata():
    from skcomms.transport import TransportCategory
    t = _transport("a@x.y", None)
    assert t.name == "lora"
    assert t.category == TransportCategory.OFFLINE


@pytest.mark.asyncio
async def test_send_enforces_airtime_budget_on_send_path():
    # An over-budget multi-frame message must transmit only the frames that fit
    # the current window; the rest stay pending until the window rolls + flush.
    medium = FakeLoRaMedium()
    ia = FakeLoRaInterface("node-a", medium)
    ib = FakeLoRaInterface("node-b", medium)
    track = _SendTracker(ia)

    clock = {"t": 0.0}
    # window_s=1000 so we control rollover via the fake clock. Pre-consume most
    # of window 1's airtime so only a couple of frames fit on first send; a fresh
    # later window then has enough headroom to flush the entire remainder.
    budget = AirtimeBudget(max_bytes=2000, window_s=1000)
    budget.record(1600, now=0.0)  # only 400 bytes left in window 1 (~2 frames)
    a = LoRaTransport(
        identity=MeshIdentity.generate("a@x.y"), interface=ia,
        budget=budget, clock=lambda: clock["t"],
    )
    b = _transport("b@x.y", ib)
    await a.start()
    await b.start()

    payload = bytes(range(256)) * 3  # 768 bytes -> several MTU-sized frames
    expected_n = len(framing.to_frames(_build_pkt(a, payload, "b@x.y")))
    assert expected_n >= 3  # genuinely multi-frame

    await a.send_async(payload, recipient="b@x.y")
    await asyncio.sleep(0.02)

    # Only the frames that fit the first window's budget were transmitted.
    first_window = list(track.frames)
    assert 0 < len(first_window) < expected_n
    fit_bytes = sum(len(f) for f in first_window)
    assert fit_bytes <= 400  # only the pre-consumed window's headroom fit
    assert a.pending() > 0  # remainder held back

    # Roll the window forward and flush — the rest now go out.
    clock["t"] = 2000.0
    await a.flush()
    await asyncio.sleep(0.02)
    assert a.pending() == 0
    # Every original frame eventually reached the bus exactly once.
    assert len(track.frames) == expected_n
    # The receiver reassembled the full original payload.
    assert payload in b.receive()


def _build_pkt(transport, payload, recipient):
    # Mirror LoRaTransport.send_async's framing to compute the expected frame
    # COUNT (msg_id/signature vary per send, so only the count/sizes are stable).
    import os

    from skcomms.transports.ble.protocol import FLAG_SIGNED, MeshPacket, PacketType
    rid = transport.identity_id_for(recipient)
    return MeshPacket(
        type=PacketType.MESSAGE, ttl=1, flags=FLAG_SIGNED, timestamp=0,
        msg_id=os.urandom(8), sender_id=transport.identity.my_id,
        recipient_id=rid, payload=payload,
        signature=transport.identity.sign(payload),
    )
