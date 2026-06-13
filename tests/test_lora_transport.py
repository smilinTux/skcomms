import asyncio

import pytest

from skcomms.transports.ble.identity import MeshIdentity
from skcomms.transports.lora.interface import FakeLoRaInterface, FakeLoRaMedium
from skcomms.transports.lora.transport import LoRaTransport


def _transport(fqid, iface):
    return LoRaTransport(identity=MeshIdentity.generate(fqid), interface=iface)


@pytest.mark.asyncio
async def test_envelope_round_trips_between_two_nodes():
    medium = FakeLoRaMedium()
    ia = FakeLoRaInterface("node-a", medium)
    ib = FakeLoRaInterface("node-b", medium)
    a = _transport("a@x.y", ia)
    b = _transport("b@x.y", ib)
    await a.start(); await b.start()

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
    await a.start(); await b.start()
    payload = bytes(range(256)) * 3  # 768 bytes -> multi-frame
    await a.send_async(payload, recipient="b@x.y")
    await asyncio.sleep(0.05)
    assert payload in b.receive()


def test_transport_metadata():
    from skcomms.transport import TransportCategory
    t = _transport("a@x.y", None)
    assert t.name == "lora"
    assert t.category == TransportCategory.OFFLINE
