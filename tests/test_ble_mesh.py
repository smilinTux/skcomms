import asyncio

import pytest

from skcomms.transports.ble.identity import MeshIdentity, id_hash
from skcomms.transports.ble.node import MeshNode
from skcomms.transports.ble.radio import FakeMedium, FakeRadio


def _node(fqid, medium):
    ident = MeshIdentity.generate(fqid)
    radio = FakeRadio(fqid, medium)
    return MeshNode(identity=ident, radio=radio)


@pytest.mark.asyncio
async def test_three_hop_line_relays_through_middle():
    medium = FakeMedium()
    a = _node("a@x.y", medium)
    b = _node("b@x.y", medium)
    c = _node("c@x.y", medium)
    medium.link("a@x.y", "b@x.y")
    medium.link("b@x.y", "c@x.y")  # A—B—C ; A and C are NOT linked

    inbox: list[bytes] = []
    c.on_message(lambda pkt: inbox.append(pkt.payload))
    for n in (a, b, c):
        await n.start()

    await a.send_broadcast(b"relayed-hello")
    await asyncio.sleep(0.05)

    assert b"relayed-hello" in inbox  # reached C only via B


@pytest.mark.asyncio
async def test_duplicate_does_not_loop_forever():
    medium = FakeMedium()
    a = _node("a@x.y", medium)
    b = _node("b@x.y", medium)
    c = _node("c@x.y", medium)
    # triangle: every node hears every other → without dedup this would storm
    medium.link("a@x.y", "b@x.y")
    medium.link("b@x.y", "c@x.y")
    medium.link("a@x.y", "c@x.y")

    counts: list[int] = []
    c.on_message(lambda pkt: counts.append(1))
    for n in (a, b, c):
        await n.start()

    await a.send_broadcast(b"once")
    await asyncio.sleep(0.05)
    assert sum(counts) == 1  # delivered exactly once despite the loop


@pytest.mark.asyncio
async def test_directed_message_only_delivers_to_recipient():
    medium = FakeMedium()
    a = _node("a@x.y", medium)
    b = _node("b@x.y", medium)
    c = _node("c@x.y", medium)
    medium.link("a@x.y", "b@x.y")
    medium.link("b@x.y", "c@x.y")

    b_inbox, c_inbox = [], []
    b.on_message(lambda pkt: b_inbox.append(pkt.payload))
    c.on_message(lambda pkt: c_inbox.append(pkt.payload))
    for n in (a, b, c):
        await n.start()

    await a.send_to(id_hash("c@x.y"), b"for-c-only")
    await asyncio.sleep(0.05)
    assert c_inbox == [b"for-c-only"]
    assert b_inbox == []  # B relays but does not deliver locally
