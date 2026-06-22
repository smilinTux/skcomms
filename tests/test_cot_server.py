"""[CoT][CB2] TAK-streaming server tests — a synthetic ATAK client over real TCP.

No pytak/phone needed: we open a raw TCP socket, stream CoT like ATAK does, and
verify (a) inbound CoT hits the ingest hook, (b) it's re-broadcast to other
connected clients, (c) inject() pushes federation-inbound CoT to clients, and
(d) the event splitter handles back-to-back + partial frames.
"""

from __future__ import annotations

import asyncio

import pytest

from skcomms.cot import CotEvent, CotPoint, parse_cot, to_cot
from skcomms.cot_server import CotStreamServer, extract_events

pytestmark = pytest.mark.asyncio

PLI = (
    '<event version="2.0" uid="ANDROID-1" type="a-f-G-U-C" how="m-g"'
    ' time="2026-06-22T03:00:00.000Z" start="2026-06-22T03:00:00.000Z"'
    ' stale="2026-06-22T03:05:00.000Z">'
    '<point lat="38.0" lon="-77.0" hae="50.0" ce="9.0" le="9.0"/>'
    '<detail><contact callsign="ALPHA-1"/></detail></event>'
)


def test_extract_events_splits_and_keeps_remainder():
    two = (PLI + PLI).encode()
    evs, rem = extract_events(two)
    assert len(evs) == 2 and rem == b""
    # partial trailing event is kept
    evs, rem = extract_events(PLI.encode() + b"<event uid='x'><point")
    assert len(evs) == 1 and rem.startswith(b"<event uid='x'>")


async def _serve(**kw):
    srv = CotStreamServer(host="127.0.0.1", port=0, **kw)
    await srv.start()
    port = srv._server.sockets[0].getsockname()[1]
    return srv, port


async def test_inbound_cot_hits_ingest_hook():
    seen = []
    srv, port = await _serve(ingest=lambda cot: seen.append(cot))
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(PLI.encode()); await w.drain()
    await asyncio.sleep(0.1)
    assert len(seen) == 1
    assert seen[0].uid == "ANDROID-1" and seen[0].callsign == "ALPHA-1"
    w.close(); await srv.stop()


async def test_async_ingest_hook_awaited():
    seen = []
    async def hook(cot): await asyncio.sleep(0); seen.append(cot.uid)
    srv, port = await _serve(ingest=hook)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(PLI.encode()); await w.drain()
    await asyncio.sleep(0.1)
    assert seen == ["ANDROID-1"]
    w.close(); await srv.stop()


async def test_rebroadcast_to_other_clients():
    srv, port = await _serve()
    # client A (listener) + client B (sender)
    ra, wa = await asyncio.open_connection("127.0.0.1", port)
    rb, wb = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.05)
    wb.write(PLI.encode()); await wb.drain()
    data = await asyncio.wait_for(ra.readuntil(b"</event>"), timeout=2)
    got = parse_cot(data)
    assert got.uid == "ANDROID-1"            # A received B's CoT
    # B should NOT receive its own echo
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(rb.readuntil(b"</event>"), timeout=0.3)
    wa.close(); wb.close(); await srv.stop()


async def test_inject_pushes_to_all_clients():
    srv, port = await _serve()
    ra, wa = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.05)
    cot = CotEvent(uid="fed-1", type="a-f-G-U-C", point=CotPoint(lat=1.0, lon=2.0), callsign="REMOTE")
    srv.inject(cot)                          # federation-inbound CoT -> operators
    data = await asyncio.wait_for(ra.readuntil(b"</event>"), timeout=2)
    assert parse_cot(data).uid == "fed-1"
    wa.close(); await srv.stop()


async def test_malformed_frame_does_not_kill_stream():
    seen = []
    srv, port = await _serve(ingest=lambda c: seen.append(c.uid))
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"<event garbage</event>" + PLI.encode()); await w.drain()
    await asyncio.sleep(0.1)
    assert seen == ["ANDROID-1"]             # good event still processed
    w.close(); await srv.stop()


def test_federation_ingest_fans_out_cot_to_peers():
    """The federation ingest hook wraps CoT + send_federated's it to each peer."""
    from skcomms.cot_server import federation_ingest

    class FakeSk:
        def __init__(self): self.calls = []
        def send_federated(self, to_fqid, message, *, content_type="text/plain", **kw):
            self.calls.append((to_fqid, content_type, message))
    sk = FakeSk()
    hook = federation_ingest(sk, from_fqid="jarvis@chef.skworld",
                             peers_provider=lambda: ["lumina@chef.skworld", "opus@chef.skworld"])
    hook(parse_cot(PLI))
    assert {c[0] for c in sk.calls} == {"lumina@chef.skworld", "opus@chef.skworld"}
    assert all(c[1] == "application/cot+xml" for c in sk.calls)
    assert "ANDROID-1" in sk.calls[0][2]          # the CoT XML rides in the body
