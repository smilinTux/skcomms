"""[CoT][CB1] CoT codec tests — parse/emit Cursor-on-Target + Envelope mapping.

Uses realistic CoT samples (PLI position, GeoChat, dropped marker) as ATAK emits.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from skcomms.cot import (
    COT_CONTENT_TYPE, CotEvent, CotPoint, cot_to_envelope, envelope_to_cot,
    parse_cot, to_cot,
)
from skcomms.envelope import Envelope

# --- realistic samples (trimmed but ATAK-shaped) ---------------------------

PLI = (
    '<event version="2.0" uid="ANDROID-deadbeef" type="a-f-G-U-C" how="m-g"'
    ' time="2026-06-22T03:00:00.000Z" start="2026-06-22T03:00:00.000Z"'
    ' stale="2026-06-22T03:05:00.000Z">'
    '<point lat="38.8895" lon="-77.0353" hae="50.0" ce="9.0" le="9.0"/>'
    '<detail><contact callsign="JARVIS-1" endpoint="*:-1:stcp"/>'
    '<__group name="Cyan" role="Team Member"/><takv device="Pixel" platform="ATAK"/>'
    '<track speed="1.4" course="270.0"/><remarks>on the move</remarks></detail>'
    '</event>'
)
GEOCHAT = (
    '<event version="2.0" uid="GeoChat.ANDROID-deadbeef.All.123" type="b-t-f" how="h-g-i-g-o"'
    ' time="2026-06-22T03:01:00.000Z" start="2026-06-22T03:01:00.000Z"'
    ' stale="2026-06-22T03:11:00.000Z">'
    '<point lat="38.8895" lon="-77.0353" hae="9999999.0" ce="9999999.0" le="9999999.0"/>'
    '<detail><__chat id="All Chat Rooms" chatroom="All Chat Rooms" senderCallsign="JARVIS-1">'
    '<chatgrp uid0="ANDROID-deadbeef" id="All Chat Rooms"/></__chat>'
    '<remarks source="BAO.F.ATAK">contact rear, moving to RP</remarks></detail>'
    '</event>'
)
MARKER = (
    '<event version="2.0" uid="marker-9f" type="b-m-p-s-m" how="h-e"'
    ' time="2026-06-22T03:02:00.000Z" start="2026-06-22T03:02:00.000Z"'
    ' stale="2026-06-23T03:02:00.000Z">'
    '<point lat="39.0" lon="-77.5" hae="100.0" ce="5.0" le="5.0"/>'
    '<detail><contact callsign="RP-Alpha"/><remarks>rally point</remarks></detail>'
    '</event>'
)


class TestParse:
    def test_pli(self):
        e = parse_cot(PLI)
        assert e.uid == "ANDROID-deadbeef" and e.type == "a-f-G-U-C"
        assert e.point.lat == 38.8895 and e.point.lon == -77.0353 and e.point.hae == 50.0
        assert e.callsign == "JARVIS-1"
        assert e.remarks == "on the move"
        assert not e.is_chat

    def test_geochat(self):
        e = parse_cot(GEOCHAT)
        assert e.is_chat and e.type == "b-t-f"
        assert e.callsign is None  # no <contact>, it's a __chat
        assert e.chat == "contact rear, moving to RP"

    def test_marker(self):
        e = parse_cot(MARKER)
        assert e.type.startswith("b-m-p") and e.callsign == "RP-Alpha"
        assert e.remarks == "rally point" and e.point.lat == 39.0

    def test_malformed_raises(self):
        with pytest.raises(ValueError):
            parse_cot("<not-cot/>")
        with pytest.raises(ValueError):
            parse_cot("<event><point lat=")  # broken xml


class TestRoundTrip:
    @pytest.mark.parametrize("sample", [PLI, GEOCHAT, MARKER])
    def test_event_attrs_and_point_survive(self, sample):
        e1 = parse_cot(sample)
        e2 = parse_cot(to_cot(e1))   # parse -> emit -> parse
        assert (e2.uid, e2.type, e2.how) == (e1.uid, e1.type, e1.how)
        assert e2.point.model_dump() == e1.point.model_dump()
        assert e2.callsign == e1.callsign

    def test_detail_preserved_verbatim(self):
        e = parse_cot(PLI)
        # full detail subtree round-trips (takv/__group/track not dropped)
        out = to_cot(e)
        assert "takv" in out and "__group" in out and "track" in out

    def test_synthesized_detail_when_none(self):
        e = CotEvent(uid="x", type="b-t-f", chat="hello", point=CotPoint(lat=1.0, lon=2.0))
        out = to_cot(e)
        re = parse_cot(out)
        assert re.uid == "x" and re.chat == "hello"


class TestEnvelopeMapping:
    def test_cot_to_envelope_and_back(self):
        e = parse_cot(PLI)
        env = cot_to_envelope(e, from_fqid="jarvis@chef.skworld", to_fqid="*")
        assert isinstance(env, Envelope)
        assert env.content_type == COT_CONTENT_TYPE
        assert env.from_fqid == "jarvis@chef.skworld" and env.to_fqid == "*"
        assert env.thread_id == "ANDROID-deadbeef"           # entity grouping
        assert env.headers["cot-uid"] == "ANDROID-deadbeef"
        assert env.headers["cot-type"] == "a-f-G-U-C"
        # body is valid CoT
        assert ET.fromstring(env.body).tag == "event"
        back = envelope_to_cot(env)
        assert back.uid == e.uid and back.callsign == "JARVIS-1"

    def test_envelope_to_cot_rejects_non_cot(self):
        env = Envelope(from_fqid="a@x", to_fqid="b@x", content_type="text/plain", body="hi")
        with pytest.raises(ValueError):
            envelope_to_cot(env)


class TestMeshDatagram:
    def test_xml_datagram_parses(self):
        from skcomms.cot import parse_cot_datagram
        cot = parse_cot_datagram(PLI.encode())
        assert cot is not None and cot.uid == "ANDROID-deadbeef"

    def test_xml_datagram_with_leading_ws(self):
        from skcomms.cot import parse_cot_datagram
        assert parse_cot_datagram(b"\n  " + PLI.encode()).uid == "ANDROID-deadbeef"

    def test_garbage_datagram_returns_none(self):
        from skcomms.cot import parse_cot_datagram
        assert parse_cot_datagram(b"") is None
        assert parse_cot_datagram(b"\x00\x01\x02not cot") is None

    def test_protobuf_datagram_best_effort_no_crash(self):
        from skcomms.cot import parse_cot_datagram
        # 0xbf header but no takproto / bogus body -> None, never raises
        assert parse_cot_datagram(b"\xbf\x01\xbf\x00\x00") is None


def test_protobuf_mesh_datagram_roundtrip():
    takproto = pytest.importorskip("takproto")
    from skcomms.cot import parse_cot_datagram
    proto = takproto.xml2proto(PLI, takproto.TAKProtoVer.MESH)
    cot = parse_cot_datagram(bytes(proto))
    assert cot is not None and cot.uid == "ANDROID-deadbeef" and cot.callsign == "JARVIS-1"
