"""[CoT][CB4] Geo / situational-awareness plane tests.

Covers classify (unit/marker/waypoint, skip chat/ping/empty), GeoStore upsert +
query (nearest ordering, lookup by uid/callsign), stale pruning,
situational_summary text, and the geo+json federation envelope round-trip.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from skcomms.cot import CotEvent, CotPoint, make_geochat
from skcomms.envelope import Envelope
from skcomms.geo import (
    DEFAULT_TTL_S, GEO_CONTENT_TYPE, GeoStore, GeoUnit, classify_cot,
    envelope_to_geounits, geo_to_envelope,
)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _pli(uid="U1", callsign="PURE", lat=41.137, lon=-73.424, ctype="a-f-G-U-C",
         stale_min=5, detail=""):
    now = datetime.now(timezone.utc)
    return CotEvent(
        uid=uid, type=ctype, how="m-g",
        point=CotPoint(lat=lat, lon=lon, hae=10.0),
        stale=_iso(now + timedelta(minutes=stale_min)),
        callsign=callsign, detail_xml=detail,
    )


# --- classify --------------------------------------------------------------

class TestClassify:
    def test_unit(self):
        assert classify_cot("a-f-G-U-C") == "unit"
        assert classify_cot("a-h-G") == "unit"  # hostile still a unit

    def test_marker(self):
        assert classify_cot("b-m-p-s-m") == "marker"
        assert classify_cot("b-m-d") == "marker"

    def test_waypoint(self):
        assert classify_cot("b-m-p-w") == "waypoint"
        assert classify_cot("b-m-p-c") == "waypoint"  # route control point

    def test_skip_chat_ping_empty(self):
        assert classify_cot("b-t-f") is None         # GeoChat
        assert classify_cot("t-x-c-t") is None        # ping
        assert classify_cot("t-x-c-t-r") is None      # pong
        assert classify_cot("") is None
        assert classify_cot("   ") is None


# --- upsert classification + skip ------------------------------------------

class TestUpsert:
    def test_unit_marker_waypoint(self):
        s = GeoStore()
        assert s.upsert_from_cot(_pli(uid="u", ctype="a-f-G-U-C")).kind == "unit"
        assert s.upsert_from_cot(_pli(uid="m", ctype="b-m-p-s-m", callsign="RP")).kind == "marker"
        assert s.upsert_from_cot(_pli(uid="w", ctype="b-m-p-w", callsign="WP1")).kind == "waypoint"
        assert s.count() == 3

    def test_skip_chat(self):
        s = GeoStore()
        chat = make_geochat("hello", sender_callsign="PURE", sender_uid="U1")
        assert s.upsert_from_cot(chat) is None
        assert s.count() == 0

    def test_skip_ping(self):
        s = GeoStore()
        ping = CotEvent(uid="ping", type="t-x-c-t", point=CotPoint(lat=1.0, lon=2.0))
        assert s.upsert_from_cot(ping) is None
        assert s.count() == 0

    def test_skip_no_fix(self):
        s = GeoStore()
        nofix = CotEvent(uid="z", type="a-f-G-U-C", point=CotPoint(lat=0.0, lon=0.0))
        assert s.upsert_from_cot(nofix) is None
        assert s.count() == 0

    def test_callsign_fallback_to_uid(self):
        s = GeoStore()
        u = s.upsert_from_cot(CotEvent(uid="bare", type="a-f-G", point=CotPoint(lat=5.0, lon=5.0)))
        assert u.callsign == "bare"

    def test_track_course_speed(self):
        s = GeoStore()
        u = s.upsert_from_cot(_pli(detail='<track speed="1.4" course="270.0"/>'))
        assert u.course == 270.0 and u.speed == 1.4

    def test_upsert_overwrites_same_uid(self):
        s = GeoStore()
        s.upsert_from_cot(_pli(uid="U1", lat=10.0, lon=10.0))
        s.upsert_from_cot(_pli(uid="U1", lat=20.0, lon=20.0))
        assert s.count() == 1
        assert s.get("U1").lat == 20.0


# --- query / nearest -------------------------------------------------------

class TestQuery:
    def test_get_by_uid_and_callsign(self):
        s = GeoStore()
        s.upsert_from_cot(_pli(uid="U1", callsign="PURE"))
        assert s.get("U1").callsign == "PURE"
        assert s.get("PURE").uid == "U1"
        assert s.get("pure").uid == "U1"  # case-insensitive callsign
        assert s.get("nope") is None

    def test_nearest_ordering(self):
        s = GeoStore()
        s.upsert_from_cot(_pli(uid="far", callsign="FAR", lat=42.0, lon=-73.0))
        s.upsert_from_cot(_pli(uid="near", callsign="NEAR", lat=41.140, lon=-73.420))
        s.upsert_from_cot(_pli(uid="mid", callsign="MID", lat=41.5, lon=-73.4))
        order = [u.callsign for u in s.nearest(41.137, -73.424, n=3)]
        assert order == ["NEAR", "MID", "FAR"]

    def test_nearest_n_limit(self):
        s = GeoStore()
        for i in range(5):
            s.upsert_from_cot(_pli(uid=f"u{i}", callsign=f"C{i}", lat=40.0 + i, lon=-73.0))
        assert len(s.nearest(40.0, -73.0, n=2)) == 2

    def test_get_all_kind_filter(self):
        s = GeoStore()
        s.upsert_from_cot(_pli(uid="u", ctype="a-f-G-U-C"))
        s.upsert_from_cot(_pli(uid="m", ctype="b-m-p-s-m"))
        assert len(s.get_all(kind="unit")) == 1
        assert len(s.get_all(kind="marker")) == 1


# --- stale pruning ---------------------------------------------------------

class TestStale:
    def test_prune_past_cot_stale(self):
        s = GeoStore()
        now = datetime.now(timezone.utc)
        expired = CotEvent(uid="old", type="a-f-G", point=CotPoint(lat=1.0, lon=1.0),
                           stale=_iso(now - timedelta(minutes=1)))
        fresh = _pli(uid="new", stale_min=5)
        s.upsert_from_cot(expired)
        s.upsert_from_cot(fresh)
        assert s.count(include_stale=True) == 2
        assert s.prune_stale() == 1
        assert s.count(include_stale=True) == 1
        assert s.get("new") is not None

    def test_get_all_excludes_stale_by_default(self):
        s = GeoStore()
        now = datetime.now(timezone.utc)
        s.upsert_from_cot(CotEvent(uid="old", type="a-f-G", point=CotPoint(lat=1.0, lon=1.0),
                                   stale=_iso(now - timedelta(minutes=1))))
        assert s.get_all() == []
        assert len(s.get_all(include_stale=True)) == 1

    def test_ttl_fallback_when_no_stale(self):
        # A unit with no usable stale time + an old last_seen prunes by TTL.
        s = GeoStore(ttl_s=10.0)
        u = GeoUnit(uid="t", callsign="T", lat=1.0, lon=1.0,
                    last_seen=_iso(datetime.now(timezone.utc) - timedelta(seconds=30)),
                    stale=None)
        s.upsert(u)
        assert s.prune_stale() == 1


# --- situational summary ---------------------------------------------------

class TestSummary:
    def test_empty(self):
        assert "yet" in GeoStore().situational_summary().lower()

    def test_text(self):
        s = GeoStore()
        s.upsert_from_cot(_pli(uid="U1", callsign="PURE", lat=41.137, lon=-73.424))
        s.upsert_from_cot(_pli(uid="m", ctype="b-m-p-s-m", callsign="RP-Alpha",
                               lat=39.0, lon=-77.5))
        txt = s.situational_summary()
        assert "PURE at 41.13700,-73.42400" in txt
        assert "marker RP-Alpha at 39.00000,-77.50000" in txt
        assert "1 unit(s)" in txt and "1 marker(s)" in txt

    def test_around_orders_nearest_first(self):
        s = GeoStore()
        s.upsert_from_cot(_pli(uid="far", callsign="FAR", lat=42.0, lon=-73.0))
        s.upsert_from_cot(_pli(uid="near", callsign="NEAR", lat=41.140, lon=-73.420))
        txt = s.situational_summary(around=(41.137, -73.424))
        assert txt.index("NEAR") < txt.index("FAR")


# --- geo envelope round-trip -----------------------------------------------

class TestEnvelope:
    def test_single_unit_round_trip(self):
        u = GeoUnit(uid="U1", callsign="PURE", cot_type="a-f-G-U-C",
                    lat=41.137, lon=-73.424, hae=10.0, course=270.0, speed=1.4,
                    kind="unit", source="mesh")
        env = geo_to_envelope(u, from_fqid="lumina@chef.skworld")
        assert env.content_type == GEO_CONTENT_TYPE
        assert env.thread_id == "U1"
        assert env.headers["geo-uid"] == "U1" and env.headers["geo-kind"] == "unit"
        out = envelope_to_geounits(env)
        assert len(out) == 1
        r = out[0]
        assert r.uid == "U1" and r.callsign == "PURE" and r.kind == "unit"
        assert r.lat == 41.137 and r.lon == -73.424
        assert r.hae == 10.0 and r.course == 270.0 and r.speed == 1.4

    def test_collection_round_trip(self):
        units = [
            GeoUnit(uid="U1", callsign="PURE", lat=41.1, lon=-73.4, kind="unit"),
            GeoUnit(uid="M1", callsign="RP", lat=39.0, lon=-77.5, kind="marker"),
        ]
        env = geo_to_envelope(units, from_fqid="lumina@chef.skworld")
        assert env.headers["geo-count"] == "2"
        out = envelope_to_geounits(env)
        assert {u.uid for u in out} == {"U1", "M1"}
        assert {u.kind for u in out} == {"unit", "marker"}

    def test_geojson_lonlat_order(self):
        u = GeoUnit(uid="U1", callsign="PURE", lat=41.137, lon=-73.424, kind="unit")
        feat = u.to_geojson_feature()
        # GeoJSON is [lon, lat]
        assert feat["geometry"]["coordinates"] == [-73.424, 41.137]

    def test_wrong_content_type_raises(self):
        env = Envelope(from_fqid="a@b.c", to_fqid="*", content_type="text/plain", body="x")
        with pytest.raises(ValueError):
            envelope_to_geounits(env)

    def test_store_to_envelope_round_trip(self):
        s = GeoStore()
        s.upsert_from_cot(_pli(uid="U1", callsign="PURE"))
        s.upsert_from_cot(_pli(uid="m", ctype="b-m-p-s-m", callsign="RP"))
        env = geo_to_envelope(s.get_all(), from_fqid="lumina@chef.skworld")
        # A peer ingests it back into its own store.
        peer = GeoStore()
        for u in envelope_to_geounits(env):
            peer.upsert(u)
        assert peer.count() == 2
        assert peer.get("PURE") is not None
