"""Tests for ``GET /api/v1/geo/units`` (the skmap situational-picture feed).

The endpoint publishes the process-global geo store (``skcomms.geo_store``),
which the CoT bridge feeds. These tests cover the two contract cases the
Flutter ``skmap`` pane depends on:

  * empty store  -> a valid, empty envelope (never a 500), and
  * a seeded unit -> the exact flat shape ``GeoUnit.fromJson`` reads
    (``uid`` / ``callsign`` / ``lat`` / ``lon`` / ``cot_type`` / ``last_seen``),
    plus the GeoJSON ``FeatureCollection`` alternative.
"""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    """A TestClient over the reloaded app on an isolated HOME."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    # Disable the live skcot bridge so these tests deterministically exercise
    # the local in-process store (the bridge is covered in test_api_geo_skcot_bridge).
    monkeypatch.setenv("SKCOT_GEO_URL", "")

    import skcomms.api as api

    importlib.reload(api)
    return TestClient(api.app)


def _seed_store(gs):
    """Install a fresh fallback store as the singleton and return it.

    The fallback keeps no staleness clock and accepts plain dicts, so the
    endpoint contract can be asserted deterministically regardless of whether
    the richer ``skcot`` GeoStore is installed in the test environment (its
    300s TTL would otherwise prune fixtures with a fixed ``last_seen``).
    """
    store = gs.SkcotGeoStore()
    gs.set_geo_store(store)
    return store


def test_geo_units_empty(tmp_path, monkeypatch):
    """No units reported yet: 200 with an empty, well-shaped envelope."""
    import skcomms.geo_store as gs

    _seed_store(gs)
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"units": [], "count": 0}


def test_geo_units_seeded(tmp_path, monkeypatch):
    """A seeded unit is returned in the flat shape GeoUnit.fromJson expects."""
    import skcomms.geo_store as gs

    store = _seed_store(gs)
    store.upsert(
        {
            "uid": "LUMINA",
            "callsign": "LUMINA",
            "cot_type": "a-f-G-U-C",
            "lat": 40.7580,
            "lon": -73.9855,
            "kind": "unit",
            "last_seen": "2026-08-05T12:00:00+00:00",
        }
    )

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    unit = body["units"][0]
    # Exactly the keys the app's GeoUnit.fromJson reads.
    assert unit["uid"] == "LUMINA"
    assert unit["callsign"] == "LUMINA"
    assert unit["lat"] == 40.7580
    assert unit["lon"] == -73.9855
    assert unit["cot_type"] == "a-f-G-U-C"
    assert unit["last_seen"] == "2026-08-05T12:00:00+00:00"


def test_geo_units_geojson_format(tmp_path, monkeypatch):
    """?format=geojson returns a FeatureCollection with [lon, lat] geometry."""
    import skcomms.geo_store as gs

    store = _seed_store(gs)
    store.upsert(
        {
            "uid": "OBJ-RALLY",
            "callsign": "RALLY POINT",
            "cot_type": "b-m-p-w",
            "lat": 40.7625,
            "lon": -73.9840,
            "kind": "waypoint",
            "last_seen": "2026-08-05T12:00:00+00:00",
        }
    )

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units", params={"format": "geojson"})
    assert resp.status_code == 200
    fc = resp.json()
    assert fc["type"] == "FeatureCollection"
    assert len(fc["features"]) == 1
    feat = fc["features"][0]
    assert feat["type"] == "Feature"
    # GeoJSON is [lon, lat] order.
    assert feat["geometry"]["coordinates"] == [-73.9840, 40.7625]
    assert feat["properties"]["uid"] == "OBJ-RALLY"
    assert feat["properties"]["callsign"] == "RALLY POINT"


def test_geo_units_store_is_shared_feed_point(tmp_path, monkeypatch):
    """The endpoint reads the same singleton the CoT bridge would feed."""
    import skcomms.geo_store as gs

    _seed_store(gs)
    client = _client(tmp_path, monkeypatch)

    # Feed AFTER the app is built: the endpoint must see live upserts.
    gs.get_geo_store().upsert(
        {"uid": "PURE", "callsign": "PURE", "cot_type": "a-f-G-U-C",
         "lat": 40.7614, "lon": -73.9776}
    )
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    uids = [u["uid"] for u in resp.json()["units"]]
    assert "PURE" in uids
