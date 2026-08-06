"""Tests for the live skcot bridge behind ``GET /api/v1/geo/units``.

The situational picture's source of truth is the ``skcot`` service process,
exposed read-only over HTTP (``skcot.geo_http``). This endpoint prefers that
live feed and falls back to the local in-process store (the fleet seed) when
skcot is unreachable OR reports zero units. These tests cover exactly those
three branches, plus a real end-to-end fetch over a socket:

  * skcot reachable WITH units -> the endpoint returns skcot's real units,
  * skcot down (fetch returns None) -> local/seed fallback,
  * skcot up but EMPTY -> local/seed fallback,
  * a real stub HTTP server at SKCOT_GEO_URL -> its units are returned.

The map endpoint must never 500, so every branch yields a valid shape.
"""

from __future__ import annotations

import importlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    """A TestClient over the reloaded app on an isolated HOME."""
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))

    import skcomms.api as api

    importlib.reload(api)
    return TestClient(api.app)


def _seed_local(gs):
    """Install a fresh fallback store as the local singleton and seed one unit."""
    store = gs.SkcotGeoStore()
    gs.set_geo_store(store)
    store.upsert(
        {
            "uid": "fleet:self",
            "callsign": "fleet:self",
            "cot_type": "a-f-G-U-C",
            "lat": 39.0,
            "lon": -77.0,
            "kind": "unit",
            "source": "seed:self",
            "last_seen": "2026-08-05T12:00:00+00:00",
        }
    )
    return store


def test_skcot_reachable_with_units_wins(tmp_path, monkeypatch):
    """skcot has real units -> those are returned, not the local seed."""
    import skcomms.geo_store as gs

    _seed_local(gs)  # a seed exists locally, but must be overridden

    real = {
        "units": [
            {
                "uid": "ATAK-7",
                "callsign": "RANGER-7",
                "cot_type": "a-f-G-U-C",
                "lat": 40.7614,
                "lon": -73.9776,
                "kind": "unit",
                "source": "tls",
                "last_seen": "2026-08-05T12:34:56+00:00",
            }
        ],
        "count": 1,
    }
    monkeypatch.setattr(gs, "fetch_skcot_geo", lambda **kw: real)

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    uids = {u["uid"] for u in body["units"]}
    assert uids == {"ATAK-7"}  # real telemetry, seed suppressed


def test_skcot_down_falls_back_to_local(tmp_path, monkeypatch):
    """skcot unreachable (fetch -> None) -> local/seed store is served."""
    import skcomms.geo_store as gs

    _seed_local(gs)
    monkeypatch.setattr(gs, "fetch_skcot_geo", lambda **kw: None)

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["units"][0]["uid"] == "fleet:self"


def test_skcot_up_but_empty_falls_back_to_local(tmp_path, monkeypatch):
    """skcot reachable but 0 units -> local/seed store is served."""
    import skcomms.geo_store as gs

    _seed_local(gs)
    monkeypatch.setattr(gs, "fetch_skcot_geo", lambda **kw: {"units": [], "count": 0})

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["units"][0]["uid"] == "fleet:self"


def test_skcot_empty_and_no_local_is_valid_empty(tmp_path, monkeypatch):
    """skcot empty + empty local -> a well-shaped empty envelope, never a 500."""
    import skcomms.geo_store as gs

    store = gs.SkcotGeoStore()
    gs.set_geo_store(store)  # nothing seeded
    monkeypatch.setattr(gs, "fetch_skcot_geo", lambda **kw: None)

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    assert resp.json() == {"units": [], "count": 0}


def test_skcot_geojson_format_passthrough(tmp_path, monkeypatch):
    """?format=geojson returns skcot's FeatureCollection when it has features."""
    import skcomms.geo_store as gs

    _seed_local(gs)
    fc = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [-73.9776, 40.7614]},
                "properties": {"uid": "ATAK-7", "callsign": "RANGER-7"},
            }
        ],
    }

    def _fetch(**kw):
        assert kw.get("fmt") == "geojson"
        return fc

    monkeypatch.setattr(gs, "fetch_skcot_geo", _fetch)

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units", params={"format": "geojson"})
    assert resp.status_code == 200
    got = resp.json()
    assert got["type"] == "FeatureCollection"
    assert got["features"][0]["properties"]["uid"] == "ATAK-7"


# --------------------------------------------------------------------------
# Real end-to-end fetch: stand up a stub HTTP server at SKCOT_GEO_URL and prove
# the urllib path in fetch_skcot_geo actually pulls it (no monkeypatch of the
# fetch function). This exercises the real network seam skcot fills in prod.
# --------------------------------------------------------------------------


class _StubGeoHandler(BaseHTTPRequestHandler):
    payload = {
        "units": [
            {
                "uid": "STUB-1",
                "callsign": "STUB-1",
                "cot_type": "a-f-G-U-C",
                "lat": 1.0,
                "lon": 2.0,
                "kind": "unit",
                "last_seen": "2026-08-05T12:00:00+00:00",
            }
        ],
        "count": 1,
    }

    def do_GET(self):  # noqa: N802 - stdlib handler contract
        body = json.dumps(self.payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test noise
        pass


def test_real_stub_url_end_to_end(tmp_path, monkeypatch):
    """A live SKCOT_GEO_URL stub -> its units flow through to the endpoint."""
    import skcomms.geo_store as gs

    _seed_local(gs)  # a seed exists, but the reachable stub must win

    server = HTTPServer(("127.0.0.1", 0), _StubGeoHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setenv("SKCOT_GEO_URL", f"http://127.0.0.1:{port}/geo/units")
        # sanity: the low-level fetch pulls the stub
        assert gs.geo_payload_has_units(gs.fetch_skcot_geo()) is True

        client = _client(tmp_path, monkeypatch)
        resp = client.get("/api/v1/geo/units")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 1
        assert body["units"][0]["uid"] == "STUB-1"
    finally:
        server.shutdown()
        server.server_close()
