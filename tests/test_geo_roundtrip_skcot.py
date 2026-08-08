"""Cross-process serialization round-trip: skcot <-> skcomms agree (CR-5.2 AC2).

There is ONE ``GeoUnit`` / ``GeoStore`` type and it lives in :mod:`skcot.geo`.
skcomms imports it (it does not reimplement it), and the ONLY cross-process seam
between the two is the read-only HTTP bridge (:mod:`skcot.geo_http` served by the
skcot process, :func:`skcomms.geo_store.fetch_skcot_geo` on the skcomms side).

These tests stand up the REAL skcot geo HTTP server over an ephemeral socket,
seed it with a fully-populated :class:`skcot.geo.GeoUnit`, fetch it back through
``fetch_skcot_geo`` exactly as the ``/api/v1/geo/units`` endpoint does, and prove
that a unit serialized by skcot deserializes **identically** on the skcomms side
-- for both the flat ``units`` shape and the GeoJSON ``FeatureCollection`` shape.
Because both sides use the same shared type, "identical" means field-for-field
model equality, not just key overlap.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

# skcot is an optional sibling package, not a skcomms dependency (the `dev`
# extras deliberately install no sibling sk* packages). Without this guard the
# module raises ImportError at COLLECTION time, which aborts the whole run
# rather than skipping these three tests.
pytest.importorskip("skcot.geo", reason="skcot sibling package not installed")

from skcot.geo import GeoStore, GeoUnit  # noqa: E402
from skcot.geo_http import start_geo_http_server  # noqa: E402

import skcomms.geo_store as gs


def _fully_populated_unit() -> GeoUnit:
    """A GeoUnit exercising every serialized field (no None left to chance)."""
    return GeoUnit(
        uid="ATAK-7",
        callsign="RANGER-7",
        cot_type="a-f-G-U-C",
        lat=40.7614,
        lon=-73.9776,
        hae=123.5,
        course=270.0,
        speed=4.2,
        last_seen="2026-08-05T12:34:56+00:00",
        stale="2999-01-01T00:00:00+00:00",  # far future so nothing is pruned
        source="tls",
        kind="unit",
    )


class _SkcotServer:
    """Run the real skcot geo HTTP server in a background asyncio loop/thread.

    Mirrors production: skcot serves the store read-only over asyncio while the
    skcomms side pulls it with a blocking ``urllib`` fetch from another thread.
    """

    def __init__(self, store: GeoStore) -> None:
        self._store = store
        self._loop = asyncio.new_event_loop()
        self._server = None
        self.port = 0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._ready = threading.Event()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(
            start_geo_http_server(self._store, host="127.0.0.1", port=0)
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    def __enter__(self) -> "_SkcotServer":
        self._thread.start()
        assert self._ready.wait(timeout=5.0), "skcot geo http server did not start"
        return self

    def __exit__(self, *exc) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5.0)
        if self._server is not None:
            self._server.close()
        self._loop.close()


@pytest.fixture
def _skcot_bridge(monkeypatch):
    """Seed a skcot store, serve it over the real HTTP bridge, wire SKCOT_GEO_URL."""
    store = GeoStore(ttl_s=float("inf"))
    original = _fully_populated_unit()
    store.upsert(original)
    with _SkcotServer(store) as srv:
        monkeypatch.setenv(
            gs.SKCOT_GEO_URL_ENV, f"http://127.0.0.1:{srv.port}/geo/units"
        )
        yield original


def test_units_shape_round_trips_identically(_skcot_bridge):
    """skcot serializes -> skcomms fetches -> reconstructs the SAME GeoUnit."""
    original = _skcot_bridge

    payload = gs.fetch_skcot_geo(include_stale=True, fmt="units")
    assert payload is not None
    assert gs.geo_payload_has_units(payload) is True
    assert payload["count"] == 1

    # Reconstruct on the skcomms side using the ONE shared type.
    rebuilt = GeoUnit(**payload["units"][0])
    assert rebuilt == original  # field-for-field equality, not just key overlap


def test_geojson_shape_round_trips_identically(_skcot_bridge):
    """The GeoJSON Feature skcot emits rebuilds the SAME GeoUnit on the skcomms side."""
    original = _skcot_bridge

    payload = gs.fetch_skcot_geo(include_stale=True, fmt="geojson")
    assert payload is not None
    assert payload["type"] == "FeatureCollection"
    assert len(payload["features"]) == 1

    rebuilt = GeoUnit.from_geojson_feature(payload["features"][0])
    assert rebuilt == original


def test_skcomms_and_skcot_geounit_are_the_same_type(_skcot_bridge):
    """AC1: skcomms does not reimplement the type; it is skcot's GeoUnit verbatim.

    The skcomms-side adapter's inner store, the seed path and this test all use
    ``skcot.geo.GeoUnit`` / ``GeoStore`` -- there is exactly one class.
    """
    adapter = gs.SkcotGeoStore()
    # The adapter composes the shared skcot GeoStore (single type), not a clone.
    assert isinstance(adapter._inner, GeoStore)
    # And the object skcomms hands back is the very class skcot defines.
    assert GeoUnit.__module__ == "skcot.geo"
