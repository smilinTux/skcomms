"""Tests for the fleet self-seed (``skcomms.geo_seed``) end to end.

Proves the plumbing the skmap pane depends on: seeding the sovereign fleet
upserts real units into the process-global geo store, and ``GET
/api/v1/geo/units`` then returns them in the flat shape ``GeoUnit.fromJson``
reads. Also covers the opt-in gate and idempotency.
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
    # Disable the live skcot bridge so the seed/local path is what is asserted
    # here (the bridge is covered in test_api_geo_skcot_bridge).
    monkeypatch.setenv("SKCOT_GEO_URL", "")

    import skcomms.api as api

    importlib.reload(api)
    return TestClient(api.app)


def _fresh_fallback_store(gs):
    """Install a fresh fallback store as the singleton (deterministic shape)."""
    store = gs.SkcotGeoStore()
    gs.set_geo_store(store)
    return store


def test_seed_fleet_flows_to_endpoint(tmp_path, monkeypatch):
    """seed_fleet() -> GET /api/v1/geo/units returns the fleet units."""
    import skcomms.geo_seed as seed
    import skcomms.geo_store as gs

    _fresh_fallback_store(gs)
    uids = seed.seed_fleet()  # feed the process-global store
    assert len(uids) >= 1
    assert all(u.startswith("fleet:") for u in uids)

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1
    got = {u["uid"] for u in body["units"]}
    assert set(uids) <= got

    # Each unit carries the flat keys GeoUnit.fromJson reads, tagged as a seed.
    unit = next(u for u in body["units"] if u["uid"] in uids)
    assert unit["callsign"].startswith("fleet:")
    assert unit["cot_type"] == "a-f-G-U-C"
    assert isinstance(unit["lat"], float) and isinstance(unit["lon"], float)
    assert unit["source"] == "seed:self"


def test_seed_is_idempotent(tmp_path, monkeypatch):
    """Re-seeding keys by uid — no duplicate units accumulate."""
    import skcomms.geo_seed as seed
    import skcomms.geo_store as gs

    _fresh_fallback_store(gs)
    first = seed.seed_fleet()
    second = seed.seed_fleet()
    assert first == second

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    uids = [u["uid"] for u in resp.json()["units"]]
    assert len(uids) == len(set(uids)) == len(first)


def test_seed_gate_off_by_default(tmp_path, monkeypatch):
    """Without SKCOMMS_GEO_SEED_FLEET the lifespan seeds nothing (empty map)."""
    import skcomms.geo_seed as seed
    import skcomms.geo_store as gs

    monkeypatch.delenv(seed.SEED_ENV, raising=False)
    _fresh_fallback_store(gs)
    assert seed.is_seed_enabled() is False
    assert seed.seed_fleet_if_enabled() == []

    # The app built with the gate off leaves the endpoint empty.
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.json() == {"units": [], "count": 0}


def test_seed_gate_on_seeds_and_endpoint_reflects_it(tmp_path, monkeypatch):
    """With the gate on, the startup hook seeds and the endpoint reflects it.

    Exercises the exact call the api-server lifespan makes
    (``seed_fleet_if_enabled``), then asserts the endpoint publishes the result.
    (The app's lifespan only runs under a ``with TestClient(...)`` context; the
    other tests here deliberately build the client without it, so we call the
    hook directly to prove the gate + endpoint wiring.)
    """
    import skcomms.geo_seed as seed
    import skcomms.geo_store as gs

    monkeypatch.setenv(seed.SEED_ENV, "1")
    _fresh_fallback_store(gs)
    assert seed.is_seed_enabled() is True

    seeded = seed.seed_fleet_if_enabled()  # what lifespan calls on startup
    assert len(seeded) >= 1

    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/geo/units")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1
