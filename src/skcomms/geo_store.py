"""Geo / situational-awareness store accessor for the SKComms daemon.

Serves ``GET /api/v1/geo/units`` (the backend half of the Flutter ``skmap``
pane). The situational picture, where every unit / marker / waypoint is, is
produced by the CoT (Cursor-on-Target) bridge, which now lives in the extracted
``skcot`` package. This module exposes a single **process-global** store that:

  * the CoT bridge / service FEEDS  →
        ``get_geo_store().upsert_from_cot(cot, source=...)``
    (or ``.upsert(unit)`` for a pre-built / federated entity), and
  * the ``/api/v1/geo/units`` endpoint READS →
        ``get_geo_store().units_json(include_stale=...)``.

That single accessor is the documented seam for wiring the real position feed:
whoever runs the CoT service inside (or alongside) the daemon upserts into the
store returned by :func:`get_geo_store`, and the endpoint publishes it.

Backend selection:
  * If ``skcot`` is importable its full :class:`skcot.geo.GeoStore` is used
    verbatim (CoT classification, staleness/TTL, GeoJSON, federation
    envelopes).
  * Otherwise a minimal in-process fallback with the *same* ``units_json`` /
    ``to_feature_collection`` / ``upsert`` contract keeps the endpoint
    functional, it just returns the currently-known set (which may be empty)
    rather than 500-ing when the geo plane is not installed.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("skcomms.geo_store")

# --------------------------------------------------------------------------
# Live skcot bridge (source of truth = skcot's process, not this one).
# --------------------------------------------------------------------------
#
# The real situational picture lives in the `skcot` service process (fed from
# TCP/TLS/mesh CoT + federation). That process exposes it read-only over HTTP
# (`skcot.geo_http`, default 127.0.0.1:8091). When that endpoint is reachable
# AND has units, it is the source of truth; otherwise we fall back to this
# process's local store (the opt-in fleet seed), so the map endpoint always
# returns a valid shape and never 500s.

SKCOT_GEO_URL_ENV = "SKCOT_GEO_URL"
DEFAULT_SKCOT_GEO_URL = "http://127.0.0.1:8091/geo/units"
SKCOT_GEO_TIMEOUT_ENV = "SKCOT_GEO_TIMEOUT_S"
DEFAULT_SKCOT_GEO_TIMEOUT_S = 0.75


def skcot_geo_url() -> Optional[str]:
    """The skcot geo endpoint URL, or None if the bridge is disabled.

    Defaults to :data:`DEFAULT_SKCOT_GEO_URL`. Set ``SKCOT_GEO_URL`` to an empty
    string to disable the bridge and serve only the local in-process store.
    """
    url = os.environ.get(SKCOT_GEO_URL_ENV, DEFAULT_SKCOT_GEO_URL)
    return url or None


def _skcot_geo_timeout() -> float:
    try:
        return float(os.environ.get(SKCOT_GEO_TIMEOUT_ENV, DEFAULT_SKCOT_GEO_TIMEOUT_S))
    except (TypeError, ValueError):
        return DEFAULT_SKCOT_GEO_TIMEOUT_S


def fetch_skcot_geo(*, include_stale: bool = False, fmt: str = "units") -> Optional[Any]:
    """Fetch the live situational picture from skcot's HTTP endpoint.

    Blocking (stdlib ``urllib``) with a short timeout; call from an async
    handler via ``asyncio.to_thread`` so the event loop is never blocked.

    Returns the parsed JSON payload (a ``{"units": [...], "count": N}`` dict for
    ``fmt="units"``, a GeoJSON ``FeatureCollection`` for ``fmt="geojson"``), or
    ``None`` on ANY failure (bridge disabled, connection refused, timeout,
    non-200, unparseable body). Fail-soft: never raises to the caller.
    """
    url = skcot_geo_url()
    if not url:
        return None
    params: dict[str, str] = {}
    if include_stale:
        params["include_stale"] = "1"
    if fmt == "geojson":
        params["format"] = "geojson"
    if params:
        sep = "&" if urllib.parse.urlsplit(url).query else "?"
        url = url + sep + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=_skcot_geo_timeout()) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            body = resp.read()
        return json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - map endpoint must never 500 on this
        logger.debug("skcot geo fetch failed (%s): %s", url, exc)
        return None


def geo_payload_has_units(payload: Any) -> bool:
    """Whether a skcot geo payload actually carries at least one unit.

    Handles both response shapes: the flat ``{"units": [...], "count": N}`` and
    the GeoJSON ``{"type": "FeatureCollection", "features": [...]}``.
    """
    if not isinstance(payload, dict):
        return False
    units = payload.get("units")
    if isinstance(units, list):
        return len(units) > 0
    feats = payload.get("features")
    if isinstance(feats, list):
        return len(feats) > 0
    return False

# --------------------------------------------------------------------------
# Minimal fallback store (used only when `skcot` is not installed).
# --------------------------------------------------------------------------


class _FallbackGeoStore:
    """A tiny thread-safe stand-in for :class:`skcot.geo.GeoStore`.

    Implements just the surface the daemon needs: ``upsert`` (dict or object
    with ``uid``), ``units_json`` and ``to_feature_collection``. It performs no
    CoT classification or staleness pruning, it simply holds the last-known
    dict per ``uid`` so the endpoint has a real, feedable store even on a
    deployment without the ``skcot`` geo plane.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._units: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _as_dict(unit: Any) -> dict[str, Any]:
        if isinstance(unit, dict):
            d = dict(unit)
        elif hasattr(unit, "model_dump"):
            d = unit.model_dump(mode="json")
        else:
            raise TypeError(f"cannot store geo unit of type {type(unit)!r}")
        d.setdefault(
            "last_seen", datetime.now(timezone.utc).isoformat()
        )
        return d

    def upsert(self, unit: Any) -> dict[str, Any]:
        d = self._as_dict(unit)
        uid = str(d.get("uid") or d.get("id") or "")
        if not uid:
            raise ValueError("geo unit requires a non-empty 'uid'")
        d["uid"] = uid
        with self._lock:
            self._units[uid] = d
        return d

    def upsert_from_cot(self, cot: Any, *, source: Optional[str] = None):  # pragma: no cover - no CoT plane
        raise NotImplementedError(
            "CoT ingest requires the 'skcot' package; install it to feed the "
            "geo store from live CoT events."
        )

    def remove(self, uid: str) -> bool:
        with self._lock:
            return self._units.pop(uid, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._units.clear()

    def units_json(self, *, include_stale: bool = False) -> list[dict[str, Any]]:
        # The fallback keeps no staleness clock, so `include_stale` is a no-op:
        # every known unit is returned.
        with self._lock:
            return [dict(u) for u in self._units.values()]

    def to_feature_collection(self, *, include_stale: bool = False) -> dict[str, Any]:
        feats = []
        for u in self.units_json(include_stale=include_stale):
            props = {k: v for k, v in u.items() if k not in ("lat", "lon")}
            feats.append(
                {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [u.get("lon", 0.0), u.get("lat", 0.0)],
                    },
                    "properties": props,
                }
            )
        return {"type": "FeatureCollection", "features": feats}


# --------------------------------------------------------------------------
# Process-global accessor.
# --------------------------------------------------------------------------

_store_lock = threading.Lock()
_store: Any = None


def _new_store() -> Any:
    """Construct the best available store: real skcot GeoStore, else fallback."""
    try:
        from skcot.geo import GeoStore  # type: ignore

        return GeoStore()
    except Exception:
        return _FallbackGeoStore()


def get_geo_store() -> Any:
    """Return the process-global geo store singleton (creating it on first use).

    This is the **feed point**: the CoT service upserts into the returned store
    (``upsert_from_cot`` / ``upsert``) and the endpoint reads from it. One store
    per process keeps the daemon's map view and any co-resident agent tool
    reading the same ground truth.
    """
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = _new_store()
    return _store


def set_geo_store(store: Any) -> None:
    """Inject a store (used by the CoT service to share its own GeoStore, and
    by tests to seed a known picture)."""
    global _store
    with _store_lock:
        _store = store


def reset_geo_store() -> None:
    """Drop the singleton so the next :func:`get_geo_store` rebuilds it (tests)."""
    global _store
    with _store_lock:
        _store = None
