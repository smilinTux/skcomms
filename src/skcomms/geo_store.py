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

import threading
from datetime import datetime, timezone
from typing import Any, Optional

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
