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

One shared type
---------------
There is a single ``GeoUnit`` / ``GeoStore`` type, and it lives in
:mod:`skcot.geo` (the authoritative, CoT-fed store). This module does **not**
reimplement it. :class:`SkcotGeoStore` is a *thin adapter* over that shared
type: it holds a real :class:`skcot.geo.GeoStore` and delegates everything to
it, adding only one skcomms-side convenience -- dict-coercion on ``upsert`` so
the fleet self-seed (and tests) can feed plain GeoUnit-shaped dicts. All
storage, staleness, GeoJSON serialization and CoT classification come from the
shared skcot type, so the two processes agree on unit serialization by
construction (a GeoUnit serialized by skcot deserializes identically here).

The local adapter store is only ever the *fallback* the endpoint reads when the
live skcot HTTP bridge (:func:`fetch_skcot_geo`) has no units; it is seeded with
sovereign fleet placeholders that must not expire, so its inner store is built
with an infinite TTL (the real freshness clock lives on the live skcot store
behind the HTTP bridge).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.parse
import urllib.request
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
# Thin adapter over the ONE shared skcot GeoStore type.
# --------------------------------------------------------------------------


class SkcotGeoStore:
    """Thin skcomms-side adapter over the shared :class:`skcot.geo.GeoStore`.

    This is **not** a reimplementation. It composes a real
    :class:`skcot.geo.GeoStore` (the single shared type -- CoT classification,
    staleness/TTL, GeoJSON serialization, federation envelopes all live there)
    and delegates every attribute to it via :meth:`__getattr__`. The only thing
    it adds is dict-coercion on :meth:`upsert`, so the fleet self-seed and the
    API can feed plain GeoUnit-shaped dicts as well as real
    :class:`skcot.geo.GeoUnit` objects.

    ``skcot`` is imported lazily (in ``__init__``) rather than at module import
    time: ``skcot`` depends on ``skcomms``, so a top-level import here would be a
    packaging cycle. Because this module is itself imported lazily (only from the
    endpoint / seed paths, after ``skcomms`` has fully loaded), the lazy import
    resolves cleanly.

    The inner store is built with an infinite TTL by default: the local store is
    only the endpoint's *fallback* (fleet-seed placeholders that must not
    expire); the authoritative freshness clock lives on the live skcot store
    reached over the HTTP bridge.
    """

    def __init__(self, inner: Any = None, *, ttl_s: float = float("inf")) -> None:
        if inner is None:
            from skcot.geo import GeoStore  # type: ignore  # lazy: avoid dep cycle

            inner = GeoStore(ttl_s=ttl_s)
        self._inner = inner

    def upsert(self, unit: Any) -> Any:
        """Upsert a :class:`skcot.geo.GeoUnit` or a GeoUnit-shaped dict.

        A dict is coerced into the shared :class:`skcot.geo.GeoUnit` (unknown
        keys dropped) so the whole store speaks one type; then it is stored by
        the shared store verbatim.
        """
        if isinstance(unit, dict):
            from skcot.geo import GeoUnit  # type: ignore  # lazy: avoid dep cycle

            fields = set(GeoUnit.model_fields)
            unit = GeoUnit(**{k: v for k, v in unit.items() if k in fields})
        return self._inner.upsert(unit)

    def __getattr__(self, name: str) -> Any:
        # Delegate everything else (upsert_from_cot, units_json,
        # to_feature_collection, get_all, remove, clear, ...) to the shared
        # skcot store. Only reached for names not defined on the adapter.
        return getattr(self._inner, name)


# --------------------------------------------------------------------------
# Process-global accessor.
# --------------------------------------------------------------------------

_store_lock = threading.Lock()
_store: Any = None


def _new_store() -> Any:
    """Construct the process-global local store: the shared skcot GeoStore,
    wrapped in the thin :class:`SkcotGeoStore` adapter."""
    return SkcotGeoStore()


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
