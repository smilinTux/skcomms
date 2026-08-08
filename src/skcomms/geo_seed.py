"""Fleet self-seed for the SKMap geo store (``GET /api/v1/geo/units``).

Why this exists
---------------
The situational picture served by ``/api/v1/geo/units`` is fed by the CoT
(Cursor-on-Target) plane. On this fleet the live CoT service (``skcot.service``,
TAK/ATAK streaming on :8087/:8089/:6969) runs as a **separate process** with its
own in-memory ``GeoStore``; it only fills up when a real ATAK/iTAK device (or a
federated peer's CoT) actually beacons a position. Until a device connects, that
store -- and therefore the ``skcomms-api`` process's own ``get_geo_store()`` -- is
empty, so the Flutter ``skmap`` pane shows nothing.

This module upserts the **sovereign fleet nodes** as CoT units so the map is not
empty and the whole plumbing (``upsert_from_cot`` -> store -> endpoint ->
``GeoUnit.fromJson``) is demonstrably working end to end. It is fed through the
*real* :meth:`skcot.geo.GeoStore.upsert_from_cot` path (building genuine
:class:`skcot.codec.CotEvent` atoms), not a shortcut, so it exercises exactly the
code a live feed uses. On a deployment without ``skcot`` installed it falls back
to the store's plain ``upsert`` so the seed still lands.

Clearly a seed, not real telemetry
-----------------------------------
Every seeded entity is unmistakable as a placeholder:

  * ``uid`` / ``callsign`` are prefixed ``fleet:`` (e.g. ``fleet:chiap08``),
  * ``source`` is ``"seed:self"``,
  * coordinates are **placeholders** -- these compute nodes have no GPS. They are
    spread out only so the markers don't stack on the map.

Replacing the seed with a real CoT feed
---------------------------------------
When a real position feed is wired (an ATAK/iTAK device connecting to
``skcot.service``, or CoT federated in from a peer), those live units flow into
the same store and supersede-by-``uid``. The seed units keep their ``fleet:``
uids and simply coexist; set ``SKCOMMS_GEO_SEED_FLEET=0`` to turn the seed off
entirely once real telemetry is present.

Enablement
----------
Off by default (the empty-store contract stays intact for anything that doesn't
opt in). Set ``SKCOMMS_GEO_SEED_FLEET`` to a truthy value (``1``/``true``/``yes``/
``on``) to have the ``skcomms-api`` lifespan seed the fleet on startup.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Env flag that opts the api-server lifespan into seeding the fleet on startup.
SEED_ENV = "SKCOMMS_GEO_SEED_FLEET"

# Attribution tag stored on each seeded unit's ``GeoUnit.source``.
SEED_SOURCE = "seed:self"

# CoT type for a friendly ground unit (atom -> classified as ``kind='unit'``).
_FLEET_COT_TYPE = "a-f-G-U-C"


# Known sovereign fleet nodes. ``lat``/``lon`` are PLACEHOLDERS (these nodes have
# no GPS); they are only spread apart so seeded markers are individually visible.
# ``hint`` is the tailscale/LAN address for human reference (not a GeoUnit field).
_FLEET_NODES: list[dict[str, Any]] = [
    {
        "name": "noroc2027",
        "hint": "100.108.59.57 / .158 dev+primary (this host)",
        "lat": 39.0000,
        "lon": -77.0000,
    },
    {
        "name": "dot100",
        "hint": "192.168.0.100 RTX 5060 Ti / inference",
        "lat": 39.0200,
        "lon": -77.0200,
    },
    {
        "name": "dot41",
        "hint": "100.86.156.5 / .41 tailscale-only heavy-build",
        "lat": 38.9800,
        "lon": -77.0200,
    },
    {"name": "chiap08", "hint": "100.81.238.58 terminal node", "lat": 39.0200, "lon": -76.9800},
]


def is_seed_enabled() -> bool:
    """Whether the fleet self-seed is opted in via :data:`SEED_ENV`."""
    return os.environ.get(SEED_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _upsert_node(store: Any, node: dict[str, Any]) -> Optional[str]:
    """Upsert a single fleet node into *store*; return its uid or ``None``.

    Feeds through the real ``upsert_from_cot`` path (a genuine CoT atom) when the
    ``skcot`` plane is available, else falls back to the store's plain ``upsert``
    (used by the in-process fallback store). Fails soft: logs and returns
    ``None`` on any error so one bad node can't abort the whole seed.
    """
    name = node["name"]
    uid = f"fleet:{name}"
    lat, lon = float(node["lat"]), float(node["lon"])
    try:
        try:
            # Real path: build a CoT atom and let the geo plane classify + store it.
            from skcot.codec import CotEvent, CotPoint

            cot = CotEvent(
                uid=uid,
                type=_FLEET_COT_TYPE,
                how="m-g",
                point=CotPoint(lat=lat, lon=lon),
                callsign=uid,
            )
            unit = store.upsert_from_cot(cot, source=SEED_SOURCE)
            # upsert_from_cot returns None only if it classified the event as
            # non-mappable; an ``a-*`` atom with a real fix never does.
            return getattr(unit, "uid", uid) if unit is not None else None
        except (ImportError, NotImplementedError):
            # Fallback store (no skcot): upsert a plain GeoUnit-shaped dict.
            store.upsert(
                {
                    "uid": uid,
                    "callsign": uid,
                    "cot_type": _FLEET_COT_TYPE,
                    "lat": lat,
                    "lon": lon,
                    "kind": "unit",
                    "source": SEED_SOURCE,
                }
            )
            return uid
    except Exception as exc:  # noqa: BLE001 — one bad node must not abort the seed
        logger.warning("geo seed: could not upsert %s (%s): %s", uid, node.get("hint"), exc)
        return None


def seed_fleet(store: Any = None) -> list[str]:
    """Upsert the sovereign fleet nodes as seed CoT units into *store*.

    Idempotent: entities are keyed by ``uid`` (``fleet:<name>``), so re-running
    updates in place rather than duplicating. Returns the list of upserted uids.

    Args:
        store: The geo store to seed. Defaults to the process-global store from
            :func:`skcomms.geo_store.get_geo_store` (the one the endpoint reads).
    """
    if store is None:
        from .geo_store import get_geo_store

        store = get_geo_store()
    uids = [uid for node in _FLEET_NODES if (uid := _upsert_node(store, node))]
    logger.info("geo seed: upserted %d fleet unit(s): %s", len(uids), uids)
    return uids


def seed_fleet_if_enabled(store: Any = None) -> list[str]:
    """Seed the fleet only when :data:`SEED_ENV` is opted in; else a no-op.

    The startup hook: safe to call unconditionally from the api-server lifespan.
    Returns the upserted uids (empty when the seed is not enabled).
    """
    if not is_seed_enabled():
        logger.info("geo seed: %s not set — fleet self-seed disabled", SEED_ENV)
        return []
    return seed_fleet(store)
