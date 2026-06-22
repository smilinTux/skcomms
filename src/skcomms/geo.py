"""[CoT][CB4] Geo / situational-awareness plane.

The CoT bridge (CB1-CB3) speaks TAK on the wire; CB4 turns that raw event
stream into a **ground-truth picture**: a thread-safe store of where every unit,
marker and waypoint is, kept fresh from every CoT the node receives (mesh + TLS
+ federation). It is the backend half of `[skfed][LIBERATE] skmap` — the
Flutter map and the LUMINA agent both read the same store instead of each
re-deriving positions ad-hoc.

What lives here:

  * :class:`GeoUnit` — a normalized, JSON-friendly entity (unit / marker /
    waypoint) distilled from a :class:`~skcomms.cot.CotEvent`.
  * :class:`GeoStore` — thread-safe upsert/query/prune over those entities.
    ``upsert_from_cot`` classifies by CoT type and skips chat/ping/empty.
    ``situational_summary`` renders a short LLM-readable brief (what
    ``cot_agent`` feeds the model); ``units_json`` is the machine view (what a
    map client renders).
  * :func:`geo_to_envelope` / :func:`envelope_to_geounits` — wrap a
    :class:`GeoUnit` (or the whole store) as a canonical signed-able
    :class:`~skcomms.envelope.Envelope` carrying ``application/geo+json`` so
    positions/markers can ride the federation S2S path to peer nodes, not just
    the local LAN mesh.

In-memory is the v1 source of truth (positions are inherently ephemeral and
re-beaconed); persistence, if ever wanted, is a best-effort cache on top.
"""

from __future__ import annotations

import json
import math
import threading
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from .cot import CotEvent, CotPoint, to_cot
from .envelope import Envelope

GEO_CONTENT_TYPE = "application/geo+json"
GEO_BROADCAST = "*"

# CoT's "unknown" sentinel (hae/ce/le, and we treat it as no-altitude).
_COT_UNKNOWN = 9999999.0
# Default TTL (seconds) when a CoT carries no usable stale time.
DEFAULT_TTL_S = 300.0


def _utc_iso(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(timezone.utc)).isoformat()


def _parse_iso(s: str) -> Optional[datetime]:
    """Best-effort ISO-8601 parse → aware UTC datetime, or None."""
    if not s:
        return None
    try:
        v = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def classify_cot(cot_type: str) -> Optional[str]:
    """Classify a CoT type into a geo ``kind`` — or None to skip.

    Returns ``'unit'``, ``'marker'``, ``'waypoint'``, or None for things that
    aren't map entities (chat ``b-t-f``, TAK ping ``t-x-c-t``, empty type).

    Taxonomy (MIL-STD-2525-ish):
      * ``a-*``     atoms (friendly/hostile/neutral units, sensors) → unit
      * ``b-m-p-w`` map·point·waypoint → waypoint
      * ``b-m-p-c`` route control points → waypoint
      * ``b-m-*``   other map graphics / dropped markers → marker
      * ``b-t-f``   GeoChat → skip
      * ``t-x-c-t`` ping/pong + other ``t-x-*`` transients → skip
    """
    t = (cot_type or "").strip()
    if not t:
        return None
    if t.startswith("b-t-f"):  # GeoChat
        return None
    if t.startswith("t-x-") or t.startswith("t-b-"):  # tasking/transient (ping etc.)
        return None
    if t.startswith("a-"):  # atom: any unit/entity with a position
        return "unit"
    if t.startswith("b-m-p-w") or t.startswith("b-m-p-c"):  # waypoint / route point
        return "waypoint"
    if t.startswith("b-m-"):  # dropped marker / map graphic
        return "marker"
    if t.startswith("b-"):  # other bits payloads (treat as marker, not chat)
        return "marker"
    return None


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers."""
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


class GeoUnit(BaseModel):
    """A normalized geo entity on the situational picture.

    Attributes:
        uid: CoT entity uid (stable per entity/marker).
        callsign: Human label (contact callsign) if known; falls back to uid.
        cot_type: Originating CoT type (kept for icon/affiliation rendering).
        lat/lon: WGS-84 degrees.
        hae: Height above ellipsoid (m); None when unknown.
        course: Heading in degrees (0-360), if reported.
        speed: Ground speed (m/s), if reported.
        last_seen: ISO-8601 UTC of the last update.
        stale: ISO-8601 UTC when this fix expires (from the CoT), if known.
        source: Where the fix came from (node FQID / device id / 'mesh' / 'tls').
        kind: ``'unit'`` | ``'marker'`` | ``'waypoint'``.
    """

    uid: str
    callsign: str
    cot_type: str = "a-f-G-U-C"
    lat: float
    lon: float
    hae: Optional[float] = None
    course: Optional[float] = None
    speed: Optional[float] = None
    last_seen: str = Field(default_factory=_utc_iso)
    stale: Optional[str] = None
    source: Optional[str] = None
    kind: str = "unit"

    @property
    def label(self) -> str:
        return self.callsign or self.uid

    def age_seconds(self, now: Optional[datetime] = None) -> Optional[float]:
        """Seconds since ``last_seen`` (None if unparseable)."""
        seen = _parse_iso(self.last_seen)
        if seen is None:
            return None
        return ((now or datetime.now(timezone.utc)) - seen).total_seconds()

    def is_stale(self, now: Optional[datetime] = None, *, ttl_s: float = DEFAULT_TTL_S) -> bool:
        """Whether this fix has expired (past CoT stale, or older than TTL)."""
        now = now or datetime.now(timezone.utc)
        st = _parse_iso(self.stale) if self.stale else None
        if st is not None:
            return now >= st
        age = self.age_seconds(now)
        return age is not None and age > ttl_s

    def to_geojson_feature(self) -> dict:
        """Render as a GeoJSON Feature (Point) with geo properties.

        GeoJSON is ``[lon, lat]`` order. Custom fields live under
        ``properties`` so any GeoJSON consumer still renders the point.
        """
        props = {
            "uid": self.uid,
            "callsign": self.callsign,
            "cot_type": self.cot_type,
            "kind": self.kind,
            "last_seen": self.last_seen,
        }
        if self.hae is not None:
            props["hae"] = self.hae
        if self.course is not None:
            props["course"] = self.course
        if self.speed is not None:
            props["speed"] = self.speed
        if self.stale is not None:
            props["stale"] = self.stale
        if self.source is not None:
            props["source"] = self.source
        return {
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [self.lon, self.lat]},
            "properties": props,
        }

    @classmethod
    def from_geojson_feature(cls, feat: dict) -> "GeoUnit":
        """Reconstruct a :class:`GeoUnit` from a GeoJSON Feature."""
        geom = feat.get("geometry") or {}
        coords = geom.get("coordinates") or [0.0, 0.0]
        props = feat.get("properties") or {}
        lon, lat = float(coords[0]), float(coords[1])
        return cls(
            uid=props.get("uid", ""),
            callsign=props.get("callsign") or props.get("uid", ""),
            cot_type=props.get("cot_type", "a-f-G-U-C"),
            lat=lat,
            lon=lon,
            hae=props.get("hae"),
            course=props.get("course"),
            speed=props.get("speed"),
            last_seen=props.get("last_seen") or _utc_iso(),
            stale=props.get("stale"),
            source=props.get("source"),
            kind=props.get("kind", "unit"),
        )

    @classmethod
    def from_cot(cls, cot: CotEvent, *, source: Optional[str] = None) -> Optional["GeoUnit"]:
        """Build a :class:`GeoUnit` from a CoT event, or None if not mappable.

        Returns None for chat/ping/empty types and for events with no usable
        position (both lat and lon zero is treated as "no fix").
        """
        kind = classify_cot(cot.type)
        if kind is None:
            return None
        lat, lon = cot.point.lat, cot.point.lon
        if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
            return None
        if lat == 0.0 and lon == 0.0:  # CoT "no fix" placeholder
            return None
        hae = None if cot.point.hae >= _COT_UNKNOWN else cot.point.hae
        course, speed = _track_from_detail(cot.detail_xml)
        return cls(
            uid=cot.uid,
            callsign=cot.callsign or cot.uid,
            cot_type=cot.type,
            lat=lat,
            lon=lon,
            hae=hae,
            course=course,
            speed=speed,
            last_seen=_utc_iso(),
            stale=cot.stale or None,
            source=source,
            kind=kind,
        )

    def to_cot(self) -> CotEvent:
        """Reconstruct a minimal CoT event for re-emission on the wire."""
        return CotEvent(
            uid=self.uid,
            type=self.cot_type,
            how="m-g",
            point=CotPoint(
                lat=self.lat,
                lon=self.lon,
                hae=self.hae if self.hae is not None else _COT_UNKNOWN,
            ),
            stale=self.stale or _utc_iso(),
            callsign=self.callsign if self.callsign != self.uid else None,
        )


def _track_from_detail(detail_xml: str) -> tuple[Optional[float], Optional[float]]:
    """Extract (course, speed) from a CoT ``<track>`` detail element."""
    if not detail_xml or "<track" not in detail_xml:
        return None, None
    import xml.etree.ElementTree as ET

    try:
        det = ET.fromstring(f"<detail>{detail_xml}</detail>")
    except ET.ParseError:
        return None, None
    trk = det.find("track")
    if trk is None:
        return None, None

    def _f(k):
        v = trk.get(k)
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    return _f("course"), _f("speed")


class GeoStore:
    """Thread-safe in-memory store of the current situational picture.

    Keyed by CoT ``uid`` (the stable per-entity identity). Feed it every
    received CoT via :meth:`upsert_from_cot`; query via :meth:`get_all`,
    :meth:`get`, :meth:`nearest`; render for an LLM via
    :meth:`situational_summary` or for a map via :meth:`units_json`.

    Args:
        ttl_s: Default TTL (seconds) for fixes that carry no CoT stale time.
    """

    def __init__(self, *, ttl_s: float = DEFAULT_TTL_S) -> None:
        self._ttl_s = ttl_s
        self._lock = threading.RLock()
        self._units: dict[str, GeoUnit] = {}

    # --- ingest -----------------------------------------------------------
    def upsert_from_cot(self, cot: CotEvent, *, source: Optional[str] = None) -> Optional[GeoUnit]:
        """Classify + upsert a CoT event. Returns the stored GeoUnit, or None.

        None means the event was skipped (chat / ping / no position).
        """
        unit = GeoUnit.from_cot(cot, source=source)
        if unit is None:
            return None
        with self._lock:
            self._units[unit.uid] = unit
        return unit

    def upsert(self, unit: GeoUnit) -> GeoUnit:
        """Upsert a pre-built :class:`GeoUnit` (e.g. from a federation peer)."""
        with self._lock:
            self._units[unit.uid] = unit
        return unit

    def remove(self, uid: str) -> bool:
        with self._lock:
            return self._units.pop(uid, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._units.clear()

    # --- query ------------------------------------------------------------
    def get_all(self, *, kind: Optional[str] = None, include_stale: bool = False) -> list[GeoUnit]:
        """All units (optionally filtered by kind / excluding stale)."""
        now = datetime.now(timezone.utc)
        with self._lock:
            units = list(self._units.values())
        out = []
        for u in units:
            if kind is not None and u.kind != kind:
                continue
            if not include_stale and u.is_stale(now, ttl_s=self._ttl_s):
                continue
            out.append(u)
        return out

    def get(self, callsign_or_uid: str) -> Optional[GeoUnit]:
        """Look up by uid first, then by (case-insensitive) callsign."""
        with self._lock:
            u = self._units.get(callsign_or_uid)
            if u is not None:
                return u
            needle = callsign_or_uid.casefold()
            for u in self._units.values():
                if u.callsign.casefold() == needle:
                    return u
        return None

    def nearest(self, lat: float, lon: float, n: int = 5, *, kind: Optional[str] = None) -> list[GeoUnit]:
        """The ``n`` non-stale units nearest (lat, lon), closest first."""
        units = self.get_all(kind=kind)
        units.sort(key=lambda u: _haversine_km(lat, lon, u.lat, u.lon))
        return units[:n]

    def count(self, *, include_stale: bool = True) -> int:
        return len(self.get_all(include_stale=include_stale))

    # --- maintenance ------------------------------------------------------
    def prune_stale(self) -> int:
        """Drop expired fixes. Returns the number removed."""
        now = datetime.now(timezone.utc)
        with self._lock:
            dead = [uid for uid, u in self._units.items() if u.is_stale(now, ttl_s=self._ttl_s)]
            for uid in dead:
                del self._units[uid]
        return len(dead)

    # --- rendering --------------------------------------------------------
    def situational_summary(self, *, around: Optional[tuple[float, float]] = None, limit: int = 12) -> str:
        """A short, LLM-readable brief of the current picture.

        e.g. ``"PURE at 41.13700,-73.42400 (12s ago); marker RP-Alpha at
        39.00000,-77.50000. 2 unit(s), 1 marker(s)."``  When ``around`` is
        given, units are ordered nearest-first to that anchor.
        """
        units = self.get_all()
        if not units:
            return "No units reported on the net yet."
        if around is not None:
            la, lo = around
            units.sort(key=lambda u: _haversine_km(la, lo, u.lat, u.lon))
        else:
            units.sort(key=lambda u: u.age_seconds() or 0.0)
        parts = []
        for u in units[:limit]:
            age = u.age_seconds()
            age_s = f" ({int(age)}s ago)" if age is not None else ""
            prefix = "" if u.kind == "unit" else f"{u.kind} "
            parts.append(f"{prefix}{u.label} at {u.lat:.5f},{u.lon:.5f}{age_s}")
        nU = sum(1 for u in units if u.kind == "unit")
        nM = sum(1 for u in units if u.kind == "marker")
        nW = sum(1 for u in units if u.kind == "waypoint")
        tally = f"{nU} unit(s), {nM} marker(s), {nW} waypoint(s)."
        return "; ".join(parts) + ". " + tally

    def units_json(self, *, include_stale: bool = False) -> list[dict]:
        """Machine view: a list of GeoUnit dicts (for an agent tool / API)."""
        return [u.model_dump(mode="json") for u in self.get_all(include_stale=include_stale)]

    def to_feature_collection(self, *, include_stale: bool = False) -> dict:
        """The whole picture as a GeoJSON FeatureCollection (for the map)."""
        return {
            "type": "FeatureCollection",
            "features": [u.to_geojson_feature() for u in self.get_all(include_stale=include_stale)],
        }


# --- federation envelope (application/geo+json) ----------------------------


def geo_to_envelope(
    unit_or_units: GeoUnit | list[GeoUnit],
    *,
    from_fqid: str,
    to_fqid: str = GEO_BROADCAST,
) -> Envelope:
    """Wrap a :class:`GeoUnit` (or a list) as a canonical geo Envelope.

    The body is GeoJSON (a single Feature for one unit, a FeatureCollection for
    many) with ``content_type`` ``application/geo+json``, so positions/markers
    ride the federation S2S path to peer nodes. For a single unit, the CoT uid
    is set as ``thread_id`` so peers can group/dedup updates to the same entity.
    """
    if isinstance(unit_or_units, GeoUnit):
        body = json.dumps(unit_or_units.to_geojson_feature(), separators=(",", ":"))
        thread_id = unit_or_units.uid
        headers = {"geo-uid": unit_or_units.uid, "geo-kind": unit_or_units.kind,
                   "geo-cot-type": unit_or_units.cot_type}
    else:
        fc = {
            "type": "FeatureCollection",
            "features": [u.to_geojson_feature() for u in unit_or_units],
        }
        body = json.dumps(fc, separators=(",", ":"))
        thread_id = None
        headers = {"geo-count": str(len(unit_or_units))}
    return Envelope(
        from_fqid=from_fqid,
        to_fqid=to_fqid,
        content_type=GEO_CONTENT_TYPE,
        body=body,
        thread_id=thread_id,
        headers=headers,
    )


def envelope_to_geounits(env: Envelope) -> list[GeoUnit]:
    """Parse a geo Envelope back into :class:`GeoUnit` objects.

    Handles both a single Feature and a FeatureCollection body.

    Raises:
        ValueError: if the envelope is not an ``application/geo+json`` envelope
            or the body is not parseable GeoJSON.
    """
    if env.content_type != GEO_CONTENT_TYPE:
        raise ValueError(f"not a geo envelope (content_type={env.content_type})")
    try:
        data = json.loads(env.body)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"malformed geo+json body: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("geo+json body is not an object")
    t = data.get("type")
    if t == "FeatureCollection":
        return [GeoUnit.from_geojson_feature(f) for f in data.get("features", [])]
    if t == "Feature":
        return [GeoUnit.from_geojson_feature(data)]
    raise ValueError(f"unsupported geo+json type: {t!r}")
