"""CoT (Cursor-on-Target) codec — speak TAK/ATAK on the SKFed fabric.

CoT is the TAK ecosystem's wire format: ``<event>`` XML carrying a typed entity
(friendly unit, chat, marker…), a geospatial ``<point>``, and a ``<detail>``
blob. This module is the [CoT][CB1] codec: parse CoT XML ⇄ a structured
:class:`CotEvent`, and map :class:`CotEvent` ⇄ the canonical
:class:`~skcomms.envelope.Envelope` so an ATAK/iTAK device's traffic rides our
sovereign, signed, federated backend (CB2 streams it, CB3 binds identity).

Design: fidelity-first — the full ``<detail>`` subtree is preserved verbatim
(``detail_xml``) so nothing TAK-specific is lost on round-trip, while common
fields (callsign, remarks, GeoChat text) are surfaced as typed accessors.

CoT type taxonomy (MIL-STD-2525-ish), examples:
  ``a-f-G-U-C`` atom·friendly·ground·unit·combat (a PLI / position)
  ``b-t-f``     bits·text·file  → GeoChat message
  ``b-m-p-s-m`` bits·map·point·... → a dropped marker/waypoint
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel, Field

from .envelope import Envelope

COT_CONTENT_TYPE = "application/cot+xml"
COT_BROADCAST = "*"  # CoT is broadcast-by-default; no single addressee


def _utc_iso(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class CotPoint(BaseModel):
    """A CoT ``<point>`` — WGS-84 lat/lon + height/error estimates.

    ``9999999.0`` is CoT's conventional "unknown" sentinel for hae/ce/le.
    """

    lat: float = 0.0
    lon: float = 0.0
    hae: float = 9999999.0  # height above ellipsoid (m)
    ce: float = 9999999.0   # circular error (m)
    le: float = 9999999.0   # linear error (m)


class CotEvent(BaseModel):
    """A parsed CoT ``<event>``.

    Attributes:
        uid: Globally-unique entity id (persistent per entity/marker).
        type: CoT type string (e.g. ``a-f-G-U-C``).
        how: Provenance (e.g. ``m-g`` machine-GPS, ``h-e`` human-entered).
        version: CoT schema version (``2.0``).
        time/start/stale: ISO-8601 UTC; ``stale`` is when the event expires.
        point: Geospatial point.
        detail_xml: Verbatim inner XML of ``<detail>`` (fidelity preservation).
        callsign/remarks/chat: Convenience extractions from ``<detail>``.
    """

    uid: str
    type: str = "a-f-G-U-C"
    how: str = "m-g"
    version: str = "2.0"
    time: str = Field(default_factory=_utc_iso)
    start: str = Field(default_factory=_utc_iso)
    stale: str = Field(default_factory=lambda: _utc_iso(datetime.now(timezone.utc) + timedelta(minutes=5)))
    point: CotPoint = Field(default_factory=CotPoint)
    detail_xml: str = ""
    callsign: Optional[str] = None
    remarks: Optional[str] = None
    chat: Optional[str] = None

    @property
    def is_chat(self) -> bool:
        """Whether this is a GeoChat message (``b-t-f``)."""
        return self.type.startswith("b-t-f")


def parse_cot(xml: str | bytes) -> CotEvent:
    """Parse a CoT ``<event>`` XML document into a :class:`CotEvent`.

    Raises:
        ValueError: if the XML is malformed or not a CoT ``<event>``.
    """
    try:
        root = ET.fromstring(xml.encode() if isinstance(xml, str) else xml)
    except ET.ParseError as exc:
        raise ValueError(f"malformed CoT XML: {exc}") from exc
    if root.tag != "event":
        raise ValueError(f"not a CoT <event> (got <{root.tag}>)")

    pt_el = root.find("point")
    point = CotPoint()
    if pt_el is not None:
        def _f(k, d):
            try:
                return float(pt_el.get(k, d))
            except (TypeError, ValueError):
                return d
        point = CotPoint(lat=_f("lat", 0.0), lon=_f("lon", 0.0), hae=_f("hae", 9999999.0),
                         ce=_f("ce", 9999999.0), le=_f("le", 9999999.0))

    detail_xml, callsign, remarks, chat = "", None, None, None
    det = root.find("detail")
    if det is not None:
        detail_xml = "".join(ET.tostring(c, encoding="unicode") for c in det)
        contact = det.find("contact")
        if contact is not None:
            callsign = contact.get("callsign")
        rem = det.find("remarks")
        if rem is not None and rem.text:
            remarks = rem.text.strip()
        chat_el = det.find("__chat")
        if chat_el is not None:
            # GeoChat text lives in a nested <remarks> or the __chat 'message'/text
            chat = (chat_el.get("message") or "")
            cr = chat_el.find("remarks")
            if (not chat) and cr is not None and cr.text:
                chat = cr.text.strip()
        if not chat and root.get("type", "").startswith("b-t-f"):
            chat = remarks  # GeoChat carries its text in the detail-level <remarks>

    return CotEvent(
        uid=root.get("uid", ""),
        type=root.get("type", "a-f-G-U-C"),
        how=root.get("how", "m-g"),
        version=root.get("version", "2.0"),
        time=root.get("time") or _utc_iso(),
        start=root.get("start") or _utc_iso(),
        stale=root.get("stale") or _utc_iso(),
        point=point,
        detail_xml=detail_xml,
        callsign=callsign,
        remarks=remarks,
        chat=chat,
    )


def to_cot(ev: CotEvent) -> str:
    """Serialize a :class:`CotEvent` back to CoT ``<event>`` XML.

    Reconstructs ``<detail>`` from ``detail_xml`` when present (full fidelity);
    otherwise synthesizes a minimal detail from ``callsign``/``remarks``/``chat``.
    """
    root = ET.Element("event", {
        "version": ev.version, "uid": ev.uid, "type": ev.type, "how": ev.how,
        "time": ev.time, "start": ev.start, "stale": ev.stale,
    })
    ET.SubElement(root, "point", {
        "lat": repr(ev.point.lat), "lon": repr(ev.point.lon), "hae": repr(ev.point.hae),
        "ce": repr(ev.point.ce), "le": repr(ev.point.le),
    })
    if ev.detail_xml:
        # Parse the preserved detail subtree back in (wrap so it parses).
        try:
            det = ET.fromstring(f"<detail>{ev.detail_xml}</detail>")
        except ET.ParseError:
            det = ET.Element("detail")
        root.append(det)
    else:
        det = ET.SubElement(root, "detail")
        if ev.callsign:
            ET.SubElement(det, "contact", {"callsign": ev.callsign})
        txt = ev.chat if ev.is_chat and ev.chat else ev.remarks
        if txt:
            ET.SubElement(det, "remarks").text = txt
    return ET.tostring(root, encoding="unicode")


def cot_to_envelope(ev: CotEvent, *, from_fqid: str, to_fqid: str = COT_BROADCAST) -> Envelope:
    """Wrap a :class:`CotEvent` in the canonical :class:`Envelope`.

    The CoT XML rides verbatim in the body (``content_type`` =
    ``application/cot+xml``); CoT routing metadata is carried in headers so a
    receiver can index/dedup without re-parsing.
    """
    return Envelope(
        from_fqid=from_fqid,
        to_fqid=to_fqid,
        content_type=COT_CONTENT_TYPE,
        body=to_cot(ev),
        thread_id=ev.uid,  # group updates to the same entity/marker
        headers={"cot-uid": ev.uid, "cot-type": ev.type, "cot-how": ev.how},
    )


def envelope_to_cot(env: Envelope) -> CotEvent:
    """Extract a :class:`CotEvent` from a CoT-bearing :class:`Envelope`.

    Raises:
        ValueError: if the envelope is not a CoT envelope.
    """
    if env.content_type != COT_CONTENT_TYPE:
        raise ValueError(f"not a CoT envelope (content_type={env.content_type})")
    return parse_cot(env.body)
