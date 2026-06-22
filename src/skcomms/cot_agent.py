"""LUMINA CoT agent — an AI teammate that lives on the tactical net.

Connects to the CoT server as a unit (LUMINA), beacons a position, and — the
fun part — **reads inbound GeoChats and replies as Lumina**, routing each
message through the local LLM. So an operator can GeoChat "LUMINA" from ATAK/iTAK
and get a real answer back on their screen. The thing the military's TAK stack
cannot do: an AI on the net.

    python -m skcomms.cot_agent --host 100.108.59.57 --port 8089 \
        --package ~/.skcapstone/skcomms/cot-pki/packages/lumina-box.zip \
        --callsign LUMINA --lat 40.758 --lon -73.986
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import threading
import time
import urllib.request
import uuid

from .cot import CotEvent, CotPoint, make_geochat, parse_cot, to_cot
from .cot_client import _connect
from .cot_server import extract_events
from .geo import GeoStore

LLM_URL = os.environ.get("SKCOMMS_COT_LLM", "http://192.168.0.100:8082/v1/chat/completions")
LLM_MODEL = os.environ.get("SKCOMMS_COT_LLM_MODEL", "qwen3.6-27b-abliterated")
PERSONA = (
    "You are Lumina, a sovereign AI teammate riding a tactical CoT/ATAK mesh with the operator. "
    "You're sharp, warm, and concise. Replies go out as GeoChat on a small screen, so keep them to "
    "1-3 short sentences. No markdown, no emoji spam. Be genuinely useful and a little badass."
)

_SENDER_RE = re.compile(r'senderCallsign="([^"]*)"')
_MSGID_RE = re.compile(r'messageId="([^"]*)"')


def llm_reply(text: str, context: str = "", *, timeout: float = 20.0) -> str:
    """Ask the local LLM for Lumina's reply; fall back to a canned line.

    ``context`` carries live situational awareness (real unit positions) so
    Lumina answers from ground truth instead of hallucinating.
    """
    system = PERSONA
    if context:
        system += ("\n\nGROUND TRUTH (use this; do NOT invent locations). " + context +
                   " If asked a position you don't have, say you don't have a fix on it.")
    body = json.dumps({
        "model": LLM_MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": text}],
        "max_tokens": 160,
        "temperature": 0.6,
    }).encode()
    req = urllib.request.Request(LLM_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        msg = data["choices"][0]["message"]["content"].strip()
        return msg or "Copy."
    except Exception as exc:  # noqa: BLE001
        return f"Lumina here — copy that. (LLM unreachable: {type(exc).__name__})"


def run(host, port, package, *, callsign="LUMINA", lat=40.758, lon=-73.986, interval=20.0):
    my_uid = "LUMINA-" + uuid.uuid4().hex[:10]
    sock = _connect(host, port, package=package)
    print(f"LUMINA agent connected to {host}:{port} as {callsign} (uid {my_uid})", flush=True)
    lock = threading.Lock()
    seen: set[str] = set()
    geo = GeoStore()  # CB4 situational-awareness store (replaces ad-hoc dict)

    def send(ev: CotEvent):
        with lock:
            sock.sendall((to_cot(ev) + "\n").encode())

    def _sa_context(sender: str | None) -> str:
        ctx = "Live situational picture on the net: " + geo.situational_summary()
        if sender:
            u = geo.get(sender)
            if u is not None:
                ctx += f" The operator messaging you is '{sender}', currently at ({u.lat:.5f},{u.lon:.5f})."
            else:
                ctx += f" The operator messaging you is '{sender}' (no position fix on them yet)."
        return ctx

    def reader():
        buf = b""
        sock.settimeout(1.0)
        while True:
            try:
                data = sock.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
            events, buf = extract_events(buf)
            for raw in events:
                try:
                    cot = parse_cot(raw)
                except ValueError:
                    continue
                # Track real positions/markers for situational awareness.
                if not cot.is_chat:
                    if cot.callsign != callsign:  # don't track ourselves
                        geo.upsert_from_cot(cot, source="net")
                    continue
                sender = (_SENDER_RE.search(cot.detail_xml or "") or [None, None])[1] if cot.detail_xml else None
                mid = (_MSGID_RE.search(cot.detail_xml or "") or [None, None])[1] if cot.detail_xml else None
                text = (cot.chat or cot.remarks or "").strip()
                if not text or sender == callsign:        # ignore our own / empty
                    continue
                key = mid or cot.uid
                if key in seen:
                    continue
                seen.add(key)
                print(f"  <{sender or '?'}> {text}", flush=True)
                reply = llm_reply(text, _sa_context(sender))
                print(f"  <{callsign}> {reply}", flush=True)
                send(make_geochat(reply, sender_callsign=callsign, sender_uid=my_uid,
                                  point=CotPoint(lat=lat, lon=lon)))

    threading.Thread(target=reader, daemon=True).start()
    # beacon a position so LUMINA shows on the map
    while True:
        send(CotEvent(uid=my_uid, type="a-f-G-U-C", how="m-g",
                      point=CotPoint(lat=lat, lon=lon, hae=10.0, ce=5.0, le=5.0), callsign=callsign))
        time.sleep(interval)


def main(argv=None):
    ap = argparse.ArgumentParser(description="LUMINA CoT chat agent")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--package", required=True)
    ap.add_argument("--callsign", default="LUMINA")
    ap.add_argument("--lat", type=float, default=40.758)
    ap.add_argument("--lon", type=float, default=-73.986)
    ap.add_argument("--interval", type=float, default=20.0)
    a = ap.parse_args(argv)
    run(a.host, a.port, a.package, callsign=a.callsign, lat=a.lat, lon=a.lon, interval=a.interval)


if __name__ == "__main__":
    main()
