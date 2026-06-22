"""Headless CoT test client — a Linux "ATAK operator" for testing.

No GUI ATAK exists for Linux, so this is a scriptable TAK client: it connects to
a CoT endpoint (plain TCP, or TLS using a data-package's certs), broadcasts a
position (PLI) on an interval, optionally sends a GeoChat, and prints every CoT
it receives. Run one on .158 and one on .41 to exercise multi-operator + the
federation path without a phone.

    python -m skcomms.cot_client --host 100.108.59.57 --port 8089 \
        --package ~/.skcapstone/skcomms/cot-pki/packages/jarvis-box.zip \
        --callsign JARVIS-BOX --lat 38.95 --lon -77.45

Plain (no TLS):  python -m skcomms.cot_client --host 127.0.0.1 --port 8087 --callsign T1
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import tempfile
import threading
import time
import zipfile

from .cot import CotEvent, CotPoint, parse_cot, to_cot
from .cot_server import extract_events


def _certs_from_package(zip_path: str, password: str = "atakatak") -> tuple[str, str, str]:
    """Extract client cert/key + CA from a data package into temp PEM files."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, pkcs12,
    )

    z = zipfile.ZipFile(zip_path)
    client_p12 = next(z.read(n) for n in z.namelist() if n.endswith(".p12") and "trust" not in n.lower())
    ca_p12 = next(z.read(n) for n in z.namelist() if "trust" in n.lower() and n.endswith(".p12"))
    key, cert, _ = pkcs12.load_key_and_certificates(client_p12, password.encode())
    cak, cac, extra = pkcs12.load_key_and_certificates(ca_p12, password.encode())
    ca_cert = cac or (extra[0] if extra else None)

    d = tempfile.mkdtemp(prefix="cotcli-")
    cp, kp, ap = (os.path.join(d, f) for f in ("client.pem", "client.key", "ca.pem"))
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    with open(ap, "wb") as f:
        f.write(ca_cert.public_bytes(Encoding.PEM))
    return cp, kp, ap


def _connect(host: str, port: int, *, package: str | None = None) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=10)
    if not package:
        return raw
    cp, kp, ap = _certs_from_package(package)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ap)
    ctx.load_cert_chain(cp, kp)
    ctx.check_hostname = False  # cert SANs carry the IP; skip strict name match
    return ctx.wrap_socket(raw, server_hostname=host)


def _reader(sock: socket.socket, stop: threading.Event) -> None:
    buf = b""
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data = sock.recv(8192)
        except (socket.timeout, ssl.SSLWantReadError):
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
            label = cot.callsign or cot.chat or cot.uid
            print(f"  RX  {cot.type:<10} {label}  @({cot.point.lat},{cot.point.lon})", flush=True)


def run(host, port, callsign, lat, lon, *, package=None, interval=5.0, count=0, chat=None, uid=None):
    uid = uid or f"SKFED-{callsign}"
    sock = _connect(host, port, package=package)
    proto = "TLS" if package else "TCP"
    print(f"connected to {host}:{port} ({proto}) as {callsign}", flush=True)
    stop = threading.Event()
    t = threading.Thread(target=_reader, args=(sock, stop), daemon=True)
    t.start()
    if chat:
        ev = CotEvent(uid=f"GeoChat.{uid}", type="b-t-f", how="h-g-i-g-o",
                      point=CotPoint(lat=lat, lon=lon), callsign=callsign, chat=chat, remarks=chat)
        sock.sendall(to_cot(ev).encode())
        print(f"  TX  GeoChat: {chat}", flush=True)
    sent = 0
    try:
        while True:
            ev = CotEvent(uid=uid, type="a-f-G-U-C", how="m-g",
                          point=CotPoint(lat=lat, lon=lon, hae=10.0, ce=5.0, le=5.0), callsign=callsign)
            sock.sendall(to_cot(ev).encode())
            sent += 1
            print(f"  TX  PLI #{sent} {callsign} @({lat},{lon})", flush=True)
            if count and sent >= count:
                time.sleep(1.5)  # let final RX flush
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        try:
            sock.close()
        except OSError:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="Headless CoT/TAK test client")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--package", help="data-package .zip for TLS+client-cert (omit for plain TCP)")
    ap.add_argument("--callsign", default="LINUX-1")
    ap.add_argument("--lat", type=float, default=38.8895)
    ap.add_argument("--lon", type=float, default=-77.0353)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--count", type=int, default=0, help="stop after N PLIs (0=forever)")
    ap.add_argument("--chat", help="send a GeoChat message on connect")
    ap.add_argument("--uid")
    a = ap.parse_args(argv)
    run(a.host, a.port, a.callsign, a.lat, a.lon, package=a.package,
        interval=a.interval, count=a.count, chat=a.chat, uid=a.uid)


if __name__ == "__main__":
    main()
