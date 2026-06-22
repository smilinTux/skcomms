"""Runnable CoT service — bind the CB2 TAK-streaming endpoint to a live node.

``python -m skcomms.cot_service`` starts the :class:`CotStreamServer` bound to
the tailnet (``0.0.0.0:8087``) wired to this node's SKComms:

  * **phone → fabric:** inbound CoT from connected ATAK/iTAK clients is wrapped
    in a signed Envelope and federated to peer nodes (``federation_ingest``),
  * **fabric → phone:** a poll loop watches the skcomms inbox for CoT-bearing
    envelopes that arrived from peers and :meth:`~CotStreamServer.push`es them
    to the connected clients — so an operator on this node sees remote teams.

This is the deploy substrate for CB5 (real-device E2E). Plain TCP; CB3 adds TLS
+ per-device capauth identity.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from .cot import parse_cot
from .cot_server import (
    DEFAULT_COT_PORT, DEFAULT_COT_TLS_PORT, CotStreamServer, TlsCotStreamServer,
    UdpMeshListener, federation_ingest,
)
from .home import skcomms_home
from .identity import resolve_self_identity

logger = logging.getLogger("skcomms.cot_service")


def _extract_cot_body(data: dict) -> str | None:
    """Pull a CoT XML string out of a stored inbox envelope (shape-tolerant)."""
    for k in ("content", "body"):
        v = data.get(k)
        if isinstance(v, str) and "<event" in v:
            return v
    payload = data.get("payload")
    if isinstance(payload, dict):
        v = payload.get("content") or payload.get("body")
        if isinstance(v, str) and "<event" in v:
            return v
    return None


async def _inbox_inject_loop(
    server: CotStreamServer, *, also: CotStreamServer | None = None, poll_s: float = 3.0
) -> None:
    """Inject peer-originated CoT (landed in the inbox) to connected clients.

    *also* is an optional second server (e.g. the TLS endpoint) to fan the same
    CoT to, so peer-originated traffic reaches both plain and TLS operators.
    """
    inbox = skcomms_home() / "inbox"
    processed = inbox / "cot-processed"
    try:
        processed.mkdir(parents=True, exist_ok=True)
    except Exception:  # noqa: BLE001
        pass
    seen: set[str] = set()
    while True:
        try:
            for f in sorted(inbox.glob("*.json")):
                if f.name in seen:
                    continue
                seen.add(f.name)
                try:
                    data = json.loads(f.read_text())
                except Exception:  # noqa: BLE001
                    continue
                body = _extract_cot_body(data)
                if not body:
                    continue
                try:
                    cot = parse_cot(body)
                except ValueError:
                    continue
                await server.push(cot)
                if also is not None:
                    await also.push(cot)
                logger.info("injected peer CoT uid=%s to %d client(s)", cot.uid, server.client_count)
                try:
                    f.rename(processed / f.name)
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("inbox inject loop error: %s", exc)
        await asyncio.sleep(poll_s)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ident = resolve_self_identity()
    fqid = ident.get("fqid") or ident.get("agent") or "local"
    host = os.environ.get("SKCOMMS_COT_HOST", "0.0.0.0")
    port = int(os.environ.get("SKCOMMS_COT_PORT", DEFAULT_COT_PORT))

    from .core import SKComms  # local import — avoids heavy import at module load

    sk = SKComms.from_config()
    fed_hook = federation_ingest(sk, from_fqid=fqid)
    server = CotStreamServer(host=host, port=port, ingest=fed_hook)
    await server.start()
    logger.info("CoT service up as %s on %s:%d (phone→federate + inbox→inject)", fqid, host, port)

    # CB3: TLS-enrolled endpoint (:8089). Each TLS connection's CoT is
    # additionally attributed to the device identity pinned from its client cert.
    tls_server: TlsCotStreamServer | None = None
    if os.environ.get("SKCOMMS_COT_TLS", "0") == "1":
        tls_port = int(os.environ.get("SKCOMMS_COT_TLS_PORT", DEFAULT_COT_TLS_PORT))

        def _ident_hook(cot, identity, fingerprint):
            logger.info("TLS CoT uid=%s attributed to device=%s (fp=%s)", cot.uid, identity, fingerprint)
            fed_hook(cot)

        tls_server = TlsCotStreamServer(host=host, port=tls_port, ident_ingest=_ident_hook)
        await tls_server.start()
        logger.info("CoT TLS endpoint up on %s:%d (per-device client-cert identity)", host, tls_port)

    # Mesh-mode ATAK (no server/auth): join the multicast group on the LAN so a
    # phone's mesh CoT is ingested + federated + shown to any TCP viewers.
    if os.environ.get("SKCOMMS_COT_MESH", "1") != "0":
        async def _mesh_event(cot):
            fed_hook(cot)            # mesh CoT → federate to peers
            await server.push(cot)   # → any plain-TCP viewers
            if tls_server is not None:
                await tls_server.push(cot)  # → any TLS viewers
            logger.info("mesh CoT uid=%s callsign=%s pos=(%s,%s)", cot.uid, cot.callsign,
                        cot.point.lat, cot.point.lon)
        try:
            await UdpMeshListener(on_event=_mesh_event).start()
        except Exception as exc:  # noqa: BLE001
            logger.warning("mesh listener not started: %s", exc)

    await _inbox_inject_loop(server, also=tls_server)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
