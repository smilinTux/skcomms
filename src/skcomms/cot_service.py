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
from .cot_server import DEFAULT_COT_PORT, CotStreamServer, federation_ingest
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


async def _inbox_inject_loop(server: CotStreamServer, *, poll_s: float = 3.0) -> None:
    """Inject peer-originated CoT (landed in the inbox) to connected clients."""
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
    server = CotStreamServer(host=host, port=port, ingest=federation_ingest(sk, from_fqid=fqid))
    await server.start()
    logger.info("CoT service up as %s on %s:%d (phone→federate + inbox→inject)", fqid, host, port)
    await _inbox_inject_loop(server)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
