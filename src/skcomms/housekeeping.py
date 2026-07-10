"""Periodic housekeeping: outbox pruning, archive TTL, mailbox retention.

Every file-based rail in skcomms is append-only at write time:

  * ``FileTransport.send`` / ``SyncthingTransport.send`` write ``{id}.skc.json``
    into the sender outbox and nothing on the send path ever deletes them,
  * the receive path moves processed envelopes into ``archive/`` forever,
  * ``mailbox.send_message`` keeps a local outbox record per message forever.

Left unswept, those directories grow without bound; in production a 140k-file
outbox pegged Syncthing and froze a fleet laptop. This module is the single
sweeper: :func:`run_housekeeping_pass` performs one full pass, and
:func:`housekeeping_loop` runs it periodically inside the daemon (wired in
``api.lifespan``). The ``skcomms housekeep`` CLI verb runs one pass on demand
and is suitable for a systemd timer.

Retention is driven by :class:`skcomms.config.HousekeepingConfig` (config.yml
``housekeeping:`` block). Defaults: sender outbox 48h, receiver archive 168h
(7 days), mailbox outbox records 168h (7 days), daemon pass every 3600s.
The pass also bounds the persistent outbox's ``dead/`` and ``archive/``
directories (30-day TTL + 5000-entry cap by default) when handed the outbox,
so a persistent peer outage can not grow the dead-letter queue forever.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Iterable, Optional

from .config import HousekeepingConfig
from .home import skcomms_home

logger = logging.getLogger("skcomms.housekeeping")


def prune_mailbox_outboxes(ttl_hours: float, home: Optional[Path] = None) -> int:
    """Delete stale mailbox outbox records from the realm message tree.

    ``mailbox.send_message`` writes a local record of every sent message to
    ``<home>/<realm>/<operator>/<agent>/outbox/`` and nothing ever deletes
    them. This sweeps every agent's outbox in the tree, deleting ``*.json``
    records whose mtime is older than *ttl_hours*.

    Inbox files are deliberately NOT touched: they are the delivery path and
    may not have been read yet.

    Args:
        ttl_hours: Age threshold in hours. Values <= 0 prune nothing.
        home: Override the skcomms home root (defaults to
            :func:`skcomms.home.skcomms_home`, which honors ``SKCOMMS_HOME``).

    Returns:
        int: The number of outbox record files deleted.
    """
    if ttl_hours <= 0:
        return 0

    root = home if home is not None else skcomms_home()
    if not root.exists():
        return 0

    cutoff = time.time() - (ttl_hours * 3600.0)
    deleted = 0

    # Tree shape: <root>/<realm>/<operator>/<agent>/outbox/*.json
    for realm_dir in root.iterdir():
        if not realm_dir.is_dir() or realm_dir.name.startswith("."):
            continue
        for op_dir in realm_dir.iterdir():
            if not op_dir.is_dir() or op_dir.name.startswith("."):
                continue
            for agent_dir in op_dir.iterdir():
                if not agent_dir.is_dir() or agent_dir.name.startswith("."):
                    continue
                outbox = agent_dir / "outbox"
                if not outbox.is_dir():
                    continue
                for record in outbox.glob("*.json"):
                    if record.name.startswith("."):
                        continue
                    try:
                        if record.stat().st_mtime < cutoff:
                            record.unlink()
                            deleted += 1
                    except OSError as exc:
                        logger.warning("Failed to prune mailbox record %s: %s", record, exc)

    if deleted:
        logger.info("Pruned %d mailbox outbox record(s) older than %sh", deleted, ttl_hours)
    return deleted


def run_housekeeping_pass(
    transports: Iterable[object],
    config: Optional[HousekeepingConfig] = None,
    outbox: Optional[object] = None,
) -> dict:
    """Run one full housekeeping pass over the given transports + mailbox tree.

    For every transport that exposes them (duck-typed, so non-file rails are
    skipped automatically):

      * ``prune_outbox(max_age_hours)``: stale sender outbox envelopes,
      * ``prune_archive(ttl_hours)``: processed-envelope archive TTL,

    then :func:`prune_mailbox_outboxes` sweeps the realm message tree. When a
    :class:`~skcomms.outbox.PersistentOutbox` is supplied, its ``dead/`` and
    ``archive/`` directories are bounded too (``dead_letter_*`` /
    ``outbox_archive_*`` retention settings): without this a persistent peer
    outage dead-letters every retry-exhausted send and grows ``dead/`` forever
    exactly like the 140k-file sender outbox did. Per-target failures are
    logged and never abort the pass.

    Args:
        transports: Transport instances to sweep (e.g. ``router.transports``).
        config: Retention settings; defaults to :class:`HousekeepingConfig`.
        outbox: Optional :class:`~skcomms.outbox.PersistentOutbox` whose
            dead-letter and archive retention to enforce. When None (the
            default), the persistent outbox is left untouched, preserving the
            historical behavior for callers that only sweep transports.

    Returns:
        dict: ``{"outbox_pruned": int, "archive_pruned": int,
        "mailbox_pruned": int}`` totals for the pass, plus
        ``"dead_pruned"`` and ``"outbox_archive_pruned"`` when *outbox*
        was supplied.
    """
    cfg = config or HousekeepingConfig()
    results = {"outbox_pruned": 0, "archive_pruned": 0, "mailbox_pruned": 0}

    for transport in transports:
        name = getattr(transport, "name", transport.__class__.__name__)

        prune_outbox = getattr(transport, "prune_outbox", None)
        if callable(prune_outbox):
            try:
                results["outbox_pruned"] += prune_outbox(
                    max_age_hours=cfg.outbox_max_age_hours
                )
            except Exception:
                logger.exception("prune_outbox failed for transport %s", name)

        prune_archive = getattr(transport, "prune_archive", None)
        if callable(prune_archive):
            try:
                results["archive_pruned"] += prune_archive(ttl_hours=cfg.archive_ttl_hours)
            except Exception:
                logger.exception("prune_archive failed for transport %s", name)

    try:
        results["mailbox_pruned"] = prune_mailbox_outboxes(cfg.mailbox_ttl_hours)
    except Exception:
        logger.exception("mailbox outbox pruning failed")

    if outbox is not None:
        results["dead_pruned"] = 0
        results["outbox_archive_pruned"] = 0
        try:
            results["dead_pruned"] = outbox.prune_dead(
                ttl_hours=cfg.dead_letter_ttl_hours,
                max_count=cfg.dead_letter_max_count,
            )
        except Exception:
            logger.exception("dead-letter retention pruning failed")
        try:
            results["outbox_archive_pruned"] = outbox.prune_archive(
                ttl_hours=cfg.outbox_archive_ttl_hours,
                max_count=cfg.outbox_archive_max_count,
            )
        except Exception:
            logger.exception("outbox-archive retention pruning failed")

    logger.info(
        "Housekeeping pass: %d outbox, %d archive, %d mailbox, "
        "%d dead-letter, %d outbox-archive record(s) pruned",
        results["outbox_pruned"],
        results["archive_pruned"],
        results["mailbox_pruned"],
        results.get("dead_pruned", 0),
        results.get("outbox_archive_pruned", 0),
    )
    return results


async def housekeeping_loop(
    get_transports,
    config: Optional[HousekeepingConfig] = None,
    get_outbox=None,
) -> None:
    """Run :func:`run_housekeeping_pass` forever at the configured interval.

    Intended to be started as an ``asyncio`` task by the daemon lifespan and
    cancelled on shutdown. Sleeps FIRST, then runs a pass, so a short-lived
    process (or a test driving the lifespan) never sweeps real state unless
    it outlives one interval. Each pass runs in a worker thread so filesystem
    sweeps never block the event loop. Errors are logged and the loop keeps
    going; only cancellation stops it.

    Args:
        get_transports: Zero-arg callable returning the current transports
            (late-bound so the loop always sees the live router state).
        config: Retention + interval settings; defaults to
            :class:`HousekeepingConfig` (hourly).
        get_outbox: Optional zero-arg callable returning the live
            :class:`~skcomms.outbox.PersistentOutbox` (or None). When it
            yields an outbox, each pass also enforces dead-letter and
            outbox-archive retention.
    """
    cfg = config or HousekeepingConfig()
    while True:
        await asyncio.sleep(cfg.interval_s)
        try:
            transports = list(get_transports() or [])
            outbox = get_outbox() if callable(get_outbox) else None
            await asyncio.to_thread(run_housekeeping_pass, transports, cfg, outbox)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Housekeeping pass failed; will retry next interval")
