"""Greylisting — first-contact speed-bump that REPLACES proof-of-work (gate 5).

Round-2 of the consent research (``docs/skfed-consent-design.md``) is explicit:
**proof-of-work is DROPPED** — Laurie & Clayton, *"Proof-of-Work proves not to
work"*, is the canonical, undisputed result that the PoW difficulty needed to deter
resourced/botnet spammers overlaps legitimate usage, so it taxes the innocent and
can't work. In its place we ADD **greylisting**, the classic email primitive: an
unknown first-contact is **temp-deferred** ('defer'); a sender that **retries after
a short delay** is **admitted** ('admit').

Why it works without a central server or any compute tax:

* Legitimate senders retry naturally (their MTA / agent re-sends), so a real
  first-contact pays only a one-time delay.
* Naive bulk spammers are fire-and-forget — they don't keep per-recipient retry
  state, so they never come back and never get admitted.

The friction is *time*, not *work*: the exact property PoW failed to deliver.
This is a **speed-bump, never the wall** — it composes with the request-queue
quarantine (:mod:`skcomms.consent`), capability tokens, and signed ban feeds. State
``(sender, first_seen, sightings)`` is persisted per-agent under
``skcomms_home()/consent/<agent>/`` (SQLite, isolated per agent), matching the
:class:`~skcomms.consent.ContactStore` layout. The clock is injectable so the delay
is testable without sleeping.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .home import skcomms_home

#: Default first-contact deferral window (seconds). A retry sooner than this is
#: still 'defer'; a retry at/after it 'admit's. Node POLICY, not protocol — the
#: design leaves concrete thresholds to the node (safe default here).
DEFAULT_MIN_DELAY_S = 60


def _consent_dir(agent: str) -> Path:
    """Per-agent consent state dir under ``skcomms_home()`` (created if absent).

    Mirrors :func:`skcomms.consent._consent_dir` so the greylist lives alongside
    the contact/request stores for the same agent.
    """
    d = skcomms_home() / "consent" / agent
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass(frozen=True)
class GreylistRecord:
    """Tracked state for one sender: when first seen and how many sightings."""

    sender: str
    first_seen: float
    sightings: int


class Greylist:
    """Per-agent greylist: ``see(sender)`` → ``'defer'`` or ``'admit'``.

    First sighting of an unknown sender records ``first_seen`` and returns
    ``'defer'``. A later sighting is ``'admit'`` once it lands at/after
    ``first_seen + min_delay_s``; earlier retries stay ``'defer'``. Once a sender
    has been admitted it stays admitted (the greylist's job is the *first-contact*
    speed-bump, not an ongoing rate limit). Sightings are counted on every call.

    State is persisted in ``consent/<agent>/greylist.db`` so deferral survives
    process restarts (a spammer can't reset the clock by reconnecting).
    """

    def __init__(self, agent: str, *, min_delay_s: float = DEFAULT_MIN_DELAY_S) -> None:
        self.agent = agent
        self.min_delay_s = min_delay_s
        self._db = _consent_dir(agent) / "greylist.db"
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS greylist ("
                "sender TEXT PRIMARY KEY, "
                "first_seen REAL NOT NULL, "
                "sightings INTEGER NOT NULL, "
                "admitted INTEGER NOT NULL DEFAULT 0)"
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db))

    def see(self, sender: str, *, now: Optional[float] = None) -> str:
        """Record a sighting of *sender* and decide ``'defer'`` | ``'admit'``.

        Args:
            sender: The sender FQID knocking on this agent's inbox.
            now: Injected clock (epoch seconds). Defaults to :func:`time.time`.

        Returns:
            ``'admit'`` if the sender has cleared the deferral window (or was
            already admitted), else ``'defer'``.
        """
        if now is None:
            now = time.time()
        with self._conn() as c:
            row = c.execute(
                "SELECT first_seen, sightings, admitted FROM greylist WHERE sender=?",
                (sender,),
            ).fetchone()

            if row is None:
                # First contact: record + defer.
                c.execute(
                    "INSERT INTO greylist (sender, first_seen, sightings, admitted) "
                    "VALUES (?,?,?,0)",
                    (sender, now, 1),
                )
                return "defer"

            first_seen, sightings, admitted = row[0], row[1], row[2]
            sightings += 1
            # Sticky: an already-admitted sender stays admitted regardless of clock.
            admit = bool(admitted) or (now - first_seen >= self.min_delay_s)
            c.execute(
                "UPDATE greylist SET sightings=?, admitted=? WHERE sender=?",
                (sightings, 1 if admit else 0, sender),
            )
            return "admit" if admit else "defer"

    def record(self, sender: str) -> Optional[GreylistRecord]:
        """Return the persisted :class:`GreylistRecord` for *sender*, or ``None``."""
        with self._conn() as c:
            row = c.execute(
                "SELECT sender, first_seen, sightings FROM greylist WHERE sender=?",
                (sender,),
            ).fetchone()
        if row is None:
            return None
        return GreylistRecord(sender=row[0], first_seen=row[1], sightings=row[2])
