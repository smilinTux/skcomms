"""First-contact consent gate — *discoverability != delivery* (gate 5).

The public directory makes an agent **reachable**; this module decides what is
actually **delivered**. An unknown first-contact is quarantined into a capped,
no-notify :class:`RequestQueue`; a known/accepted contact is delivered; a blocked
sender is dropped. In ``tailnet`` deployment mode every sender is already a
network-authenticated member (WireGuard cryptokey routing — consent by
construction), so nothing is quarantined.

Design: ``docs/skfed-consent-design.md``. This is P1; per-contact capability
tokens (P2), sender-auth tiering + ban-feeds (P3) and group consent (P4) layer on
top of the same store.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .home import skcomms_home


class ConsentDecision(str, Enum):
    """What the gate decides for an incoming envelope."""

    DELIVER = "deliver"        #: known/accepted contact (or tailnet-mode member)
    QUARANTINE = "quarantine"  #: unknown first-contact → request queue
    DROP = "drop"              #: blocked sender → discard silently


def _consent_dir(agent: str) -> Path:
    d = skcomms_home() / "consent" / agent
    d.mkdir(parents=True, exist_ok=True)
    return d


class ContactStore:
    """Per-agent known/blocked contact state (SQLite, isolated per agent)."""

    def __init__(self, agent: str) -> None:
        self.agent = agent
        self._db = _consent_dir(agent) / "contacts.db"
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS contacts "
                "(fqid TEXT PRIMARY KEY, state TEXT NOT NULL, updated_at REAL NOT NULL)"
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db))

    def _set(self, fqid: str, state: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO contacts (fqid, state, updated_at) VALUES (?,?,?)",
                (fqid, state, time.time()),
            )

    def _state(self, fqid: str) -> Optional[str]:
        with self._conn() as c:
            row = c.execute("SELECT state FROM contacts WHERE fqid=?", (fqid,)).fetchone()
        return row[0] if row else None

    def accept(self, fqid: str) -> None:
        """Mark *fqid* a known/accepted contact (full delivery)."""
        self._set(fqid, "known")

    def block(self, fqid: str) -> None:
        """Block *fqid* — its traffic is dropped (overrides known)."""
        self._set(fqid, "blocked")

    def is_known(self, fqid: str) -> bool:
        return self._state(fqid) == "known"

    def is_blocked(self, fqid: str) -> bool:
        return self._state(fqid) == "blocked"

    def list_known(self) -> list[str]:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT fqid FROM contacts WHERE state='known'")]


class ConsentGate:
    """Classify an incoming sender → :class:`ConsentDecision`.

    Order: blocked → DROP; known → DELIVER; tailnet-mode → DELIVER (network
    membership = consent); else → QUARANTINE. ``verified`` (a sovereign/DID-signed
    sender) is accepted now for the P3 tiering layer and does not yet change the
    decision — an unknown sovereign sender still knocks, just a *verified* knock.
    """

    def __init__(self, contacts: ContactStore, *, mode: str = "public") -> None:
        self._contacts = contacts
        self.mode = mode

    def classify(self, sender_fqid: str, *, verified: bool = False) -> ConsentDecision:
        if self._contacts.is_blocked(sender_fqid):
            return ConsentDecision.DROP
        if self._contacts.is_known(sender_fqid):
            return ConsentDecision.DELIVER
        if self.mode == "tailnet":
            return ConsentDecision.DELIVER
        return ConsentDecision.QUARANTINE


@dataclass
class ContactRequest:
    """A quarantined first-contact message awaiting accept/decline."""

    sender: str
    body: bytes
    envelope_id: str
    received_at: float


class RequestQueue:
    """Quarantined first-contact messages — capped per sender, no notification.

    The cap is the anti-spam lever: an unknown sender gets at most
    ``cap_per_sender`` queued knocks until the recipient accepts (Signal Message
    Request semantics — quiet by default, the user reviews on their own time).
    """

    def __init__(self, agent: str, *, cap_per_sender: int = 1) -> None:
        self.agent = agent
        self.cap = cap_per_sender
        self._db = _consent_dir(agent) / "requests.db"
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS requests "
                "(envelope_id TEXT PRIMARY KEY, sender TEXT NOT NULL, body BLOB, "
                "received_at REAL NOT NULL)"
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db))

    def enqueue(self, sender: str, body: bytes, *, envelope_id: str) -> bool:
        """Queue a first-contact message. Returns False if the per-sender cap is hit."""
        with self._conn() as c:
            n = c.execute(
                "SELECT COUNT(*) FROM requests WHERE sender=?", (sender,)
            ).fetchone()[0]
            if n >= self.cap:
                return False
            c.execute(
                "INSERT OR IGNORE INTO requests (envelope_id, sender, body, received_at) "
                "VALUES (?,?,?,?)",
                (envelope_id, sender, body, time.time()),
            )
        return True

    def list_requests(self) -> list[ContactRequest]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT sender, body, envelope_id, received_at FROM requests "
                "ORDER BY received_at"
            ).fetchall()
        return [
            ContactRequest(sender=r[0], body=r[1], envelope_id=r[2], received_at=r[3])
            for r in rows
        ]

    def accept_request(self, sender: str, *, store: ContactStore) -> None:
        """Promote *sender* to a known contact and clear its queued knocks."""
        store.accept(sender)
        with self._conn() as c:
            c.execute("DELETE FROM requests WHERE sender=?", (sender,))

    def decline_request(self, sender: str, *, store: Optional[ContactStore] = None,
                        block: bool = False) -> None:
        """Drop *sender*'s queued knocks; optionally block the sender."""
        if block and store is not None:
            store.block(sender)
        with self._conn() as c:
            c.execute("DELETE FROM requests WHERE sender=?", (sender,))
