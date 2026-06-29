"""Shadow-block + consent-gated reporting — SimpleX + MlsGov (design sec. 4 & 5).

Two moderation primitives, each borrowed from the platform that does it best
(``docs/skfed-consent-design.md``):

* **Shadow-block** (SimpleX, sec. 4 — group-join consent toolkit). Hide a
  suspected attacker's messages from *everyone else* while **their own view is
  unchanged** — they keep posting, unaware they've been muted, so they don't
  simply re-knock under a fresh identity. :class:`ShadowBlockSet` is the set of
  shadow-blocked members for one group plus the :meth:`~ShadowBlockSet.visible_to`
  filter that realizes the "hidden from all but self" rule.

* **Consent-gated abuse reporting** (MlsGov, sec. 5). In an E2EE group the
  moderator cannot read messages; **only a message a user explicitly reports**
  becomes visible to moderation, and the report discloses **minimal metadata
  only** — the originating message id, the reporter, and a reason — *never the
  content or the social graph*. An **unreported message leaves no record at
  all**. :class:`ReportLog` is that minimal, append-only moderator-visible log.

State lives under ``skcomms_home()/consent/moderation/<group_id>/`` (a sibling of
the gate-5 :mod:`skcomms.consent` and group :mod:`skcomms.consent_groups` stores),
so a fresh handle over the same home re-reads identical state. Pass
``persisted=False`` for an ephemeral in-memory store (tests / transient rooms).

This module is **purely additive**: it imports :func:`skcomms.home.skcomms_home`
and edits nothing in :mod:`skcomms.consent`. The inbox / group-render path
composes it — see the integration note at the bottom of this docstring.

Integration
-----------
On render, the group view filters each message through the per-group
:class:`ShadowBlockSet`::

    sb = ShadowBlockSet(group_id)
    feed = [m for m in messages if sb.visible_to(viewer_fqid, m.sender_fqid)]

and a moderator's queue is exactly ``ReportLog(group_id).list_reports()`` — never
the raw message store. ``shadow_block`` is the natural action a moderator takes on
a reported sender (sec. 4 + sec. 5 compose: report surfaces, shadow-block mutes).
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .home import skcomms_home


def _moderation_dir(group_id: str) -> Path:
    d = skcomms_home() / "consent" / "moderation" / group_id
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Shadow-block (SimpleX, design sec. 4)
# ---------------------------------------------------------------------------


class ShadowBlockSet:
    """The set of shadow-blocked members for one group + the visibility filter.

    A shadow-blocked sender's messages are hidden from **everyone except the
    sender themselves** — the defining SimpleX property: the blocked member's own
    view is unchanged, so they keep talking unaware. Blocking is **scoped per
    group_id** (a block in one group never bleeds into another).

    Args:
        group_id: The group this block set belongs to.
        persisted: ``True`` (default) backs state with an on-disk SQLite file so a
            fresh handle over the same ``skcomms_home()`` re-reads it; ``False``
            keeps an ephemeral in-memory set (tests / transient rooms).
    """

    def __init__(self, group_id: str, *, persisted: bool = True) -> None:
        self.group_id = group_id
        self.persisted = persisted
        if persisted:
            self._conn = sqlite3.connect(str(_moderation_dir(group_id) / "shadowblock.db"))
        else:
            self._conn = sqlite3.connect(":memory:")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS shadow_blocks "
            "(fqid TEXT PRIMARY KEY, blocked_at REAL NOT NULL)"
        )
        self._conn.commit()

    def shadow_block(self, member: str) -> None:
        """Shadow-block *member*: hide their messages from everyone but themselves."""
        self._conn.execute(
            "INSERT OR REPLACE INTO shadow_blocks (fqid, blocked_at) VALUES (?,?)",
            (member, time.time()),
        )
        self._conn.commit()

    def unblock(self, member: str) -> None:
        """Lift the shadow-block on *member*, restoring visibility to everyone."""
        self._conn.execute("DELETE FROM shadow_blocks WHERE fqid=?", (member,))
        self._conn.commit()

    def is_shadow_blocked(self, member: str) -> bool:
        """Whether *member* is currently shadow-blocked in this group."""
        row = self._conn.execute(
            "SELECT 1 FROM shadow_blocks WHERE fqid=?", (member,)
        ).fetchone()
        return row is not None

    def visible_to(self, viewer: str, sender: str) -> bool:
        """Whether *viewer* should see *sender*'s messages.

        The shadow-block rule: a shadow-blocked *sender* is hidden from everyone
        **except themselves** — so a message is visible iff the sender is not
        shadow-blocked, or the viewer *is* the sender (own view unchanged). A
        non-blocked sender is visible to all.

        Args:
            viewer: The fqid whose feed is being rendered.
            sender: The fqid that authored the message.

        Returns:
            bool: ``True`` if the message should appear in *viewer*'s feed.
        """
        if self.is_shadow_blocked(sender):
            return viewer == sender
        return True

    def list_shadow_blocked(self) -> list[str]:
        """All currently shadow-blocked fqids in this group (moderator view)."""
        return [
            r[0]
            for r in self._conn.execute(
                "SELECT fqid FROM shadow_blocks ORDER BY blocked_at"
            )
        ]


# ---------------------------------------------------------------------------
# Consent-gated reporting (MlsGov, design sec. 5)
# ---------------------------------------------------------------------------


@dataclass
class Report:
    """A minimal abuse report — **metadata only, never content**.

    Discloses exactly the originating message id, the reporter, a reason, and a
    timestamp (MlsGov / Signal model: an originating id + a reason, never the
    message body or social graph). The dataclass deliberately has **no content
    field** — that invariant is asserted by the test suite.
    """

    message_id: str
    reporter: str
    reason: str
    reported_at: float


class ReportLog:
    """The moderator-visible log of explicitly-reported messages (one group).

    Consent-gated: a record exists **only** for a message a user explicitly
    reports via :meth:`file_report`; an unreported message leaves **no record**.
    Each record is a minimal :class:`Report` (id + reporter + reason + time),
    never content. Scoped per ``group_id``.

    Args:
        group_id: The group this report log belongs to.
        persisted: ``True`` (default) backs the log with an on-disk SQLite file;
            ``False`` keeps it in-memory (tests / transient rooms).
    """

    def __init__(self, group_id: str, *, persisted: bool = True) -> None:
        self.group_id = group_id
        self.persisted = persisted
        if persisted:
            self._conn = sqlite3.connect(str(_moderation_dir(group_id) / "reports.db"))
        else:
            self._conn = sqlite3.connect(":memory:")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS reports "
            "(message_id TEXT NOT NULL, reporter TEXT NOT NULL, reason TEXT NOT NULL, "
            "reported_at REAL NOT NULL, "
            "PRIMARY KEY (message_id, reporter))"
        )
        self._conn.commit()

    def file_report(self, message_id: str, reporter: str, reason: str) -> Report:
        """Record a minimal report (id + reporter + reason — never content).

        Args:
            message_id: The reported message's id (the only message handle stored).
            reporter: fqid of the user filing the report.
            reason: Short free-text reason (e.g. ``"spam"``).

        Returns:
            Report: The stored minimal record.
        """
        rep = Report(
            message_id=message_id,
            reporter=reporter,
            reason=reason,
            reported_at=time.time(),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO reports "
            "(message_id, reporter, reason, reported_at) VALUES (?,?,?,?)",
            (rep.message_id, rep.reporter, rep.reason, rep.reported_at),
        )
        self._conn.commit()
        return rep

    def is_reported(self, message_id: str) -> bool:
        """Whether *message_id* has at least one report on file."""
        row = self._conn.execute(
            "SELECT 1 FROM reports WHERE message_id=? LIMIT 1", (message_id,)
        ).fetchone()
        return row is not None

    def list_reports(self) -> list[Report]:
        """All reports on file, oldest first (the moderator's queue)."""
        return [
            Report(message_id=r[0], reporter=r[1], reason=r[2], reported_at=r[3])
            for r in self._conn.execute(
                "SELECT message_id, reporter, reason, reported_at FROM reports "
                "ORDER BY reported_at"
            )
        ]
