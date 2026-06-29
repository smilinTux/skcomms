"""Group-join consent — SimpleX toolkit (gate, sec. 4 of the design).

The design's group-consent layer (``docs/skfed-consent-design.md`` sec. 4,
"Group-join consent — SimpleX toolkit") borrows SimpleX's directly-transferable
admission model: **groups are invite-only by default, never join-from-directory**,
with three admission modes and a delegated moderator role.

* ``invite_only`` (default) — a joiner must have been **invited** by an
  owner/moderator; an un-invited stranger is rejected outright.
* ``knock`` — *member review*: every prospective member is queued
  (:class:`JoinStatus.PENDING`) and an owner/moderator vets it before they join
  (SimpleX v6.4.1 "knocking").
* ``open`` — admitted on request, **still subject to a captcha** if the owner set
  one (SimpleX v6.3 captcha admission — the directory bot itself challenges the
  joiner, no third-party server).

Roles — **owner / moderator / member** — gate moderation. A delegated moderator
can approve members in review, deny, and **block-for-all** (drop a suspected
attacker so they can never re-knock). A plain member can do none of these; the
role checks fail closed with :class:`PermissionError`.

State lives under ``skcomms_home()/consent/groups/<group_id>/policy.db`` (a
sibling of the gate-5 :mod:`skcomms.consent` stores), so a fresh
:class:`GroupJoinPolicy` over the same home re-reads identical state. Pass
``persisted=False`` for an ephemeral in-memory policy (tests / transient rooms).

This module is **purely additive**: it imports :func:`skcomms.home.skcomms_home`
and edits nothing in :mod:`skcomms.consent`. The first-contact gate composes the
two — see the integration note in the module that wires the inbox.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .home import skcomms_home

#: Admission modes (the `mode` of a :class:`GroupJoinPolicy`).
MODES = ("invite_only", "knock", "open")


class Role(str, Enum):
    """A member's role within a group (escalating moderation authority)."""

    OWNER = "owner"          #: created the group; full authority
    MODERATOR = "moderator"  #: delegated: approve/deny/block-for-all
    MEMBER = "member"        #: ordinary member; no moderation authority


class JoinStatus(str, Enum):
    """The status of an fqid with respect to a group."""

    INVITED = "invited"    #: pre-authorized (invite_only) but not yet joined
    PENDING = "pending"    #: knocking / awaiting captcha — queued for review
    MEMBER = "member"      #: admitted, full member
    DENIED = "denied"      #: rejected (un-invited stranger, or denied in review)
    BLOCKED = "blocked"    #: block-for-all — dropped, may never re-knock


#: Roles that may moderate (approve / deny / block-for-all).
_MODERATOR_ROLES = (Role.OWNER, Role.MODERATOR)


@dataclass
class JoinRequest:
    """The outcome of a join attempt / a queued knock awaiting review."""

    fqid: str
    group_id: str
    status: JoinStatus
    requested_at: float


class GroupJoinPolicy:
    """Per-group join-consent state machine (SimpleX-style admission + roles).

    Args:
        group_id: Stable group identifier (used for the on-disk path).
        mode: One of ``invite_only`` (default), ``knock``, ``open``.
        owner: FQID seeded as the group :class:`Role.OWNER` (optional but
            recommended — a group with no owner/moderator can never approve).
        captcha: Optional expected captcha answer. When set, an ``open``-mode
            joiner stays :class:`JoinStatus.PENDING` until it presents the
            matching ``captcha_answer`` (SimpleX captcha admission).
        persisted: ``True`` (default) backs state with an on-disk SQLite file so a
            fresh handle re-reads it; ``False`` uses an ephemeral in-memory DB.
    """

    def __init__(
        self,
        group_id: str,
        *,
        mode: str = "invite_only",
        owner: Optional[str] = None,
        captcha: Optional[str] = None,
        persisted: bool = True,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r} (expected one of {MODES})")
        self.group_id = group_id
        self.mode = mode
        self.captcha = captcha
        self.persisted = persisted

        if persisted:
            d = skcomms_home() / "consent" / "groups" / group_id
            d.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(d / "policy.db"))
        else:
            self._conn = sqlite3.connect(":memory:")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS membership "
            "(fqid TEXT PRIMARY KEY, role TEXT, status TEXT NOT NULL, "
            " updated_at REAL NOT NULL)"
        )
        self._conn.commit()

        if owner:
            # Idempotent — re-opening an existing group never demotes the owner.
            if self._role(owner) is None:
                self._upsert(owner, Role.OWNER, JoinStatus.MEMBER)

    # -- low-level row helpers -------------------------------------------------

    def _upsert(self, fqid: str, role: Optional[Role], status: JoinStatus) -> None:
        self._conn.execute(
            "INSERT INTO membership (fqid, role, status, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(fqid) DO UPDATE SET role=excluded.role, "
            "status=excluded.status, updated_at=excluded.updated_at",
            (fqid, role.value if role else None, status.value, time.time()),
        )
        self._conn.commit()

    def _row(self, fqid: str) -> Optional[tuple]:
        return self._conn.execute(
            "SELECT role, status FROM membership WHERE fqid=?", (fqid,)
        ).fetchone()

    def _role(self, fqid: str) -> Optional[Role]:
        row = self._row(fqid)
        return Role(row[0]) if row and row[0] else None

    def _status(self, fqid: str) -> Optional[JoinStatus]:
        row = self._row(fqid)
        return JoinStatus(row[1]) if row else None

    # -- public state queries --------------------------------------------------

    def role_of(self, fqid: str) -> Optional[Role]:
        """The active role of *fqid*, or ``None`` if not an active member."""
        if self._status(fqid) is JoinStatus.MEMBER:
            return self._role(fqid)
        return None

    def is_member(self, fqid: str) -> bool:
        """Whether *fqid* is an admitted member of the group."""
        return self._status(fqid) is JoinStatus.MEMBER

    def is_blocked(self, fqid: str) -> bool:
        """Whether *fqid* has been block-for-all'd."""
        return self._status(fqid) is JoinStatus.BLOCKED

    def members(self) -> list[str]:
        """All admitted member FQIDs."""
        return [
            r[0]
            for r in self._conn.execute(
                "SELECT fqid FROM membership WHERE status=?", (JoinStatus.MEMBER.value,)
            )
        ]

    def list_pending(self) -> list[JoinRequest]:
        """Queued knocks / captcha-waiters awaiting review (oldest first)."""
        rows = self._conn.execute(
            "SELECT fqid, updated_at FROM membership WHERE status=? ORDER BY updated_at",
            (JoinStatus.PENDING.value,),
        ).fetchall()
        return [
            JoinRequest(fqid=r[0], group_id=self.group_id,
                        status=JoinStatus.PENDING, requested_at=r[1])
            for r in rows
        ]

    # -- membership / invites --------------------------------------------------

    def add_member(self, fqid: str, *, role: Role = Role.MEMBER) -> None:
        """Directly seat *fqid* as an active member with *role* (owner action)."""
        self._upsert(fqid, role, JoinStatus.MEMBER)

    def invite(self, fqid: str, *, by: Optional[str] = None) -> None:
        """Pre-authorize *fqid* to join an ``invite_only`` group.

        If *by* is given it must be an owner/moderator (fails closed otherwise).
        """
        if by is not None:
            self._require_moderator(by)
        # Never downgrade an existing member/blocked entry to merely invited.
        if self._status(fqid) in (JoinStatus.MEMBER, JoinStatus.BLOCKED):
            return
        self._upsert(fqid, None, JoinStatus.INVITED)

    # -- the join path ---------------------------------------------------------

    def request_join(
        self, fqid: str, *, captcha_answer: Optional[str] = None
    ) -> JoinRequest:
        """Attempt to join. Behaviour depends on ``mode`` (see class docstring).

        Returns a :class:`JoinRequest` whose ``status`` reflects the outcome:
        admitted (:class:`JoinStatus.MEMBER`), queued
        (:class:`JoinStatus.PENDING`), rejected (:class:`JoinStatus.DENIED`), or
        dropped (:class:`JoinStatus.BLOCKED`). Idempotent for an already-admitted
        or already-blocked fqid.
        """
        status = self._status(fqid)
        if status is JoinStatus.BLOCKED:
            return self._req(fqid, JoinStatus.BLOCKED)
        if status is JoinStatus.MEMBER:
            return self._req(fqid, JoinStatus.MEMBER)

        if self.mode == "invite_only":
            if status is JoinStatus.INVITED:
                self._upsert(fqid, Role.MEMBER, JoinStatus.MEMBER)
                return self._req(fqid, JoinStatus.MEMBER)
            self._upsert(fqid, None, JoinStatus.DENIED)
            return self._req(fqid, JoinStatus.DENIED)

        if self.mode == "open":
            if self.captcha is not None and captcha_answer != self.captcha:
                self._upsert(fqid, None, JoinStatus.PENDING)
                return self._req(fqid, JoinStatus.PENDING)
            self._upsert(fqid, Role.MEMBER, JoinStatus.MEMBER)
            return self._req(fqid, JoinStatus.MEMBER)

        # knock — queue for moderator review
        self._upsert(fqid, None, JoinStatus.PENDING)
        return self._req(fqid, JoinStatus.PENDING)

    # -- moderation (role-gated) ----------------------------------------------

    def approve(self, fqid: str, *, by: str) -> JoinRequest:
        """Promote a pending joiner to member. *by* must be owner/moderator."""
        self._require_moderator(by)
        self._upsert(fqid, Role.MEMBER, JoinStatus.MEMBER)
        return self._req(fqid, JoinStatus.MEMBER)

    def deny(self, fqid: str, *, by: Optional[str] = None) -> JoinRequest:
        """Reject a pending joiner. If *by* is given it must be owner/moderator."""
        if by is not None:
            self._require_moderator(by)
        self._upsert(fqid, None, JoinStatus.DENIED)
        return self._req(fqid, JoinStatus.DENIED)

    def block_for_all(self, fqid: str, *, by: str) -> JoinRequest:
        """Block *fqid* for the whole group — dropped, may never re-knock.

        *by* must be owner/moderator. This is SimpleX's delegated "block-for-all":
        the fqid is removed from membership and can no longer join in any mode.
        """
        self._require_moderator(by)
        self._upsert(fqid, None, JoinStatus.BLOCKED)
        return self._req(fqid, JoinStatus.BLOCKED)

    # -- internals -------------------------------------------------------------

    def _require_moderator(self, by: str) -> None:
        role = self.role_of(by)
        if role not in _MODERATOR_ROLES:
            raise PermissionError(
                f"{by!r} (role={role}) may not moderate group {self.group_id!r}; "
                "owner or moderator required"
            )

    def _req(self, fqid: str, status: JoinStatus) -> JoinRequest:
        row = self._row(fqid)
        ts = row and self._conn.execute(
            "SELECT updated_at FROM membership WHERE fqid=?", (fqid,)
        ).fetchone()[0]
        return JoinRequest(
            fqid=fqid, group_id=self.group_id, status=status,
            requested_at=ts or time.time(),
        )
