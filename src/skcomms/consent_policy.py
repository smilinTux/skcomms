"""Invite / contact-filter policy — Matrix MSC4155 semantics (consent gate 3-ish).

The first-contact stack (:mod:`skcomms.consent`) decides *delivery vs quarantine*
for unknown senders. **This module is the prior, explicit allow/block/ignore
filter** the recipient configures by hand — Matrix's MSC4155 invite-filtering,
reconstructed as a sovereign, per-agent, persisted policy.

MSC4155 (merged in Synapse behind a flag; see ``docs/skfed-consent-design.md``
round-3 §"Nostr + Matrix-invite") allows server-enforceable invite filtering with
three verbs — **allow / block / ignore** — at two granularities — **user** and
**server**. ``ignore`` means *silently quarantine* (excluded from sync + push);
``block`` is a hard reject the user can still see; ``allow`` is an explicit
exemption that overrides a broader block.

Deterministic precedence (the whole point — no ambiguity):

1. **Granularity:** user rules beat server rules (most-specific wins).
2. **Verb (within a granularity):** ``allow`` > ``ignore`` > ``block`` — if the
   same target sits in two sets, the most permissive verb wins.
3. **Disabled policy** (the default) → pure pass-through, everything ``allow``.
4. **Enabled, no rule matches** → default ``allow`` (a filter blocks the listed,
   not the unlisted).

``server`` is the ``operator.realm`` part of an ``<agent>@<operator>.<realm>``
fqid (everything after the ``@``). Server entries are matched as **globs**
(:func:`fnmatch.fnmatch`), so ``*.relay`` or ``*`` work; an exact string is just a
glob with no wildcards. User entries match exactly.

Persistence: one JSON file per agent under
``$SKCOMMS_HOME/consent/<agent>/invite_policy.json`` (Syncthing-shareable,
isolated per agent — same home tree as :mod:`skcomms.consent`).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional, Set

from .home import skcomms_home


class InviteDecision(str, Enum):
    """The MSC4155 verbs. ``str`` subclass → compares equal to its value."""

    ALLOW = "allow"     #: deliver / let the invite through
    IGNORE = "ignore"   #: silently quarantine (no sync, no push)
    BLOCK = "block"     #: hard reject (user-visible)


def server_of(fqid: str) -> str:
    """Return the ``operator.realm`` server part of an ``a@o.r`` fqid.

    Falls back to the whole string if there is no ``@`` (already a bare server).
    """
    return fqid.split("@", 1)[1] if "@" in fqid else fqid


def _policy_path(agent: str) -> Path:
    return skcomms_home() / "consent" / agent / "invite_policy.json"


@dataclass
class InvitePolicy:
    """Per-agent invite/contact filter with MSC4155 allow/block/ignore semantics.

    Args:
        agent: Short agent name (the persistence + isolation key).
        enabled: Master switch. ``False`` (default) → :meth:`evaluate` always
            returns ``allow`` (pass-through).
        allowed_users / ignored_users / blocked_users: exact-match fqids.
        allowed_servers / ignored_servers / blocked_servers: glob patterns
            matched against the sender's ``operator.realm`` server.
    """

    agent: str
    enabled: bool = False
    allowed_users: Set[str] = field(default_factory=set)
    ignored_users: Set[str] = field(default_factory=set)
    blocked_users: Set[str] = field(default_factory=set)
    allowed_servers: Set[str] = field(default_factory=set)
    ignored_servers: Set[str] = field(default_factory=set)
    blocked_servers: Set[str] = field(default_factory=set)

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, sender_fqid: str) -> InviteDecision:
        """Classify *sender_fqid* → :class:`InviteDecision` (``allow``/``ignore``/``block``).

        Deterministic MSC4155 order: user granularity first (allow > ignore >
        block), then server granularity (allow > ignore > block), else the
        default ``allow``. A disabled policy short-circuits to ``allow``.
        """
        if not self.enabled:
            return InviteDecision.ALLOW

        # 1. user granularity (most specific) — allow > ignore > block.
        if sender_fqid in self.allowed_users:
            return InviteDecision.ALLOW
        if sender_fqid in self.ignored_users:
            return InviteDecision.IGNORE
        if sender_fqid in self.blocked_users:
            return InviteDecision.BLOCK

        # 2. server granularity (glob) — allow > ignore > block.
        server = server_of(sender_fqid)
        if self._server_match(server, self.allowed_servers):
            return InviteDecision.ALLOW
        if self._server_match(server, self.ignored_servers):
            return InviteDecision.IGNORE
        if self._server_match(server, self.blocked_servers):
            return InviteDecision.BLOCK

        # 3. no rule matched → permissive default.
        return InviteDecision.ALLOW

    @staticmethod
    def _server_match(server: str, patterns: Set[str]) -> bool:
        return any(fnmatch(server, pat) for pat in patterns)

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "enabled": self.enabled,
            "allowed_users": sorted(self.allowed_users),
            "ignored_users": sorted(self.ignored_users),
            "blocked_users": sorted(self.blocked_users),
            "allowed_servers": sorted(self.allowed_servers),
            "ignored_servers": sorted(self.ignored_servers),
            "blocked_servers": sorted(self.blocked_servers),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InvitePolicy":
        return cls(
            agent=data["agent"],
            enabled=bool(data.get("enabled", False)),
            allowed_users=set(data.get("allowed_users", [])),
            ignored_users=set(data.get("ignored_users", [])),
            blocked_users=set(data.get("blocked_users", [])),
            allowed_servers=set(data.get("allowed_servers", [])),
            ignored_servers=set(data.get("ignored_servers", [])),
            blocked_servers=set(data.get("blocked_servers", [])),
        )

    def save(self) -> Path:
        """Persist this policy to ``$SKCOMMS_HOME/consent/<agent>/invite_policy.json``."""
        path = _policy_path(self.agent)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True),
                        encoding="utf-8")
        return path

    @classmethod
    def load(cls, agent: str) -> "InvitePolicy":
        """Load *agent*'s policy; a missing file → disabled (pass-through) default."""
        path = _policy_path(agent)
        if not path.exists():
            return cls(agent=agent)
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)
