"""Invite / contact-filter policy — Matrix MSC4155 semantics (gate, design §round-3).

MSC4155 gives server-enforceable invite filtering with allow / block / **ignore**
at **user AND server** granularity. This module reconstructs those exact semantics
as a per-agent, persisted :class:`InvitePolicy` whose :meth:`evaluate` returns the
deterministic decision for an incoming ``sender_fqid``.

Precedence (deterministic, MSC4155):
  * **user granularity beats server granularity** (the most specific rule wins);
  * within a granularity: **allow > ignore > block** (a sender listed in two sets
    at the same granularity resolves to the most permissive — allow over ignore
    over block);
  * a disabled policy is a pass-through → everything ``allow``.

``server`` = the ``operator.realm`` part of an ``<agent>@<operator>.<realm>`` fqid.
"""
from __future__ import annotations

import pytest

from skcomms.consent_policy import InvitePolicy

L = "lumina@chef.skworld"          # server = chef.skworld
O = "opus@chef.skworld"            # server = chef.skworld
SPAM = "bot01@spam.relay"          # server = spam.relay
ANON = "k7x9q@anon.relay"          # server = anon.relay


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    return tmp_path


# --- default / disabled ----------------------------------------------------


def test_disabled_passes_all(home):
    # enabled defaults to False → pure pass-through, even for a "blocked" sender.
    p = InvitePolicy("lumina", blocked_users={SPAM}, blocked_servers={"spam.relay"})
    assert p.enabled is False
    assert p.evaluate(SPAM) == "allow"
    assert p.evaluate(L) == "allow"


def test_enabled_no_match_defaults_allow(home):
    p = InvitePolicy("lumina", enabled=True)
    assert p.evaluate(L) == "allow"


# --- user-granularity precedence: allow > ignore > block -------------------


def test_user_allow(home):
    p = InvitePolicy("lumina", enabled=True, allowed_users={L})
    assert p.evaluate(L) == "allow"


def test_user_ignore(home):
    p = InvitePolicy("lumina", enabled=True, ignored_users={SPAM})
    assert p.evaluate(SPAM) == "ignore"


def test_user_block(home):
    p = InvitePolicy("lumina", enabled=True, blocked_users={SPAM})
    assert p.evaluate(SPAM) == "block"


def test_user_allow_beats_ignore(home):
    p = InvitePolicy("lumina", enabled=True, allowed_users={L}, ignored_users={L})
    assert p.evaluate(L) == "allow"


def test_user_ignore_beats_block(home):
    p = InvitePolicy("lumina", enabled=True, ignored_users={SPAM}, blocked_users={SPAM})
    assert p.evaluate(SPAM) == "ignore"


def test_user_allow_beats_block(home):
    p = InvitePolicy("lumina", enabled=True, allowed_users={SPAM}, blocked_users={SPAM})
    assert p.evaluate(SPAM) == "allow"


# --- server-granularity precedence -----------------------------------------


def test_server_allow(home):
    p = InvitePolicy("lumina", enabled=True, allowed_servers={"chef.skworld"})
    assert p.evaluate(L) == "allow"


def test_server_ignore(home):
    p = InvitePolicy("lumina", enabled=True, ignored_servers={"spam.relay"})
    assert p.evaluate(SPAM) == "ignore"


def test_server_block(home):
    p = InvitePolicy("lumina", enabled=True, blocked_servers={"spam.relay"})
    assert p.evaluate(SPAM) == "block"


def test_server_allow_beats_block(home):
    p = InvitePolicy("lumina", enabled=True,
                     allowed_servers={"spam.relay"}, blocked_servers={"spam.relay"})
    assert p.evaluate(SPAM) == "allow"


# --- user beats server -----------------------------------------------------


def test_user_allow_beats_server_block(home):
    # block the whole realm, but explicitly allow one user on it → user wins.
    p = InvitePolicy("lumina", enabled=True,
                     allowed_users={L}, blocked_servers={"chef.skworld"})
    assert p.evaluate(L) == "allow"
    # a *different* user on the blocked server still gets blocked.
    assert p.evaluate(O) == "block"


def test_user_block_beats_server_allow(home):
    # trust the realm, but a single user is blocked → user wins.
    p = InvitePolicy("lumina", enabled=True,
                     blocked_users={O}, allowed_servers={"chef.skworld"})
    assert p.evaluate(O) == "block"
    assert p.evaluate(L) == "allow"


def test_user_ignore_beats_server_allow(home):
    p = InvitePolicy("lumina", enabled=True,
                     ignored_users={O}, allowed_servers={"chef.skworld"})
    assert p.evaluate(O) == "ignore"


# --- server glob -----------------------------------------------------------


def test_server_glob(home):
    p = InvitePolicy("lumina", enabled=True, blocked_servers={"*.relay"})
    assert p.evaluate(SPAM) == "block"
    assert p.evaluate(ANON) == "block"
    assert p.evaluate(L) == "allow"


def test_server_glob_star_matches_all(home):
    # default-deny posture: ignore every server, allow only an explicit user.
    p = InvitePolicy("lumina", enabled=True,
                     ignored_servers={"*"}, allowed_users={L})
    assert p.evaluate(L) == "allow"       # user allow beats server ignore
    assert p.evaluate(SPAM) == "ignore"


# --- persistence -----------------------------------------------------------


def test_save_load_roundtrip(home):
    p = InvitePolicy("lumina", enabled=True,
                     allowed_users={L}, blocked_users={SPAM},
                     ignored_servers={"*.relay"})
    p.save()
    q = InvitePolicy.load("lumina")
    assert q.enabled is True
    assert q.allowed_users == {L}
    assert q.blocked_users == {SPAM}
    assert q.ignored_servers == {"*.relay"}
    assert q.evaluate(L) == "allow"
    assert q.evaluate(SPAM) == "block"
    assert q.evaluate(ANON) == "ignore"


def test_load_missing_returns_disabled_default(home):
    p = InvitePolicy.load("nobody")
    assert p.enabled is False
    assert p.evaluate(SPAM) == "allow"


def test_per_agent_isolation(home):
    a = InvitePolicy("lumina", enabled=True, blocked_users={SPAM})
    a.save()
    b = InvitePolicy.load("jarvis")
    assert b.enabled is False
    assert b.evaluate(SPAM) == "allow"
