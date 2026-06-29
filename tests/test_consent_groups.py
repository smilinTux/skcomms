"""Group-join consent P4 — SimpleX toolkit (skfed-consent-design gate, sec. 4).

Groups are invite-only by default, never join-from-directory. Three admission
modes: ``invite_only`` (un-invited strangers rejected), ``knock`` (queued for
moderator review), ``open`` (admitted, still subject to a captcha if one is set).
Roles owner/moderator/member gate moderation: a moderator can approve a pending
joiner, deny it, or block-for-all; a plain member cannot.
"""
import pytest

from skcomms.consent_groups import (GroupJoinPolicy, JoinRequest, JoinStatus,
                                     Role)

OWNER = "lumina@chef.skworld"
MOD = "opus@chef.skworld"
MEMBER = "jarvis@chef.skworld"
STRANGER = "mallory@evil.skworld"
GID = "skfed-builders"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))


def _policy(mode, **kw):
    p = GroupJoinPolicy(GID, mode=mode, owner=OWNER, **kw)
    return p


# --- mode: invite_only --------------------------------------------------------

def test_invite_only_rejects_stranger():
    p = _policy("invite_only")
    req = p.request_join(STRANGER)
    assert req.status is JoinStatus.DENIED
    assert not p.is_member(STRANGER)


def test_invite_only_admits_invited():
    p = _policy("invite_only")
    p.invite(MEMBER, by=OWNER)
    req = p.request_join(MEMBER)
    assert req.status is JoinStatus.MEMBER
    assert p.is_member(MEMBER)


# --- mode: knock (member review) ---------------------------------------------

def test_knock_queues_for_review():
    p = _policy("knock")
    req = p.request_join(STRANGER)
    assert req.status is JoinStatus.PENDING
    assert not p.is_member(STRANGER)
    pending = p.list_pending()
    assert [r.fqid for r in pending] == [STRANGER]


def test_knock_approve_promotes_to_member():
    p = _policy("knock")
    p.request_join(MEMBER)
    out = p.approve(MEMBER, by=OWNER)
    assert out.status is JoinStatus.MEMBER
    assert p.is_member(MEMBER)
    assert p.list_pending() == []


def test_moderator_can_approve():
    p = _policy("knock")
    p.add_member(MOD, role=Role.MODERATOR)
    p.request_join(STRANGER)
    out = p.approve(STRANGER, by=MOD)
    assert out.status is JoinStatus.MEMBER
    assert p.is_member(STRANGER)


def test_deny_removes_pending():
    p = _policy("knock")
    p.request_join(STRANGER)
    p.deny(STRANGER, by=OWNER)
    assert p.list_pending() == []
    assert not p.is_member(STRANGER)


# --- role enforcement ---------------------------------------------------------

def test_member_cannot_approve():
    p = _policy("knock")
    p.add_member(MEMBER, role=Role.MEMBER)
    p.request_join(STRANGER)
    with pytest.raises(PermissionError):
        p.approve(STRANGER, by=MEMBER)
    assert not p.is_member(STRANGER)


def test_unknown_actor_cannot_approve():
    p = _policy("knock")
    p.request_join(STRANGER)
    with pytest.raises(PermissionError):
        p.approve(STRANGER, by="nobody@nowhere.skworld")


def test_member_cannot_block_for_all():
    p = _policy("knock")
    p.add_member(MEMBER, role=Role.MEMBER)
    with pytest.raises(PermissionError):
        p.block_for_all(STRANGER, by=MEMBER)


# --- moderator block-for-all --------------------------------------------------

def test_moderator_block_for_all():
    p = _policy("knock")
    p.add_member(MOD, role=Role.MODERATOR)
    p.add_member(STRANGER, role=Role.MEMBER)
    p.block_for_all(STRANGER, by=MOD)
    assert not p.is_member(STRANGER)
    assert p.is_blocked(STRANGER)
    # a blocked fqid can no longer knock back in
    req = p.request_join(STRANGER)
    assert req.status is JoinStatus.BLOCKED


# --- mode: open (+ optional captcha) -----------------------------------------

def test_open_admits_immediately():
    p = _policy("open")
    req = p.request_join(STRANGER)
    assert req.status is JoinStatus.MEMBER
    assert p.is_member(STRANGER)


def test_open_with_captcha_queues_until_passed():
    p = _policy("open", captcha="7")
    req = p.request_join(STRANGER)
    assert req.status is JoinStatus.PENDING
    assert not p.is_member(STRANGER)
    # wrong answer keeps it pending
    bad = p.request_join(STRANGER, captcha_answer="3")
    assert bad.status is JoinStatus.PENDING
    # correct captcha answer admits
    ok = p.request_join(STRANGER, captcha_answer="7")
    assert ok.status is JoinStatus.MEMBER
    assert p.is_member(STRANGER)


# --- roles + persistence ------------------------------------------------------

def test_owner_role_and_membership():
    p = _policy("knock")
    assert p.role_of(OWNER) is Role.OWNER
    assert p.is_member(OWNER)


def test_persistence_reload():
    p = _policy("knock", persisted=True)
    p.request_join(STRANGER)
    p.add_member(MOD, role=Role.MODERATOR)
    # fresh handle over the same home re-reads state
    p2 = GroupJoinPolicy(GID, mode="knock", owner=OWNER, persisted=True)
    assert [r.fqid for r in p2.list_pending()] == [STRANGER]
    assert p2.role_of(MOD) is Role.MODERATOR
    out = p2.approve(STRANGER, by=MOD)
    assert out.status is JoinStatus.MEMBER


def test_join_request_dataclass_shape():
    p = _policy("knock")
    req = p.request_join(STRANGER)
    assert isinstance(req, JoinRequest)
    assert req.fqid == STRANGER
    assert req.group_id == GID
    assert req.requested_at > 0
