"""GroupConsentGate — wire the group-consent modules into ONE gate (design sec. 4 & 5).

The 1:1 first-contact gate gives DMs knock -> review -> admit + moderation. This
gate gives *groups* the same protection by composing the already-built primitives:

* :class:`skcomms.consent_groups.GroupJoinPolicy` — invite_only / knock / open
  admission + owner/moderator roles.
* :class:`skcomms.consent_captcha.Captcha` — bot-issued, no-3rd-party captcha that
  must verify before an open-mode joiner is admitted.
* :class:`skcomms.consent_moderation.ShadowBlockSet` — a shadow-blocked member's
  messages are hidden from everyone but themselves.
* :class:`skcomms.consent_moderation.ReportLog` — consent-gated abuse reporting.

Clean gate API: ``join_decision(group_id, fqid)`` / ``admit(group_id, fqid, ...)`` /
``visible(group_id, viewer, sender)``.
"""
import pytest

from skcomms.consent_captcha import derive_challenge
from skcomms.consent_group_gate import GroupConsentGate, GroupJoinResult
from skcomms.consent_groups import JoinStatus

OWNER = "lumina@chef.skworld"
MOD = "opus@chef.skworld"
MEMBER = "jarvis@chef.skworld"
STRANGER = "mallory@evil.skworld"
GID = "skfed-builders"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))


def _gate():
    return GroupConsentGate(agent="lumina")


# --- invite_only: stranger rejected ------------------------------------------

def test_invite_only_rejects_stranger():
    g = _gate()
    g.configure_group(GID, mode="invite_only", owner=OWNER)
    res = g.join_decision(GID, STRANGER)
    assert isinstance(res, GroupJoinResult)
    assert res.status is JoinStatus.DENIED
    assert not g.is_member(GID, STRANGER)


def test_invite_only_admits_invited():
    g = _gate()
    g.configure_group(GID, mode="invite_only", owner=OWNER)
    g.invite(GID, MEMBER, by=OWNER)
    res = g.join_decision(GID, MEMBER)
    assert res.status is JoinStatus.MEMBER
    assert g.is_member(GID, MEMBER)


# --- knock: queue -> moderator-approve -> admit ------------------------------

def test_knock_queues_then_moderator_admits():
    g = _gate()
    g.configure_group(GID, mode="knock", owner=OWNER)
    res = g.join_decision(GID, STRANGER)
    assert res.status is JoinStatus.PENDING
    assert not g.is_member(GID, STRANGER)
    # the knock is visible to the moderator's review queue
    assert STRANGER in [r.fqid for r in g.list_pending(GID)]
    # owner/moderator approves -> admitted
    admitted = g.admit(GID, STRANGER, by=OWNER)
    assert admitted.status is JoinStatus.MEMBER
    assert g.is_member(GID, STRANGER)


def test_knock_plain_member_cannot_admit():
    g = _gate()
    g.configure_group(GID, mode="knock", owner=OWNER)
    g.add_member(GID, MEMBER)  # ordinary member
    g.join_decision(GID, STRANGER)
    with pytest.raises(PermissionError):
        g.admit(GID, STRANGER, by=MEMBER)
    assert not g.is_member(GID, STRANGER)


# --- captcha-gated join (open mode, captcha required) ------------------------

def test_captcha_gated_join_admits_only_on_verify():
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER, require_captcha=True)
    res = g.join_decision(GID, STRANGER)
    # held pending behind a captcha — NOT admitted yet
    assert res.status is JoinStatus.PENDING
    assert res.captcha_required is True
    assert res.challenge_id
    assert not g.is_member(GID, STRANGER)

    # wrong answer keeps them out
    bad = g.admit(GID, STRANGER, challenge_id=res.challenge_id, captcha_answer="999999")
    assert bad.status is JoinStatus.PENDING
    assert not g.is_member(GID, STRANGER)

    # the bot's derived answer admits
    _, _, answer = derive_challenge(res.seed)
    ok = g.admit(GID, STRANGER, challenge_id=res.challenge_id, captcha_answer=answer)
    assert ok.status is JoinStatus.MEMBER
    assert g.is_member(GID, STRANGER)


def test_open_without_captcha_admits_immediately():
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER)
    res = g.join_decision(GID, STRANGER)
    assert res.status is JoinStatus.MEMBER
    assert res.captcha_required is False
    assert g.is_member(GID, STRANGER)


# --- shadow-block: hidden from others, visible to self -----------------------

def test_shadow_block_hidden_from_others_visible_to_self():
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER)
    g.join_decision(GID, MEMBER)
    g.join_decision(GID, STRANGER)

    # before block, everyone sees the stranger
    assert g.visible(GID, MEMBER, STRANGER) is True

    # moderator shadow-blocks the stranger
    g.shadow_block(GID, STRANGER, by=OWNER)

    # hidden from everyone else...
    assert g.visible(GID, MEMBER, STRANGER) is False
    assert g.visible(GID, OWNER, STRANGER) is False
    # ...but the stranger's own view is unchanged
    assert g.visible(GID, STRANGER, STRANGER) is True
    # non-blocked senders stay visible to all
    assert g.visible(GID, STRANGER, MEMBER) is True


def test_shadow_block_requires_moderator():
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER)
    g.add_member(GID, MEMBER)
    g.join_decision(GID, STRANGER)
    with pytest.raises(PermissionError):
        g.shadow_block(GID, STRANGER, by=MEMBER)
    assert g.visible(GID, MEMBER, STRANGER) is True


# --- consent-gated reporting -------------------------------------------------

def test_report_files_minimal_record():
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER)
    rep = g.report(GID, message_id="msg-42", reporter=MEMBER, reason="spam")
    assert rep.message_id == "msg-42"
    assert rep.reporter == MEMBER
    assert rep.reason == "spam"
    # the report dataclass carries NO content field (metadata only)
    assert not hasattr(rep, "content")
    assert [r.message_id for r in g.list_reports(GID)] == ["msg-42"]


# --- persistence: a fresh gate re-reads admitted state -----------------------

def test_membership_persists_across_gate_handles():
    g = _gate()
    g.configure_group(GID, mode="knock", owner=OWNER)
    g.join_decision(GID, STRANGER)
    g.admit(GID, STRANGER, by=OWNER)

    g2 = _gate()
    g2.configure_group(GID, mode="knock", owner=OWNER)
    assert g2.is_member(GID, STRANGER)
