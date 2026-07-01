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


# --- SECURITY: captcha seed must not be computable from public inputs --------

def test_captcha_seed_not_derivable_from_public_inputs():
    """An attacker who knows only PUBLIC inputs (group_id + fqid) must NOT be
    able to precompute the captcha answer and self-admit without human/bot
    interaction. The join seed must mix a per-group server-side secret so
    ``derive_challenge(public_only)`` does not yield the real answer.
    """
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER, require_captcha=True)
    res = g.join_decision(GID, STRANGER)
    assert res.status is JoinStatus.PENDING
    assert res.challenge_id

    # The attacker knows the group_id and their own fqid — nothing else.
    # If the seed were public (f"{group_id}:{fqid}") they could compute the
    # answer offline and self-admit. That MUST fail now.
    attacker_seed = f"{GID}:{STRANGER}"
    _, _, attacker_answer = derive_challenge(attacker_seed)
    admitted = g.admit(
        GID, STRANGER, challenge_id=res.challenge_id, captcha_answer=attacker_answer
    )
    assert admitted.status is not JoinStatus.MEMBER
    assert not g.is_member(GID, STRANGER)


def test_per_group_secret_persists_and_verify_still_works():
    """The per-group secret is persisted (survives fresh gate handles) and the
    legitimate issuer/bot path (verify via the surfaced seed) still admits.
    """
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER, require_captcha=True)
    res = g.join_decision(GID, STRANGER)

    # A fresh gate over the same home re-reads the same secret → same answer.
    g2 = _gate()
    g2.configure_group(GID, mode="open", owner=OWNER, require_captcha=True)
    _, _, answer = derive_challenge(res.seed)
    ok = g2.admit(GID, STRANGER, challenge_id=res.challenge_id, captcha_answer=answer)
    assert ok.status is JoinStatus.MEMBER
    assert g2.is_member(GID, STRANGER)


# --- SECURITY: ban-gate must fail closed independent of mode -----------------

def test_banned_fqid_rejected_on_captcha_admit_path():
    """A block-for-all'd FQID must be rejected at admit BEFORE any captcha
    verification — the open/captcha path must not fail open on a ban.
    """
    g = _gate()
    g.configure_group(GID, mode="open", owner=OWNER, require_captcha=True)
    res = g.join_decision(GID, STRANGER)
    # Moderator bans the stranger while they hold a live challenge.
    g.block_for_all(GID, STRANGER, by=OWNER)

    # Even with a *correct* answer, a banned peer is never admitted.
    _, _, answer = derive_challenge(res.seed)
    out = g.admit(GID, STRANGER, challenge_id=res.challenge_id, captcha_answer=answer)
    assert out.status is JoinStatus.BLOCKED
    assert not g.is_member(GID, STRANGER)


def test_banned_fqid_rejected_on_moderator_admit_path():
    """A ban also fails closed on the moderator-approval admit path."""
    g = _gate()
    g.configure_group(GID, mode="knock", owner=OWNER)
    g.join_decision(GID, STRANGER)
    g.block_for_all(GID, STRANGER, by=OWNER)
    out = g.admit(GID, STRANGER, by=OWNER)
    assert out.status is JoinStatus.BLOCKED
    assert not g.is_member(GID, STRANGER)


# --- persistence: a fresh gate re-reads admitted state -----------------------

def test_membership_persists_across_gate_handles():
    g = _gate()
    g.configure_group(GID, mode="knock", owner=OWNER)
    g.join_decision(GID, STRANGER)
    g.admit(GID, STRANGER, by=OWNER)

    g2 = _gate()
    g2.configure_group(GID, mode="knock", owner=OWNER)
    assert g2.is_member(GID, STRANGER)
