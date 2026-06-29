"""Shadow-block + consent-gated reporting — SimpleX + MlsGov (design sec. 4 & 5).

Two moderation primitives the design draws from the strongest primary sources:

* **Shadow-block** (SimpleX, sec. 4) — hide a suspected attacker's messages from
  *everyone* while **their own view is unchanged** (they keep talking, unaware).
* **Consent-gated reporting** (MlsGov, sec. 5) — only a message a user *explicitly
  reports* becomes visible to a moderator; the report carries **minimal metadata
  only** (message id + reporter + reason — never content); unreported messages
  leave **no record at all**.
"""
import pytest

from skcomms.consent_moderation import Report, ReportLog, ShadowBlockSet

GID = "skfed-builders"
OWNER = "lumina@chef.skworld"
ALICE = "alice@chef.skworld"
BOB = "bob@chef.skworld"
MALLORY = "mallory@evil.skworld"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))


# --- shadow-block -------------------------------------------------------------

def test_shadow_blocked_hidden_from_others():
    sb = ShadowBlockSet(GID)
    sb.shadow_block(MALLORY)
    assert sb.is_shadow_blocked(MALLORY)
    # a shadow-blocked sender's messages are hidden from everyone else
    assert sb.visible_to(ALICE, MALLORY) is False
    assert sb.visible_to(BOB, MALLORY) is False
    assert sb.visible_to(OWNER, MALLORY) is False


def test_shadow_blocked_visible_to_self():
    sb = ShadowBlockSet(GID)
    sb.shadow_block(MALLORY)
    # their OWN view is unchanged — they still see their own messages
    assert sb.visible_to(MALLORY, MALLORY) is True


def test_non_blocked_visible_to_everyone():
    sb = ShadowBlockSet(GID)
    assert sb.visible_to(ALICE, BOB) is True
    assert sb.visible_to(BOB, ALICE) is True
    assert sb.visible_to(ALICE, ALICE) is True


def test_unblock_restores_visibility():
    sb = ShadowBlockSet(GID)
    sb.shadow_block(MALLORY)
    assert sb.visible_to(ALICE, MALLORY) is False
    sb.unblock(MALLORY)
    assert not sb.is_shadow_blocked(MALLORY)
    # unblock restores visibility to everyone
    assert sb.visible_to(ALICE, MALLORY) is True
    assert sb.visible_to(BOB, MALLORY) is True


def test_shadow_block_persists_across_handles():
    sb = ShadowBlockSet(GID, persisted=True)
    sb.shadow_block(MALLORY)
    sb2 = ShadowBlockSet(GID, persisted=True)
    assert sb2.is_shadow_blocked(MALLORY)
    assert sb2.visible_to(ALICE, MALLORY) is False


def test_shadow_block_scoped_per_group():
    sb_a = ShadowBlockSet("group-a", persisted=True)
    sb_b = ShadowBlockSet("group-b", persisted=True)
    sb_a.shadow_block(MALLORY)
    # blocking in one group does not bleed into another
    assert sb_a.is_shadow_blocked(MALLORY)
    assert not sb_b.is_shadow_blocked(MALLORY)


# --- consent-gated reporting (MlsGov) -----------------------------------------

def test_report_stored_minimal():
    log = ReportLog(GID)
    rep = log.file_report("msg-123", reporter=ALICE, reason="spam")
    assert isinstance(rep, Report)
    assert rep.message_id == "msg-123"
    assert rep.reporter == ALICE
    assert rep.reason == "spam"
    assert rep.reported_at > 0
    # a moderator can list it
    listed = log.list_reports()
    assert [r.message_id for r in listed] == ["msg-123"]
    assert log.is_reported("msg-123")


def test_report_carries_no_content_field():
    log = ReportLog(GID)
    rep = log.file_report("msg-9", reporter=ALICE, reason="abuse")
    # the record exposes ONLY minimal metadata — never message content
    fields = set(vars(rep).keys())
    assert fields == {"message_id", "reporter", "reason", "reported_at"}
    assert "content" not in fields
    assert "body" not in fields


def test_no_report_no_record():
    log = ReportLog(GID)
    # an unreported message leaves no record whatsoever
    assert log.list_reports() == []
    assert not log.is_reported("msg-never-reported")
    # filing one report does not conjure records for other messages
    log.file_report("msg-1", reporter=ALICE, reason="spam")
    assert not log.is_reported("msg-2")
    assert [r.message_id for r in log.list_reports()] == ["msg-1"]


def test_reports_persist_across_handles():
    log = ReportLog(GID, persisted=True)
    log.file_report("msg-77", reporter=BOB, reason="harassment")
    log2 = ReportLog(GID, persisted=True)
    assert log2.is_reported("msg-77")
    rep = log2.list_reports()[0]
    assert rep.reporter == BOB
    assert rep.reason == "harassment"


def test_reports_scoped_per_group():
    log_a = ReportLog("group-a", persisted=True)
    log_b = ReportLog("group-b", persisted=True)
    log_a.file_report("msg-x", reporter=ALICE, reason="spam")
    assert log_a.is_reported("msg-x")
    assert not log_b.is_reported("msg-x")
    assert log_b.list_reports() == []
