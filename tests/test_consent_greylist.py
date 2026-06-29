"""Greylisting — the email first-contact speed-bump that REPLACES proof-of-work.

Per the round-2 design verdict (``docs/skfed-consent-design.md``): PoW is DROPPED
(Laurie & Clayton, "Proof-of-Work proves not to work") and greylisting is ADDED as
the cheap, no-central-server first-contact friction. First sighting of an unknown
sender is temp-deferred ('defer'); a retry after ``min_delay_s`` is admitted
('admit'). Legitimate senders retry; naive bulk spammers (fire-and-forget) never do.

Clock is injected so the delay is testable without sleeping.
"""
import pytest

from skcomms.consent_greylist import Greylist

S = "spammer@nowhere.skworld"
L = "lumina@chef.skworld"


@pytest.fixture
def greylist(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    return Greylist(agent="lumina")


def test_first_contact_defers(greylist):
    assert greylist.see(S, now=1000.0) == "defer"


def test_retry_before_delay_still_defers(greylist):
    greylist.see(S, now=1000.0)
    # 59s later — under the 60s default min_delay → still grey.
    assert greylist.see(S, now=1059.0) == "defer"


def test_retry_after_delay_admits(greylist):
    greylist.see(S, now=1000.0)
    # 61s later — past the 60s window → admitted.
    assert greylist.see(S, now=1061.0) == "admit"


def test_admitted_sender_stays_admitted(greylist):
    greylist.see(S, now=1000.0)
    assert greylist.see(S, now=1061.0) == "admit"
    # Subsequent sightings (even immediately) keep admitting.
    assert greylist.see(S, now=1061.5) == "admit"
    assert greylist.see(S, now=2000.0) == "admit"


def test_injected_clock_controls_delay(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    gl = Greylist(agent="lumina", min_delay_s=10)
    assert gl.see(L, now=500.0) == "defer"
    assert gl.see(L, now=509.0) == "defer"   # 9s < 10s
    assert gl.see(L, now=510.0) == "admit"   # exactly at window boundary


def test_sightings_are_tracked_and_persisted(greylist, tmp_path):
    greylist.see(S, now=1000.0)
    greylist.see(S, now=1059.0)
    greylist.see(S, now=1061.0)
    rec = greylist.record(S)
    assert rec is not None
    assert rec.sender == S
    assert rec.first_seen == 1000.0
    assert rec.sightings == 3
    # A fresh instance reads the persisted state (same SKCOMMS_HOME/agent).
    fresh = Greylist(agent="lumina")
    assert fresh.record(S).sightings == 3
    assert fresh.see(S, now=5000.0) == "admit"


def test_unknown_sender_has_no_record(greylist):
    assert greylist.record("ghost@void.skworld") is None


def test_per_agent_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    a = Greylist(agent="lumina")
    b = Greylist(agent="jarvis")
    a.see(S, now=1000.0)
    # jarvis has never seen S → its own first contact defers independently.
    assert b.see(S, now=1000.0) == "defer"
    assert b.record(S).sightings == 1
    assert a.record(S).sightings == 1
