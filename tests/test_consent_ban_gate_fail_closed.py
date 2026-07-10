"""The consent ban gate rejects independently of tiering and FAILS CLOSED (coord ad0c4c01).

Old bad behaviour (must stay dead):

* ``SKCOMMS_CONSENT_MODE=off`` (the default) skipped the ban gate entirely, so a
  locally blocked or ban-feed-banned sender was delivered anyway.
* ANY exception inside the gate turned into ``deliver`` (fail-open), so a corrupt
  contact store / ban feed admitted banned senders.
* ``tailnet`` mode admitted on network membership; the ban gate must still run
  before that admit.

New pinned behaviour:

* :meth:`ConsentPipeline.ban_gate` runs FIRST in :meth:`ConsentPipeline.decide`,
  before every admit path (tailnet, known contact), and returns a fail-closed
  drop (``ban-gate-error``) when the check itself blows up.
* ``api._consent_classify`` consults the ban gate for EVERY mode, including
  ``off``; a gate that cannot be built or consulted drops (never admits).
* Tiering stays opt-in and fail-open: with the ban gate clean, a tiering error
  still delivers (no federation blackhole).
"""

from __future__ import annotations

import importlib

import pytest

from skcomms.consent import ContactStore
from skcomms.consent_pipeline import ConsentPipeline

SELF_AGENT = "lumina"
SENDER = "mallory@evil.skworld"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.delenv("SKCOMMS_CONSENT_MODE", raising=False)


class _BanStub:
    """A ban subscription stub: bans exactly the given fqids."""

    def __init__(self, banned=()):
        self._banned = set(banned)

    def is_banned(self, fqid: str) -> bool:
        return fqid in self._banned


class _ExplodingBan:
    """A ban subscription whose check itself fails (corrupt feed / store)."""

    def is_banned(self, fqid: str) -> bool:
        raise RuntimeError("boom: ban store unreadable")


# --- pipeline level: ban gate precedes every admit path ---------------------


def test_tailnet_mode_still_drops_blocked_sender():
    ContactStore(SELF_AGENT).block(SENDER)
    out = ConsentPipeline(SELF_AGENT, mode="tailnet").decide(SENDER)
    assert out.decision == "drop"
    assert out.reason == "blocked"


def test_tailnet_mode_still_drops_banfeed_banned_sender():
    p = ConsentPipeline(SELF_AGENT, mode="tailnet", ban_subscription=_BanStub([SENDER]))
    out = p.decide(SENDER)
    assert out.decision == "drop"
    assert out.reason == "ban-feed"


def test_known_contact_banfeed_ban_still_drops():
    """A ban wins over the known-contact fast path (ban gate runs first)."""
    ContactStore(SELF_AGENT).accept(SENDER)
    p = ConsentPipeline(SELF_AGENT, ban_subscription=_BanStub([SENDER]))
    assert p.decide(SENDER).decision == "drop"


@pytest.mark.parametrize("mode", ["public", "tailnet"])
def test_ban_check_error_fails_closed_in_every_mode(mode):
    """An exploding ban check drops (never admits), regardless of mode."""
    p = ConsentPipeline(SELF_AGENT, mode=mode, ban_subscription=_ExplodingBan())
    out = p.decide(SENDER)
    assert out.decision == "drop"
    assert out.reason == "ban-gate-error"


def test_contact_store_error_fails_closed(monkeypatch):
    """A blown-up blocked-contact lookup drops too (fail-closed, not fail-open)."""
    import sqlite3

    import skcomms.consent_pipeline as cp

    class _ExplodingStore:
        def __init__(self, agent):
            pass

        def is_blocked(self, fqid):
            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(cp, "ContactStore", _ExplodingStore)
    out = ConsentPipeline(SELF_AGENT).decide(SENDER)
    assert out.decision == "drop"
    assert out.reason == "ban-gate-error"


def test_ban_gate_clean_returns_none_and_stack_proceeds():
    p = ConsentPipeline(SELF_AGENT, ban_subscription=_BanStub())
    assert p.ban_gate(SENDER) is None
    # A clean stranger still flows into the normal tiering stack.
    assert p.decide(SENDER).decision in ("defer", "quarantine")


# --- api level: the gate runs for EVERY mode and fails closed ---------------


@pytest.fixture
def api_mod(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.delenv("SKCOMMS_CONSENT_MODE", raising=False)

    import skcomms.api as api

    importlib.reload(api)
    monkeypatch.setattr(api, "_self_agent", lambda: SELF_AGENT)
    return api


def test_mode_off_blocked_sender_is_dropped(api_mod):
    """OLD BUG: mode off skipped the ban gate and delivered blocked senders."""
    ContactStore(SELF_AGENT).block(SENDER)
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "drop"


def test_mode_off_clean_stranger_still_delivers(api_mod):
    """Legacy opt-out preserved: mode off delivers everything not banned."""
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "deliver"


def test_mode_tailnet_blocked_sender_is_dropped(api_mod, monkeypatch):
    monkeypatch.setenv("SKCOMMS_CONSENT_MODE", "tailnet")
    ContactStore(SELF_AGENT).block(SENDER)
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "drop"


def test_gate_build_failure_fails_closed(api_mod, monkeypatch):
    """OLD BUG: any gate error turned into deliver. Now: unbuildable gate drops."""
    import skcomms.consent_runtime as rt

    def _boom(agent, **kw):
        raise RuntimeError("runtime.yml unreadable")

    monkeypatch.setattr(rt, "build_pipeline", _boom)
    monkeypatch.setenv("SKCOMMS_CONSENT_MODE", "public")
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "drop"
    # And in mode off (the default) the gate still cannot be bypassed.
    monkeypatch.delenv("SKCOMMS_CONSENT_MODE")
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "drop"


def test_ban_gate_raise_fails_closed(api_mod, monkeypatch):
    """A pipeline whose ban_gate itself raises is treated as a drop."""
    import skcomms.consent_runtime as rt

    class _P:
        def ban_gate(self, sender):
            raise RuntimeError("ban gate exploded")

    monkeypatch.setattr(rt, "build_pipeline", lambda agent, **kw: _P())
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "drop"


def test_tiering_error_stays_fail_open_when_ban_gate_clean(api_mod, monkeypatch):
    """With the ban gate clean, a tiering bug must NOT blackhole federation."""
    import skcomms.consent_runtime as rt

    class _P:
        def ban_gate(self, sender):
            return None  # not banned

        def decide(self, sender, token=None):
            raise RuntimeError("tiering exploded")

    monkeypatch.setattr(rt, "build_pipeline", lambda agent, **kw: _P())
    monkeypatch.setenv("SKCOMMS_CONSENT_MODE", "public")
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "deliver"


def test_missing_identities_still_deliver(api_mod):
    """Nothing checkable (empty recipient/sender) keeps the legacy passthrough."""
    assert api_mod._consent_classify("", SENDER) == "deliver"
    assert api_mod._consent_classify(SELF_AGENT, "") == "deliver"


def test_write_to_inbox_drops_blocked_sender_in_mode_off(api_mod, monkeypatch, tmp_path):
    """End to end: the inbox write path discards a blocked sender with mode off."""
    # Redirect ~ so a regression can never write into the real agent inbox.
    monkeypatch.setenv("HOME", str(tmp_path))
    ContactStore(SELF_AGENT).block(SENDER)

    class _Env:
        id = "env-banned-1"
        to_fqid = f"{SELF_AGENT}@chef.skworld"
        from_fqid = SENDER
        body = "let me in"
        consent_token = None

    assert api_mod._write_to_recipient_inbox(_Env()) == ""
