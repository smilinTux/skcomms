"""Operator surface over the P1 consent primitives (skfed-consent-design gate 5).

These are exactly the calls a ``skcomms consent ...`` CLI / an ``/api/v1/consent``
endpoint makes: list pending knocks, accept (promote + clear), decline (+optional
block), block outright, list known contacts, unblock. The module is a thin,
side-effecting facade over :class:`skcomms.consent.RequestQueue` /
:class:`skcomms.consent.ContactStore` — it owns NO new persistence, so a fresh
process over the same ``SKCOMMS_HOME`` observes every decision (the CLI/daemon
split-process round-trip).
"""
import pytest

from skcomms import consent_requests as cr

L = "lumina@chef.skworld"
O = "opus@chef.skworld"
J = "jarvis@chef.skworld"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))


def _enqueue(agent, sender, body=b"knock", envelope_id="e1"):
    """Quarantine a first-contact knock the way the inbound gate would."""
    from skcomms.consent import RequestQueue
    RequestQueue(agent).enqueue(sender, body, envelope_id=envelope_id)


# --- list ---------------------------------------------------------------

def test_list_requests_shape_and_enqueue_then_list():
    _enqueue("lumina", O, envelope_id="e1")
    reqs = cr.list_requests("lumina")
    assert len(reqs) == 1
    r = reqs[0]
    assert r["sender"] == O
    assert r["envelope_id"] == "e1"
    assert isinstance(r["received_at"], float)
    # exact operator-surface contract: only these three keys
    assert set(r.keys()) == {"sender", "envelope_id", "received_at"}


def test_list_requests_empty_when_nothing_queued():
    assert cr.list_requests("lumina") == []


# --- accept -------------------------------------------------------------

def test_accept_promotes_to_known_and_clears_queue():
    _enqueue("lumina", O, envelope_id="e1")
    cr.accept_request("lumina", O)
    assert O in cr.list_known("lumina")
    assert cr.list_requests("lumina") == []


# --- decline / block ----------------------------------------------------

def test_decline_clears_queue_without_blocking():
    _enqueue("lumina", O, envelope_id="e1")
    cr.decline_request("lumina", O)
    assert cr.list_requests("lumina") == []
    # plain decline does not block — a future knock is not pre-dropped
    from skcomms.consent import ContactStore
    assert not ContactStore("lumina").is_blocked(O)


def test_decline_with_block_blocks_sender():
    _enqueue("lumina", J, envelope_id="e1")
    cr.decline_request("lumina", J, block=True)
    assert cr.list_requests("lumina") == []
    from skcomms.consent import ContactStore
    assert ContactStore("lumina").is_blocked(J)


def test_block_sender_blocks_directly():
    cr.block_sender("lumina", J)
    from skcomms.consent import ContactStore
    assert ContactStore("lumina").is_blocked(J)


# --- list_known ---------------------------------------------------------

def test_list_known_reflects_accepts():
    assert cr.list_known("lumina") == []
    _enqueue("lumina", O, envelope_id="e1")
    cr.accept_request("lumina", O)
    assert cr.list_known("lumina") == [O]


# --- unblock ------------------------------------------------------------

def test_unblock_removes_block():
    cr.block_sender("lumina", J)
    from skcomms.consent import ContactStore
    assert ContactStore("lumina").is_blocked(J)
    cr.unblock("lumina", J)
    assert not ContactStore("lumina").is_blocked(J)
    # unblock returns a sender to UNKNOWN (not auto-trusted)
    assert not ContactStore("lumina").is_known(J)


def test_unblock_noop_when_not_blocked():
    # idempotent / safe on an unknown sender
    cr.unblock("lumina", O)
    from skcomms.consent import ContactStore
    assert not ContactStore("lumina").is_blocked(O)


# --- persistence / split-process round-trip -----------------------------

def test_round_trips_via_fresh_stores(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    _enqueue("lumina", O, envelope_id="e1")
    cr.accept_request("lumina", O)
    cr.block_sender("lumina", J)
    # Simulate a brand-new process (CLI invocation) over the same home:
    # nothing is cached in-process, the SQLite stores are the source of truth.
    assert cr.list_known("lumina") == [O]
    from skcomms.consent import ContactStore
    assert ContactStore("lumina").is_blocked(J)
    assert cr.list_requests("lumina") == []


def test_per_agent_isolation():
    _enqueue("lumina", O, envelope_id="e1")
    cr.accept_request("lumina", O)
    # opus's surface must not see lumina's contacts/queue
    assert cr.list_known("opus") == []
    assert cr.list_requests("opus") == []
