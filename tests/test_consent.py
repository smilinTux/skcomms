"""Consent gate P1 — request-queue / quarantine (skfed-consent-design gate 5).

Discoverability != delivery: an unknown first-contact is quarantined (no notify,
capped), a known/accepted contact is delivered, a blocked sender is dropped, and a
tailnet-mode node treats every (already network-authenticated) sender as delivered.
"""
import pytest

from skcomms.consent import (ConsentDecision, ConsentGate, ContactStore,
                             RequestQueue)

L = "lumina@chef.skworld"
O = "opus@chef.skworld"
J = "jarvis@chef.skworld"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    return ContactStore(agent="lumina")


def test_unknown_sender_is_quarantined(store):
    gate = ConsentGate(store)
    assert gate.classify(O) is ConsentDecision.QUARANTINE


def test_known_contact_is_delivered(store):
    store.accept(O)
    gate = ConsentGate(store)
    assert gate.classify(O) is ConsentDecision.DELIVER
    assert store.is_known(O)


def test_blocked_sender_is_dropped(store):
    store.block(J)
    gate = ConsentGate(store)
    assert gate.classify(J) is ConsentDecision.DROP
    assert store.is_blocked(J)


def test_block_overrides_known(store):
    store.accept(J)
    store.block(J)
    gate = ConsentGate(store)
    assert gate.classify(J) is ConsentDecision.DROP


def test_tailnet_mode_delivers_unknown(store):
    # Mode B: every sender is already a network-authenticated tailnet member,
    # so consent is by construction — no quarantine.
    gate = ConsentGate(store, mode="tailnet")
    assert gate.classify(O) is ConsentDecision.DELIVER


def test_tailnet_mode_still_drops_blocked(store):
    store.block(J)
    gate = ConsentGate(store, mode="tailnet")
    assert gate.classify(J) is ConsentDecision.DROP


def test_accept_promotes_and_persists(store, tmp_path, monkeypatch):
    store.accept(O)
    # A fresh store over the same home sees the accepted contact (persisted).
    store2 = ContactStore(agent="lumina")
    assert store2.is_known(O)


def test_per_agent_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    ContactStore(agent="lumina").accept(O)
    # opus's store must NOT see lumina's accepted contacts.
    assert not ContactStore(agent="opus").is_known(O)


def test_request_queue_enqueue_list_accept(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    store = ContactStore(agent="lumina")
    q = RequestQueue(agent="lumina")
    q.enqueue(O, b"first hello", envelope_id="e1")
    reqs = q.list_requests()
    assert len(reqs) == 1 and reqs[0].sender == O
    # Accepting a request promotes the sender to a known contact + clears the queue.
    q.accept_request(O, store=store)
    assert store.is_known(O)
    assert q.list_requests() == []


def test_request_queue_caps_per_sender(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    q = RequestQueue(agent="lumina", cap_per_sender=1)
    assert q.enqueue(O, b"m1", envelope_id="e1") is True
    # second knock from the same unknown sender is refused (anti-spam cap)
    assert q.enqueue(O, b"m2", envelope_id="e2") is False
    assert len(q.list_requests()) == 1
