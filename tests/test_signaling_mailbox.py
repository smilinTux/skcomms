"""Tests for the mailbox signaling backend (sub-project B, sovereign signaling path).

SDP/ICE travel as capauth-signed skcomms envelopes (CALL_SDP_OFFER/ANSWER/ICE),
verified on receipt against the peer's TOFU fingerprint — same mechanism as the
A-phase CALL_INVITE ring (whose signing was fixed 2026-06-11).
"""
from types import SimpleNamespace

import skcomms.transports.signaling_mailbox as sm
from skcomms.transports.signaling_mailbox import (
    SUBJECT_ANSWER,
    SUBJECT_ICE,
    SUBJECT_OFFER,
    MailboxSignaling,
)


def test_kind_subject_mapping_is_bijective():
    assert sm.subject_for_kind("offer") == SUBJECT_OFFER
    assert sm.subject_for_kind("answer") == SUBJECT_ANSWER
    assert sm.subject_for_kind("ice") == SUBJECT_ICE
    assert sm.kind_for_subject(SUBJECT_OFFER) == "offer"
    assert sm.kind_for_subject(SUBJECT_ICE) == "ice"
    assert sm.kind_for_subject("RANDOM") is None


def test_send_signal_writes_signed_envelope(monkeypatch):
    sent = []
    monkeypatch.setattr(
        sm, "send_message",
        lambda to_fqid, message, *, agent=None, subject=None, **kw: sent.append(
            {"to": to_fqid, "message": message, "subject": subject, "agent": agent}
        ) or {"id": "x"},
    )
    chan = MailboxSignaling(agent="opus")
    chan.send_signal("lumina@chef.skworld", "offer", {"type": "offer", "sdp": "v=0..."})
    assert len(sent) == 1
    assert sent[0]["to"] == "lumina@chef.skworld"
    assert sent[0]["subject"] == SUBJECT_OFFER
    assert sent[0]["agent"] == "opus"
    import json
    body = json.loads(sent[0]["message"])
    assert body["kind"] == "offer"
    assert body["payload"]["sdp"] == "v=0..."


def _env(subject, from_fqid, to_fqid, payload, kind):
    import json
    return SimpleNamespace(
        id="e1", subject=subject, from_fqid=from_fqid, to_fqid=to_fqid,
        body=json.dumps({"kind": kind, "payload": payload}),
    )


def test_poll_signals_returns_only_verified_self_addressed(monkeypatch):
    monkeypatch.setattr(sm, "_self_fqid", lambda agent=None: "lumina@chef.skworld")
    inbox = [
        # valid offer addressed to us → kept
        (_env(SUBJECT_OFFER, "opus@chef.skworld", "lumina@chef.skworld", {"sdp": "A"}, "offer"),
         SimpleNamespace(valid=True)),
        # invalid signature → dropped
        (_env(SUBJECT_ANSWER, "opus@chef.skworld", "lumina@chef.skworld", {"sdp": "B"}, "answer"),
         SimpleNamespace(valid=False)),
        # not addressed to us → dropped
        (_env(SUBJECT_ICE, "opus@chef.skworld", "someone@else.z", {"candidate": "C"}, "ice"),
         SimpleNamespace(valid=True)),
        # non-signaling subject → dropped
        (_env("CALL_INVITE", "opus@chef.skworld", "lumina@chef.skworld", {}, "offer"),
         SimpleNamespace(valid=True)),
    ]
    monkeypatch.setattr(sm, "read_inbox", lambda agent=None: inbox)
    chan = MailboxSignaling(agent="lumina")
    sigs = chan.poll_signals()
    assert len(sigs) == 1
    assert sigs[0]["from_fqid"] == "opus@chef.skworld"
    assert sigs[0]["kind"] == "offer"
    assert sigs[0]["payload"]["sdp"] == "A"


def test_poll_signals_skips_unparseable_body(monkeypatch):
    monkeypatch.setattr(sm, "_self_fqid", lambda agent=None: "lumina@chef.skworld")
    bad = SimpleNamespace(
        id="e2", subject=SUBJECT_OFFER, from_fqid="opus@chef.skworld",
        to_fqid="lumina@chef.skworld", body="{not json",
    )
    monkeypatch.setattr(sm, "read_inbox", lambda agent=None: [(bad, SimpleNamespace(valid=True))])
    chan = MailboxSignaling(agent="lumina")
    assert chan.poll_signals() == []
