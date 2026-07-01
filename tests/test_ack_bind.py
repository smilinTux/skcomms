"""Security tests for ACK binding + replay protection.

The bug (MED — ACK forgery / replay): ``AckTracker.process_ack`` accepted any
ACK envelope referencing a known pending envelope id, with:
  * NO binding proving the ACK came from the party the original message was
    delivered to (anyone could forge a confirmation);
  * NO replay/dedupe (a captured ACK could be replayed to re-confirm).

These tests prove both holes, then guard the fix.
"""

from __future__ import annotations

import pytest

from skcomms.ack import AckStatus, AckTracker
from skcomms.models import MessageEnvelope, MessagePayload, RoutingConfig


def _make_tracked_message(sender: str, recipient: str) -> MessageEnvelope:
    """Build an ack-requested outbound envelope from ``sender`` to ``recipient``."""
    return MessageEnvelope(
        sender=sender,
        recipient=recipient,
        payload=MessagePayload(content="hello"),
        routing=RoutingConfig(ack_requested=True),
    )


@pytest.fixture()
def tracker(tmp_path):
    return AckTracker(acks_dir=tmp_path / "acks")


def test_ack_from_intended_recipient_is_accepted(tracker):
    """Baseline: a legitimate ACK from the real recipient confirms delivery."""
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob")  # bob is who the message went to
    resolved = tracker.process_ack(ack)

    assert resolved is not None
    assert resolved.status == AckStatus.CONFIRMED


def test_forged_ack_from_wrong_sender_is_rejected(tracker):
    """An ACK whose sender is NOT the intended recipient must be rejected."""
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    # Mallory forges an ACK for alice->bob, claiming to be the acker.
    forged = msg.make_ack(sender="mallory")
    resolved = tracker.process_ack(forged)

    assert resolved is None, "forged ACK from wrong sender must NOT confirm"
    entry = tracker.get(msg.envelope_id)
    assert entry is not None
    assert entry.status == AckStatus.PENDING, "forged ACK must not confirm delivery"


def test_replayed_ack_does_not_reconfirm(tracker):
    """A replayed ACK for an already-confirmed envelope must be rejected."""
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob")
    first = tracker.process_ack(ack)
    assert first is not None and first.status == AckStatus.CONFIRMED
    first_confirmed_at = first.confirmed_at

    # Attacker replays the exact same captured ACK.
    replay = tracker.process_ack(ack)
    assert replay is None, "replayed ACK must not re-confirm"

    entry = tracker.get(msg.envelope_id)
    assert entry.status == AckStatus.CONFIRMED
    assert entry.confirmed_at == first_confirmed_at, "replay must not mutate the entry"


def test_ack_for_unknown_envelope_is_rejected(tracker):
    """An ACK referencing an envelope we never tracked is ignored."""
    stray = MessageEnvelope(
        sender="bob",
        recipient="alice",
        payload=MessagePayload(content="does-not-exist"),
    )
    ack = stray.make_ack(sender="alice")
    assert tracker.process_ack(ack) is None
