"""Tests for ACK forgery/replay hardening (coord 83113daa).

The AckTracker binds each inbound ACK to the identity of the party the
original message was delivered to, and rejects duplicate/stale (replayed)
ACKs. These tests cover:

    * valid ACK from the real recipient  -> confirms exactly once
    * forged ACK from a third party      -> rejected, entry stays PENDING
    * replayed ACK (already confirmed)   -> rejected, no re-confirmation
    * stale ACK after timeout            -> rejected, stays TIMED_OUT
    * optional crypto sender_verifier    -> unauthenticated ACK rejected
"""

from __future__ import annotations

import pytest

from skcomms.ack import AckStatus, AckTracker
from skcomms.models import MessageEnvelope, MessagePayload, RoutingConfig


def _outbound(sender: str, recipient: str) -> MessageEnvelope:
    """An ack-requested outbound message from *sender* to *recipient*."""
    return MessageEnvelope(
        sender=sender,
        recipient=recipient,
        payload=MessagePayload(content="hello"),
        routing=RoutingConfig(ack_requested=True),
    )


@pytest.fixture
def tracker(tmp_path):
    return AckTracker(acks_dir=tmp_path / "acks", default_timeout=300)


class TestValidAck:
    def test_valid_ack_from_recipient_confirms(self, tracker):
        msg = _outbound("lumina@chef.skworld", "jarvis@chef.skworld")
        tracker.track(msg)

        ack = msg.make_ack(sender="jarvis@chef.skworld")
        resolved = tracker.process_ack(ack)

        assert resolved is not None
        assert resolved.status == AckStatus.CONFIRMED
        assert tracker.get(msg.envelope_id).status == AckStatus.CONFIRMED

    def test_fingerprint_spacing_still_matches(self, tracker):
        # Original addressed to a spaced PGP fingerprint; ACK comes back with
        # the unspaced form — identity binding must still hold.
        spaced = "1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678"
        unspaced = spaced.replace(" ", "")
        msg = _outbound("lumina", spaced)
        tracker.track(msg)

        ack = msg.make_ack(sender=unspaced)
        assert tracker.process_ack(ack) is not None
        assert tracker.get(msg.envelope_id).status == AckStatus.CONFIRMED


class TestForgedAck:
    def test_forged_ack_from_third_party_rejected(self, tracker):
        msg = _outbound("lumina@chef.skworld", "jarvis@chef.skworld")
        tracker.track(msg)

        # Attacker learns the envelope_id and forges an ACK.
        forged = msg.make_ack(sender="mallory@evil.example")
        assert forged.payload.content == msg.envelope_id  # same id, wrong sender

        assert tracker.process_ack(forged) is None
        # Pending entry untouched.
        assert tracker.get(msg.envelope_id).status == AckStatus.PENDING


class TestReplay:
    def test_replayed_ack_does_not_reconfirm(self, tracker):
        msg = _outbound("lumina", "jarvis")
        tracker.track(msg)
        ack = msg.make_ack(sender="jarvis")

        first = tracker.process_ack(ack)
        assert first is not None
        confirmed_at = tracker.get(msg.envelope_id).confirmed_at

        # Replay the exact same captured ACK.
        assert tracker.process_ack(ack) is None
        # confirmed_at must not move.
        assert tracker.get(msg.envelope_id).confirmed_at == confirmed_at

    def test_stale_ack_after_timeout_rejected(self, tracker):
        msg = _outbound("lumina", "jarvis")
        pending = tracker.track(msg)
        # Force the entry to TIMED_OUT (as check_timeouts would).
        pending.status = AckStatus.TIMED_OUT
        (tracker.acks_dir / f"{msg.envelope_id}.ack.json").write_text(
            pending.model_dump_json(indent=2)
        )

        ack = msg.make_ack(sender="jarvis")
        assert tracker.process_ack(ack) is None
        assert tracker.get(msg.envelope_id).status == AckStatus.TIMED_OUT


class TestCryptoVerifier:
    def test_unauthenticated_ack_rejected(self, tmp_path):
        tracker = AckTracker(
            acks_dir=tmp_path / "acks",
            sender_verifier=lambda env: False,  # signature never authenticates
        )
        msg = _outbound("lumina", "jarvis")
        tracker.track(msg)

        ack = msg.make_ack(sender="jarvis")  # identity matches, but no valid sig
        assert tracker.process_ack(ack) is None
        assert tracker.get(msg.envelope_id).status == AckStatus.PENDING

    def test_authenticated_ack_accepted(self, tmp_path):
        seen = {}

        def verifier(env):
            seen["sender"] = env.sender
            return True

        tracker = AckTracker(acks_dir=tmp_path / "acks", sender_verifier=verifier)
        msg = _outbound("lumina", "jarvis")
        tracker.track(msg)

        ack = msg.make_ack(sender="jarvis")
        assert tracker.process_ack(ack) is not None
        assert seen["sender"] == "jarvis"
        assert tracker.get(msg.envelope_id).status == AckStatus.CONFIRMED
