"""Regression: receiver honors the wire TTL via env.created_at.

Finding 2 (INERT RECEIVER TTL): ``envelope_v1_to_message`` built
``MessageMetadata`` without propagating ``env.created_at``, so ``created_at``
defaulted to ``now()`` on the receiver. ``MessageEnvelope.is_expired`` measures
``now - created_at`` against ``routing.ttl`` — with created_at pinned to now, a
short-TTL ephemeral beacon (or any already-stale wire message) never registered
as expired on the receiver, defeating the whole point of the short TTL.

Fix: propagate ``env.created_at`` into ``MessageMetadata.created_at`` so the
receiver's expiry math uses the real send time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from skcomms.core import (
    WIRE_HEADER_ACK_REQUESTED,
    WIRE_HEADER_TTL,
    envelope_v1_to_message,
)
from skcomms.envelope import Envelope


def test_past_created_at_plus_short_ttl_is_expired_on_receiver():
    past = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    env = Envelope(
        from_fqid="jarvis@chef.skworld", to_fqid="lumina@chef.skworld",
        content_type="application/cot+xml", body="<event/>",
        headers={WIRE_HEADER_TTL: "120", WIRE_HEADER_ACK_REQUESTED: "0"},
        created_at=past,
    )
    msg = envelope_v1_to_message(env)
    # created_at is taken from the wire, not now().
    assert msg.metadata.created_at.astimezone(timezone.utc) == datetime.fromisoformat(past).astimezone(timezone.utc)
    # 600s old, 120s TTL → expired.
    assert msg.is_expired is True


def test_fresh_created_at_short_ttl_not_expired():
    now = datetime.now(timezone.utc).isoformat()
    env = Envelope(
        from_fqid="jarvis@chef.skworld", to_fqid="lumina@chef.skworld",
        content_type="application/cot+xml", body="<event/>",
        headers={WIRE_HEADER_TTL: "120"},
        created_at=now,
    )
    msg = envelope_v1_to_message(env)
    assert msg.is_expired is False
