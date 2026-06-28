"""RFC-0001 P5 foundation — no-identity anonymous transport framing.

Exercises :mod:`skcomms.anon_transport`: the additive, flag-gated layer that
composes opaque ``aqid`` addressing + the deniable HMAC auth + the padding
ladder into one wire frame. Coverage:

    - the flag gate (default OFF; env / per-call override; OFF emits nothing).
    - aqid round-trip *through framing* (address -> seal -> relay routes on the
      opaque sender_id -> open).
    - deniable-auth accept/reject (good secret opens; wrong secret / tampered
      frame / wrong queue rejected).
    - padding size-class hiding (two different payload lengths in the same
      bucket produce IDENTICAL frame lengths).
    - two-party seal/open round-trip with NO identity in the wire.
"""

from __future__ import annotations

import pytest

from skcomms.anon_queue import encode_aqid, new_queue_pair
from skcomms.anon_transport import (
    ANON_ENV,
    ANON_MAGIC,
    ANON_TRANSPORT_SUITE,
    AnonAuthError,
    AnonChannel,
    AnonDisabledError,
    AnonFrameError,
    anon_enabled,
    frame_anon,
    is_anon_frame,
    parse_anon,
    read_sender_id,
)

SECRET = b"q" * 32


# ---------------------------------------------------------------------------
# Flag gate
# ---------------------------------------------------------------------------


def test_anon_enabled_default_off(monkeypatch):
    monkeypatch.delenv(ANON_ENV, raising=False)
    assert anon_enabled() is False


def test_anon_enabled_env_on(monkeypatch):
    monkeypatch.setenv(ANON_ENV, "1")
    assert anon_enabled() is True


def test_anon_enabled_override_wins(monkeypatch):
    monkeypatch.setenv(ANON_ENV, "1")
    assert anon_enabled(override=False) is False
    monkeypatch.delenv(ANON_ENV, raising=False)
    assert anon_enabled(override=True) is True


def test_frame_anon_disabled_raises(monkeypatch):
    # OFF and no explicit enable -> nothing is emitted (additive guarantee).
    monkeypatch.delenv(ANON_ENV, raising=False)
    _, sid = new_queue_pair()
    with pytest.raises(AnonDisabledError):
        frame_anon(b"hello", sid, SECRET)


def test_frame_anon_env_enables(monkeypatch):
    monkeypatch.setenv(ANON_ENV, "1")
    _, sid = new_queue_pair()
    wire = frame_anon(b"hello", sid, SECRET)  # no explicit enabled= needed
    assert is_anon_frame(wire)


def test_suite_constant():
    assert ANON_TRANSPORT_SUITE == "anon-transport-v1"


# ---------------------------------------------------------------------------
# Frame shape / detection / relay read
# ---------------------------------------------------------------------------


def test_frame_carries_magic_and_routes_on_opaque_sid():
    _, sid = new_queue_pair()
    wire = frame_anon(b"payload", sid, SECRET, enabled=True)
    assert wire.startswith(ANON_MAGIC)
    assert is_anon_frame(wire)
    # A relay (no secret) reads ONLY the opaque routing id to deliver.
    assert read_sender_id(wire) == sid


def test_is_anon_frame_false_for_non_anon():
    assert not is_anon_frame(b"{not an anon frame}")
    assert not is_anon_frame(b"")
    assert not is_anon_frame(b"\x00\x01\x02")


def test_read_sender_id_rejects_non_frame():
    with pytest.raises(AnonFrameError):
        read_sender_id(b"{json}")


# ---------------------------------------------------------------------------
# aqid round-trip THROUGH framing
# ---------------------------------------------------------------------------


def test_aqid_address_to_frame_roundtrip():
    # Recipient mints a channel and publishes its aqid; sender resolves it.
    recipient = AnonChannel.create("relay.skworld.io:9384", SECRET)
    addr = recipient.address
    assert addr.startswith("aqid:")

    sender = AnonChannel.from_address(addr, SECRET)
    wire = sender.seal(b"sovereign hello", enabled=True)

    # Relay would route on the opaque sender_id parsed from the wire...
    assert read_sender_id(wire) == recipient.sender_id
    # ...and the recipient opens it back to the exact payload.
    assert recipient.open(wire) == b"sovereign hello"


def test_sender_never_sees_recipient_private_sub_id():
    recipient = AnonChannel.create("r.example", SECRET)
    sender = AnonChannel.from_address(recipient.address, SECRET)
    # The published address carries only the sender_id half.
    assert sender.recipient_id is None
    assert recipient.recipient_id is not None
    assert recipient.recipient_id != recipient.sender_id


# ---------------------------------------------------------------------------
# Deniable-auth accept / reject
# ---------------------------------------------------------------------------


def test_parse_accepts_good_secret():
    _, sid = new_queue_pair()
    wire = frame_anon(b"authentic", sid, SECRET, enabled=True)
    frame = parse_anon(wire, SECRET)
    assert frame.payload == b"authentic"
    assert frame.sender_id == sid


def test_parse_rejects_wrong_secret():
    _, sid = new_queue_pair()
    wire = frame_anon(b"authentic", sid, SECRET, enabled=True)
    with pytest.raises(AnonAuthError):
        parse_anon(wire, b"WRONG-secret" + b"0" * 20)


def test_parse_rejects_tampered_body():
    _, sid = new_queue_pair()
    wire = bytearray(frame_anon(b"authentic", sid, SECRET, enabled=True))
    wire[-1] ^= 0xFF  # flip a byte in the padded body
    with pytest.raises(AnonAuthError):
        parse_anon(bytes(wire), SECRET)


def test_parse_rejects_tampered_sender_id():
    _, sid = new_queue_pair()
    wire = bytearray(frame_anon(b"authentic", sid, SECRET, enabled=True))
    # Flip a byte inside the routing id region -> tag (which binds it) fails.
    wire[len(ANON_MAGIC) + 1] ^= 0xFF
    with pytest.raises(AnonAuthError):
        parse_anon(bytes(wire), SECRET)


def test_parse_rejects_wrong_queue():
    _, sid = new_queue_pair()
    _, other_sid = new_queue_pair()
    wire = frame_anon(b"x", sid, SECRET, enabled=True)
    with pytest.raises(AnonFrameError):
        parse_anon(wire, SECRET, expected_sender_id=other_sid)


def test_channel_open_enforces_its_own_queue():
    a = AnonChannel.create("r", SECRET)
    b = AnonChannel.create("r", SECRET)
    wire = AnonChannel.from_address(a.address, SECRET).seal(b"hi", enabled=True)
    assert a.open(wire) == b"hi"
    # b's channel must reject a frame for a's queue (wrong sender_id).
    with pytest.raises(AnonFrameError):
        b.open(wire)


def test_parse_rejects_non_frame_and_truncated():
    with pytest.raises(AnonFrameError):
        parse_anon(b"{not a frame}", SECRET)
    short = frame_anon(b"x", new_queue_pair()[1], SECRET, enabled=True)[:20]
    with pytest.raises(AnonFrameError):
        parse_anon(short, SECRET)


# ---------------------------------------------------------------------------
# Padding size-class hiding
# ---------------------------------------------------------------------------


def test_padding_hides_exact_length_within_bucket():
    _, sid = new_queue_pair()
    # Two very different small payloads both land in the first (4 KB) bucket.
    short = frame_anon(b"a", sid, SECRET, enabled=True)
    longer = frame_anon(b"a" * 1000, sid, SECRET, enabled=True)
    assert len(short) == len(longer)  # identical wire length hides the count


def test_padding_different_buckets_differ():
    _, sid = new_queue_pair()
    small = frame_anon(b"a" * 10, sid, SECRET, enabled=True)
    big = frame_anon(b"a" * 5000, sid, SECRET, enabled=True)
    assert len(small) != len(big)  # crossing a bucket boundary is visible (coarse)


# ---------------------------------------------------------------------------
# No identity anywhere in the wire
# ---------------------------------------------------------------------------


def test_no_identity_in_published_address():
    # The address a peer hands out is purely opaque: aqid:<relay>/<base64url(id)>.
    # The only "name" is a CSPRNG 16-byte id — no FQID/DID/fingerprint/capauth.
    recipient = AnonChannel.create("relay.skworld.io:9384", SECRET)
    addr = recipient.address
    assert addr.startswith("aqid:")
    for marker in ("did:", "fqid", "fingerprint", "capauth", "@"):
        assert marker not in addr
    # The wire's only structural identity field is that same opaque id.
    wire = recipient_seal(recipient)
    assert read_sender_id(wire) == recipient.sender_id


def recipient_seal(channel: AnonChannel) -> bytes:
    return AnonChannel.from_address(channel.address, channel.secret).seal(
        b"opaque-body", enabled=True
    )


# ---------------------------------------------------------------------------
# Explicit-nonce path still round-trips (tag binds the *padded* body, so the
# random pad makes frames non-deterministic even at a fixed nonce — by design).
# ---------------------------------------------------------------------------


def test_explicit_nonce_roundtrips():
    _, sid = new_queue_pair()
    nonce = b"\x07" * 16
    wire = frame_anon(b"m", sid, SECRET, nonce=nonce, enabled=True)
    assert wire[len(ANON_MAGIC) + 1 + 16: len(ANON_MAGIC) + 1 + 16 + 16] == nonce
    assert parse_anon(wire, SECRET).payload == b"m"


def test_bad_inputs_rejected():
    with pytest.raises(AnonFrameError):
        frame_anon(b"x", b"short-sid", SECRET, enabled=True)
    with pytest.raises(AnonFrameError):
        frame_anon(b"x", new_queue_pair()[1], b"", enabled=True)
    with pytest.raises(AnonFrameError):
        frame_anon(b"x", new_queue_pair()[1], SECRET, nonce=b"short", enabled=True)
