"""RFC-0001 P5 foundation — SimpleX-inspired anonymous queue addressing.

CLEAN-ROOM: these tests exercise the *idea* (uncorrelated recipient/sender
ids + deniable shared-secret auth), never any AGPL SimpleX code. They cover:
    - new_queue_pair(): two distinct 16-byte ids, random per call.
    - aqid:<relay>/<base64url(sid)> codec round-trip + malformed rejection.
    - HMAC-SHA256 deniable authenticator: verifies, rejects tamper/wrong secret.
"""

from __future__ import annotations

import pytest

from skcomms.anon_queue import (
    ANON_SUITE,
    AnonQueueFormatError,
    auth_tag,
    decode_aqid,
    encode_aqid,
    new_queue_pair,
    verify_tag,
)

# --- queue-pair ids ---------------------------------------------------------


def test_queue_pair_ids_are_16_bytes():
    recipient_id, sender_id = new_queue_pair()
    assert isinstance(recipient_id, bytes)
    assert isinstance(sender_id, bytes)
    assert len(recipient_id) == 16
    assert len(sender_id) == 16


def test_queue_pair_ids_distinct():
    recipient_id, sender_id = new_queue_pair()
    # The whole point: recipient (SUB) id and sender (SEND) id are
    # uncorrelated so a relay can't link a send to a subscription.
    assert recipient_id != sender_id


def test_queue_pair_random_per_call():
    pairs = [new_queue_pair() for _ in range(64)]
    rids = {r for r, _ in pairs}
    sids = {s for _, s in pairs}
    assert len(rids) == 64
    assert len(sids) == 64
    # No recipient id collides with any sender id either.
    assert rids.isdisjoint(sids)


# --- aqid codec -------------------------------------------------------------


def test_aqid_round_trip_exact():
    _, sender_id = new_queue_pair()
    relay = "relay.skworld.io:9384"
    addr = encode_aqid(relay, sender_id)
    assert addr.startswith("aqid:")
    got_relay, got_sid = decode_aqid(addr)
    assert got_relay == relay
    assert got_sid == sender_id


def test_aqid_no_base64_padding_chars():
    # base64url should be unpadded so the address is clean in URLs/QR.
    _, sender_id = new_queue_pair()
    addr = encode_aqid("r.example", sender_id)
    assert "=" not in addr
    assert "+" not in addr and "/" not in addr.split("/", 1)[1]


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "relay/abcd",                       # missing scheme
        "aqid:relay",                       # missing /sid
        "aqid:/abcd",                       # empty relay
        "aqid:relay/",                      # empty sid
        "aqid:relay/!!!notbase64!!!",       # bad base64
        "aqid:relay/YWJj",                  # decodes to 3 bytes, not 16
        "https://relay/abcd",               # wrong scheme
    ],
)
def test_aqid_rejects_malformed(bad):
    with pytest.raises(AnonQueueFormatError):
        decode_aqid(bad)


def test_encode_aqid_rejects_bad_sid_length():
    with pytest.raises(AnonQueueFormatError):
        encode_aqid("relay", b"short")


def test_encode_aqid_rejects_empty_relay():
    _, sender_id = new_queue_pair()
    with pytest.raises(AnonQueueFormatError):
        encode_aqid("", sender_id)


# --- deniable authenticator -------------------------------------------------


def test_auth_tag_verifies():
    secret = b"\x01" * 32
    nonce = b"\x02" * 16
    msg = b"hello sovereign net"
    tag = auth_tag(secret, msg, nonce)
    assert isinstance(tag, bytes)
    assert len(tag) == 32  # HMAC-SHA256
    assert verify_tag(secret, msg, nonce, tag)


def test_auth_tag_rejects_tampered_message():
    secret = b"k" * 32
    nonce = b"n" * 16
    tag = auth_tag(secret, b"original", nonce)
    assert not verify_tag(secret, b"tampered", nonce, tag)


def test_auth_tag_rejects_wrong_secret():
    nonce = b"n" * 16
    msg = b"payload"
    tag = auth_tag(b"secret-A--------", msg, nonce)
    assert not verify_tag(b"secret-B--------", msg, nonce, tag)


def test_auth_tag_rejects_wrong_nonce():
    secret = b"s" * 32
    msg = b"payload"
    tag = auth_tag(secret, msg, b"nonce-one-------")
    assert not verify_tag(secret, msg, b"nonce-two-------", tag)


def test_auth_tag_nonce_binds_into_mac():
    # Deniable: tag = HMAC(secret, nonce || message). Same secret+message but
    # different nonce -> different tag (nonce is bound, not optional).
    secret = b"s" * 32
    msg = b"m"
    assert auth_tag(secret, msg, b"a" * 16) != auth_tag(secret, msg, b"b" * 16)


def test_anon_suite_constant():
    assert ANON_SUITE == "aqid-v1"
