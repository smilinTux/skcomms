"""Tests for the ``pqdm2`` multi-recipient (fanout) seal/open construction.

See ``docs/superpowers/plans/2026-08-02-multi-device-dm-fanout.md`` Task 1 and the
design spec ``docs/superpowers/specs/2026-08-02-multi-device-dm-fanout-design.md``
section 4 (wire format). These exercise the byte layout that the Dart side
(``sk-pqc-dart`` / ``skchat-app``) must match byte-for-byte.
"""

import base64
import json

import pytest

from skcomms import pqdm
from skcomms import pqkem

pytestmark = pytest.mark.skipif(
    not pqkem.is_available(),
    reason="liboqs / oqs backend unavailable",
)


def _mk_device():
    # generate a hybrid keypair via the same primitive pqdm.seal uses
    return pqdm.generate_hybrid_keypair()  # -> (public_hex, private_hex)


def _decode_token(tok: str):
    """Split a ``pqdm2:`` token into (header_dict, slots_bytes, body_bytes)."""
    assert tok.startswith(pqdm.PQDM2_PREFIX)
    rest = tok[len(pqdm.PQDM2_PREFIX):]
    h_b64, slots_b64, body_b64 = rest.split(".")
    header = json.loads(base64.b64decode(h_b64))
    slots = base64.b64decode(slots_b64)
    body = base64.b64decode(body_b64)
    return header, slots, body


def _iter_slots(slots: bytes):
    """Yield (key_id, full_slot_bytes) for each slot in the packed blob."""
    off = 0
    encap_len = pqdm.HYBRID_CIPHERTEXT_LEN
    wrapped_len = 32 + 16  # K + GCM tag
    while off < len(slots):
        kid_len = slots[off]
        start = off
        off += 1
        kid = slots[off:off + kid_len].decode()
        off += kid_len
        off += encap_len + wrapped_len
        yield kid, slots[start:off]


def _remove_slot_and_kid(tok: str, drop_kid: str) -> str:
    """Strip one recipient: drop its slot AND its kid from the header."""
    header, slots, body = _decode_token(tok)
    header["kids"] = [k for k in header["kids"] if k != drop_kid]
    kept = b"".join(
        raw for kid, raw in _iter_slots(slots) if kid != drop_kid
    )
    h_b64 = base64.b64encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return (
        pqdm.PQDM2_PREFIX
        + h_b64
        + "."
        + base64.b64encode(kept).decode()
        + "."
        + base64.b64encode(body).decode()
    )


def test_two_devices_each_open_their_slot():
    a_pub, a_priv = _mk_device()
    b_pub, b_priv = _mk_device()
    recips = [
        {"key_id": a_pub[:16], "hybrid_public_hex": a_pub},
        {"key_id": b_pub[:16], "hybrid_public_hex": b_pub},
    ]
    tok = pqdm.seal_multi(b"hello", recips, sender="lumina", recipient_id="chef")
    assert tok.startswith("pqdm2:")
    assert pqdm.open_multi(tok, my_key_id=a_pub[:16], my_private_hex=a_priv,
                           sender="lumina", recipient_id="chef") == b"hello"
    assert pqdm.open_multi(tok, my_key_id=b_pub[:16], my_private_hex=b_priv,
                           sender="lumina", recipient_id="chef") == b"hello"


def test_non_recipient_gets_none():
    a_pub, a_priv = _mk_device()
    _, c_priv = _mk_device()
    recips = [{"key_id": a_pub[:16], "hybrid_public_hex": a_pub}]
    tok = pqdm.seal_multi(b"secret", recips, sender="lumina", recipient_id="chef")
    # a device whose key_id is not in the header has no slot
    assert pqdm.open_multi(tok, my_key_id="deadbeefdeadbeef", my_private_hex=c_priv,
                           sender="lumina", recipient_id="chef") is None


def test_slot_strip_is_rejected():
    a_pub, a_priv = _mk_device()
    b_pub, _ = _mk_device()
    recips = [{"key_id": a_pub[:16], "hybrid_public_hex": a_pub},
              {"key_id": b_pub[:16], "hybrid_public_hex": b_pub}]
    tok = pqdm.seal_multi(b"hi", recips, sender="lumina", recipient_id="chef")
    tampered = _remove_slot_and_kid(tok, b_pub[:16])  # helper in the test
    # AAD includes sha256(kids); removing a kid breaks the body open
    assert pqdm.open_multi(tampered, my_key_id=a_pub[:16], my_private_hex=a_priv,
                           sender="lumina", recipient_id="chef") is None
