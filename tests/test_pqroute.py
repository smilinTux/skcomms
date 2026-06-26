"""PQC P3 — pqroute1 metadata-sealing envelope tests (skcomms.pqroute).

The ``pqroute1`` envelope splits a message into:
    * an OUTER routing header (plaintext, readable by an intermediate relay so it
      can forward to the next hop) — e.g. ``{"to_relay": "...", "v": 1}``
    * an INNER blob (the sensitive metadata + content) hybrid-sealed to the
      destination's prekey (X25519 + ML-KEM-768 -> HKDF -> AES-256-GCM)

The win over a classical mix/relay layer: the routing layer here is *hybrid-PQ*,
so the inner metadata (final destination, flags, timestamps) and content are
confidential against a harvest-now-decrypt-later adversary even if it records
every hop — secure if EITHER the X25519 or the ML-KEM-768 leg holds (FIPS 203).

These tests REQUIRE the liboqs-backed hybrid KEM (skcomms.pqkem); they skip if
it is unavailable (an environment gap, not a logic failure).
"""

from __future__ import annotations

import pytest

pqkem = pytest.importorskip("skcomms.pqkem")
pqroute = pytest.importorskip("skcomms.pqroute")

if not pqkem.is_available():
    pytest.skip("liboqs/oqs backend unavailable", allow_module_level=True)

from skcomms.pqroute import (  # noqa: E402
    ROUTE_SUITE,
    PqRouteFormatError,
    PqRouteOpenError,
    open_routed,
    read_route_header,
    seal_routed,
)


def _keypair() -> tuple[bytes, bytes]:
    kp = pqkem.hybrid_keypair()
    return kp.public_key, kp.private_key


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_roundtrip():
    pub, priv = _keypair()
    inner = {"final_dest": "capauth:bob@skworld.io", "flags": ["urgent"], "ts": 123}
    content = b"the actual sensitive body"
    route_hdr = {"to_relay": "relay-1.skworld.io", "v": 1}

    blob = seal_routed(inner, content, pub, route_hdr=route_hdr)
    out_hdr, out_inner, out_content = open_routed(blob, priv)

    assert out_hdr == route_hdr
    assert out_inner == inner
    assert out_content == content


def test_empty_content_and_metadata():
    pub, priv = _keypair()
    blob = seal_routed({}, b"", pub, route_hdr={"to_relay": "r", "v": 1})
    hdr, inner, content = open_routed(blob, priv)
    assert hdr == {"to_relay": "r", "v": 1}
    assert inner == {}
    assert content == b""


def test_nondeterministic_but_both_open():
    pub, priv = _keypair()
    rh = {"to_relay": "r", "v": 1}
    b1 = seal_routed({"a": 1}, b"x", pub, route_hdr=rh)
    b2 = seal_routed({"a": 1}, b"x", pub, route_hdr=rh)
    assert b1 != b2  # fresh ephemeral + nonce each time
    assert open_routed(b1, priv)[2] == b"x"
    assert open_routed(b2, priv)[2] == b"x"


# ---------------------------------------------------------------------------
# Relay can read the route header but NOT the inner metadata/content
# ---------------------------------------------------------------------------


def test_relay_reads_route_header_only():
    pub, priv = _keypair()
    inner = {"final_dest": "SECRET-bob", "flags": ["pq"]}
    content = b"SECRET-BODY-BYTES"
    route_hdr = {"to_relay": "relay-1.skworld.io", "v": 1}

    blob = seal_routed(inner, content, pub, route_hdr=route_hdr)

    # An intermediate relay (has the blob, NOT the dest private key) can read the
    # outer routing header to forward the message...
    relay_view = read_route_header(blob)
    assert relay_view == route_hdr

    # ...but the sensitive inner metadata + content must NOT appear anywhere in
    # the blob in plaintext, and the relay has no method to recover them.
    assert b"SECRET-bob" not in blob
    assert b"SECRET-BODY-BYTES" not in blob
    assert b"final_dest" not in blob

    # Without the dest private key there is no open path for the relay.
    with pytest.raises(PqRouteOpenError):
        open_routed(blob, bytes(len(priv)))  # all-zero / wrong key


def test_wrong_key_fails():
    pub, _ = _keypair()
    _, other_priv = _keypair()
    blob = seal_routed({"x": 1}, b"body", pub, route_hdr={"to_relay": "r", "v": 1})
    with pytest.raises(PqRouteOpenError):
        open_routed(blob, other_priv)


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tamper_inner_byte_fails():
    pub, priv = _keypair()
    blob = bytearray(seal_routed({"x": 1}, b"body", pub, route_hdr={"to_relay": "r", "v": 1}))
    blob[-1] ^= 0x01  # flip a tag bit in the sealed inner
    with pytest.raises(PqRouteOpenError):
        open_routed(bytes(blob), priv)


def test_tamper_route_header_detected_on_open():
    """The route header is plaintext but AEAD-bound; a relay that rewrites it
    cannot do so silently — the destination's open fails."""
    pub, priv = _keypair()
    blob = seal_routed({"x": 1}, b"body", pub, route_hdr={"to_relay": "r1", "v": 1})

    # Re-serialize a NEW outer header (e.g. a malicious relay rewrites next-hop),
    # keeping the same sealed inner. The dest reconstructs AAD from the header it
    # actually receives -> AEAD won't authenticate.
    tampered = pqroute.replace_route_header(blob, {"to_relay": "EVIL", "v": 1})
    assert read_route_header(tampered) == {"to_relay": "EVIL", "v": 1}
    with pytest.raises(PqRouteOpenError):
        open_routed(tampered, priv)


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


def test_seal_bad_pubkey_length():
    with pytest.raises(PqRouteFormatError):
        seal_routed({"x": 1}, b"b", b"too-short", route_hdr={"v": 1})


def test_open_too_short():
    _, priv = _keypair()
    with pytest.raises(PqRouteFormatError):
        open_routed(b"nope", priv)


def test_read_route_header_too_short():
    with pytest.raises(PqRouteFormatError):
        read_route_header(b"\x00\x00")


def test_suite_id_is_pqroute1():
    assert ROUTE_SUITE == "pqroute1"
