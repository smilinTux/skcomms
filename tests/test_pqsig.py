"""Tests for the hybrid Ed25519 + ML-DSA-65 signature primitive (PQC Q7).

Covers:
  * FIPS 204 ML-DSA-65 parameter KAT (the liboqs leg matches the standard's
    fixed sizes + claimed NIST level; a mismatch means the wrong algorithm).
  * Composite sign -> verify round-trip (the SKHS wire format).
  * The hybrid AND gate: a tampered message, a tampered Ed25519 leg, AND a
    tampered ML-DSA leg each fail (BOTH legs required).
  * Wire-format framing (magic / version / suite-tag / length prefixes /
    trailing-garbage rejection).
  * Cross-key isolation (wrong pubkey fails).

ML-DSA-65 signing is hedged-randomized, so a byte-exact sigGen KAT against a
fixed NIST ACVP vector is not reproducible offline; the authentic, offline KAT we
assert is therefore the FIPS 204 *parameter* KAT plus EUF-CMA functional
behaviour. liboqs 0.14+ carries the NIST-validated ML-DSA implementation.
"""

from __future__ import annotations

import pytest

from skcomms import pqsig

pytestmark = pytest.mark.skipif(
    not pqsig.is_available(), reason="liboqs (oqs) not available"
)


# ---------------------------------------------------------------------------
# FIPS 204 ML-DSA-65 parameter KAT
# ---------------------------------------------------------------------------


def test_fips204_mldsa65_parameter_kat():
    """The liboqs ML-DSA-65 leg matches FIPS 204 ML-DSA-65 fixed parameters."""
    import oqs

    with oqs.Signature("ML-DSA-65") as s:
        d = s.details
        # FIPS 204, ML-DSA-65 (Category 3) — fixed sizes.
        assert d["length_public_key"] == 1952
        assert d["length_secret_key"] == 4032
        assert d["length_signature"] == 3309
        assert d["claimed_nist_level"] == 3
        assert d["is_euf_cma"] is True
    # Module constants must mirror the standard (caught at import, asserted here).
    assert pqsig.MLDSA_PUB_LEN == 1952
    assert pqsig.MLDSA_SECRET_LEN == 4032
    assert pqsig.MLDSA_SIG_LEN == 3309


def test_keypair_sizes():
    kp = pqsig.generate_keypair()
    assert len(kp.ed25519_priv) == 32
    assert len(kp.ed25519_pub) == 32
    assert len(kp.mldsa_priv) == 4032
    assert len(kp.mldsa_pub) == 1952


# ---------------------------------------------------------------------------
# Composite sign -> verify round-trip
# ---------------------------------------------------------------------------


def test_composite_roundtrip():
    kp = pqsig.generate_keypair()
    msg = b"the canonical bytes of an envelope"
    sig = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    assert len(sig) == pqsig.COMPOSITE_SIG_LEN == 3383
    assert pqsig.hybrid_verify(msg, sig, kp.ed25519_pub, kp.mldsa_pub) is True


def test_two_signatures_differ_but_both_verify():
    """ML-DSA signing is hedged-randomized: two sigs over the same message
    differ, yet both verify (EUF-CMA)."""
    kp = pqsig.generate_keypair()
    msg = b"same message twice"
    s1 = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    s2 = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    # The ML-DSA leg differs; Ed25519 is deterministic so the composites differ.
    assert s1 != s2
    assert pqsig.hybrid_verify(msg, s1, kp.ed25519_pub, kp.mldsa_pub)
    assert pqsig.hybrid_verify(msg, s2, kp.ed25519_pub, kp.mldsa_pub)


# ---------------------------------------------------------------------------
# Hybrid AND gate — BOTH legs required
# ---------------------------------------------------------------------------


def test_tampered_message_fails():
    kp = pqsig.generate_keypair()
    msg = b"original"
    sig = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    assert pqsig.hybrid_verify(b"original!", sig, kp.ed25519_pub, kp.mldsa_pub) is False


def test_tampered_ed25519_leg_fails():
    """Flipping a bit in the Ed25519 leg fails — both legs required."""
    kp = pqsig.generate_keypair()
    msg = b"both legs matter"
    sig = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    ed_sig, mldsa_sig = pqsig.decode_composite(sig)
    bad_ed = bytearray(ed_sig)
    bad_ed[0] ^= 0x01
    bad = pqsig._encode_composite(bytes(bad_ed), mldsa_sig)
    assert pqsig.hybrid_verify(msg, bad, kp.ed25519_pub, kp.mldsa_pub) is False


def test_tampered_mldsa_leg_fails():
    """Flipping a bit in the ML-DSA leg fails — both legs required."""
    kp = pqsig.generate_keypair()
    msg = b"both legs matter"
    sig = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    ed_sig, mldsa_sig = pqsig.decode_composite(sig)
    bad_md = bytearray(mldsa_sig)
    bad_md[0] ^= 0x01
    bad = pqsig._encode_composite(ed_sig, bytes(bad_md))
    assert pqsig.hybrid_verify(msg, bad, kp.ed25519_pub, kp.mldsa_pub) is False


def test_wrong_ed25519_pubkey_fails():
    kp = pqsig.generate_keypair()
    other = pqsig.generate_keypair()
    msg = b"isolation"
    sig = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    assert pqsig.hybrid_verify(msg, sig, other.ed25519_pub, kp.mldsa_pub) is False


def test_wrong_mldsa_pubkey_fails():
    kp = pqsig.generate_keypair()
    other = pqsig.generate_keypair()
    msg = b"isolation"
    sig = pqsig.hybrid_sign(msg, kp.ed25519_priv, kp.mldsa_priv)
    assert pqsig.hybrid_verify(msg, sig, kp.ed25519_pub, other.mldsa_pub) is False


# ---------------------------------------------------------------------------
# Wire-format framing
# ---------------------------------------------------------------------------


def test_framing_header():
    kp = pqsig.generate_keypair()
    sig = pqsig.hybrid_sign(b"x", kp.ed25519_priv, kp.mldsa_priv)
    assert sig[:4] == pqsig.MAGIC == b"SKHS"
    assert sig[4] == pqsig.VERSION == 0x01
    assert sig[5] == pqsig.SUITE_TAG == 0x01
    # uint16 ed length prefix == 64
    assert int.from_bytes(sig[6:8], "big") == 64


def test_decode_rejects_bad_magic():
    with pytest.raises(pqsig.PqSigFormatError):
        pqsig.decode_composite(b"XXXX" + b"\x01\x01" + b"\x00\x40" + b"\x00" * 64)


def test_decode_rejects_trailing_garbage():
    kp = pqsig.generate_keypair()
    sig = pqsig.hybrid_sign(b"y", kp.ed25519_priv, kp.mldsa_priv)
    with pytest.raises(pqsig.PqSigFormatError):
        pqsig.decode_composite(sig + b"junk")


def test_decode_rejects_bad_version():
    kp = pqsig.generate_keypair()
    sig = bytearray(pqsig.hybrid_sign(b"z", kp.ed25519_priv, kp.mldsa_priv))
    sig[4] = 0x02  # bad version
    with pytest.raises(pqsig.PqSigFormatError):
        pqsig.decode_composite(bytes(sig))


def test_wrong_size_keys_raise():
    kp = pqsig.generate_keypair()
    with pytest.raises(pqsig.PqSigFormatError):
        pqsig.hybrid_sign(b"m", b"tooshort", kp.mldsa_priv)
    with pytest.raises(pqsig.PqSigFormatError):
        pqsig.hybrid_sign(b"m", kp.ed25519_priv, b"tooshort")


# ---------------------------------------------------------------------------
# Per-signer key persistence (separate from PGP identity)
# ---------------------------------------------------------------------------


def test_load_or_create_persists_and_is_stable(tmp_path):
    kp1 = pqsig.load_or_create_signer_keypair("agent-x", key_dir=tmp_path)
    kp2 = pqsig.load_or_create_signer_keypair("agent-x", key_dir=tmp_path)
    # Same key loaded back (not regenerated).
    assert kp1.mldsa_pub == kp2.mldsa_pub
    assert kp1.ed25519_pub == kp2.ed25519_pub
    # Private ML-DSA key file is 0600.
    key_file = tmp_path / "agent-x_mldsa65.key"
    assert key_file.exists()
    assert (key_file.stat().st_mode & 0o777) == 0o600
    # A round-trip with the persisted key still verifies.
    msg = b"persisted-key sign"
    sig = pqsig.hybrid_sign(msg, kp2.ed25519_priv, kp2.mldsa_priv)
    assert pqsig.hybrid_verify(msg, sig, kp2.ed25519_pub, kp2.mldsa_pub)
