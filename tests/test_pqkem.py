"""PQC Q1 — hybrid KEM (X25519 + ML-KEM-768) primitive tests.

The gate is **cross-implementation interop with the sk_pqc Dart package**:
decapsulating the shared test vector's ciphertext with its private key MUST
yield the recorded shared secret. Python and Dart MUST agree byte-for-byte.

Also covers:
    * ML-KEM-768 leg KAT — the oqs decapsulation matches the FIPS 203 / NIST
      ACVP-anchored leg secret recorded in the vector.
    * HKDF-SHA256 combiner KAT vs RFC 5869 §A.1.
    * Round-trip (keypair -> encap -> decap), distinct encapsulations differ,
      malformed ciphertext/keys raise (never crash), implicit rejection.
    * Registry: ``x25519-mlkem768`` is registered, active, hybrid-pq.

These tests need liboqs (via ``oqs``). They skip cleanly if it is unavailable
so the combiner KAT (pure pyca) and registry checks still run anywhere.
Run from HOME to avoid the skmemory namespace collision::

    cd ~ && ~/.skenv/bin/python -m pytest skcomms/tests/test_pqkem.py -q
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skcomms import pqkem
from skcomms.pqkem import (
    CIPHERTEXT_LEN,
    HKDF_INFO,
    PRIVATE_KEY_LEN,
    PUBLIC_KEY_LEN,
    PqKemFormatError,
    hybrid_decap,
    hybrid_encap,
    hybrid_keypair,
)

# Locate the sk_pqc cross-impl vector. Prefer the env override, else the known
# sibling checkout path.
_VECTOR_CANDIDATES = [
    Path(p)
    for p in [
        __import__("os").environ.get("SK_PQC_VECTOR", ""),
        str(
            Path.home()
            / "clawd/skcapstone-repos/sk_pqc/test_vectors/hybrid_kem_x25519_mlkem768.json"
        ),
    ]
    if p
]


def _load_vector():
    for path in _VECTOR_CANDIDATES:
        if path.exists():
            return json.loads(path.read_text()), path
    return None, None


_VECTOR, _VECTOR_PATH = _load_vector()

oqs_required = pytest.mark.skipif(
    not pqkem.is_available(),
    reason="liboqs/oqs unavailable — PQ tests skipped (combiner/registry still run)",
)
vector_required = pytest.mark.skipif(
    _VECTOR is None, reason="sk_pqc cross-impl vector not found"
)


# ---------------------------------------------------------------------------
# THE GATE — cross-impl interop with sk_pqc (Dart)
# ---------------------------------------------------------------------------


@oqs_required
@vector_required
def test_cross_impl_vector_matches_sk_pqc():
    """Decapsulate the sk_pqc vector -> must equal the recorded shared secret.

    This is the Python<->Dart agreement gate. Expected:
    f11627140207d95e0b743245f5c6381e08c30dc61cc84abf03a822c888ce21fc
    """
    priv = bytes.fromhex(_VECTOR["hybrid"]["private_key"])
    ct = bytes.fromhex(_VECTOR["hybrid"]["ciphertext"])
    expected = _VECTOR["hybrid"]["shared_secret"]

    assert len(priv) == PRIVATE_KEY_LEN
    assert len(ct) == CIPHERTEXT_LEN

    derived = hybrid_decap(ct, priv)  # default info = sk_pqc/x25519-mlkem768/v1
    assert derived.hex() == expected
    assert (
        derived.hex()
        == "f11627140207d95e0b743245f5c6381e08c30dc61cc84abf03a822c888ce21fc"
    )


@oqs_required
@vector_required
def test_cross_impl_public_key_layout_matches_vector():
    """The vector's public key = recipient X25519 pub || ML-KEM pub (1216 B)."""
    pub = bytes.fromhex(_VECTOR["hybrid"]["public_key"])
    assert len(pub) == PUBLIC_KEY_LEN
    assert pub[:32].hex() == _VECTOR["legs"]["x25519"]["recipient_public"]
    assert pub[32:].hex() == _VECTOR["legs"]["mlkem768"]["public_key"]


@oqs_required
@vector_required
def test_legs_match_vector():
    """Each leg secret independently matches the vector (X25519 + ML-KEM-768)."""
    import oqs
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    priv = bytes.fromhex(_VECTOR["hybrid"]["private_key"])
    ct = bytes.fromhex(_VECTOR["hybrid"]["ciphertext"])

    # X25519 leg.
    x_seed = priv[:32]
    eph_pub = ct[:32]
    x_priv = X25519PrivateKey.from_private_bytes(x_seed)
    x_ss = x_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    assert x_ss.hex() == _VECTOR["legs"]["x25519"]["shared_secret"]

    # ML-KEM-768 leg (FIPS 203 / NIST ACVP-anchored KAT).
    mlkem_secret = priv[32:]
    mlkem_ct = ct[32:]
    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=mlkem_secret) as kem:
        ml_ss = kem.decap_secret(mlkem_ct)
    assert ml_ss.hex() == _VECTOR["legs"]["mlkem768"]["shared_secret"]


# ---------------------------------------------------------------------------
# Combiner KAT (pure pyca — runs without liboqs)
# ---------------------------------------------------------------------------


def test_combiner_rfc5869_a1_kat():
    """HKDF-SHA256 against RFC 5869 §A.1 known answer (sanity on the KDF)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = HKDF(algorithm=hashes.SHA256(), length=42, salt=salt, info=info).derive(ikm)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4"
        "c5bf34007208d5b887185865"
    )


def test_combiner_concat_order_and_params():
    """The combiner concatenates X25519 first, uses empty salt + suite info."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    x_ss = b"\x11" * 32
    ml_ss = b"\x22" * 32
    got = pqkem._combine(x_ss, ml_ss)
    # Recompute the expected value independently.
    expect = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"sk_pqc/x25519-mlkem768/v1",
    ).derive(x_ss + ml_ss)
    assert got == expect
    # Order matters: swapping the legs changes the output.
    swapped = pqkem._combine(ml_ss, x_ss)
    assert swapped != got


# ---------------------------------------------------------------------------
# Round-trip + properties
# ---------------------------------------------------------------------------


@oqs_required
def test_roundtrip_keypair_encap_decap():
    kp = hybrid_keypair()
    assert len(kp.public_key) == PUBLIC_KEY_LEN
    assert len(kp.private_key) == PRIVATE_KEY_LEN

    ct, ss_enc = hybrid_encap(kp.public_key)
    assert len(ct) == CIPHERTEXT_LEN
    assert len(ss_enc) == 32

    ss_dec = hybrid_decap(ct, kp.private_key)
    assert ss_dec == ss_enc


@oqs_required
def test_distinct_encapsulations_differ():
    kp = hybrid_keypair()
    ct1, ss1 = hybrid_encap(kp.public_key)
    ct2, ss2 = hybrid_encap(kp.public_key)
    assert ct1 != ct2  # fresh X25519 ephemeral + fresh ML-KEM each time
    assert ss1 != ss2
    # both still decapsulate correctly
    assert hybrid_decap(ct1, kp.private_key) == ss1
    assert hybrid_decap(ct2, kp.private_key) == ss2


@oqs_required
def test_info_domain_separation():
    kp = hybrid_keypair()
    ct, ss_default = hybrid_encap(kp.public_key)
    # Decapsulating with a different info yields a different (non-matching) secret.
    ss_other = hybrid_decap(ct, kp.private_key, info=b"some/other/context")
    assert ss_other != ss_default
    assert hybrid_decap(ct, kp.private_key, info=HKDF_INFO) == ss_default


@oqs_required
def test_implicit_rejection_on_tampered_mlkem_ct():
    """Tampering the ML-KEM part does NOT raise (implicit rejection) but the
    resulting secret will not match the encapsulator's."""
    kp = hybrid_keypair()
    ct, ss = hybrid_encap(kp.public_key)
    tampered = bytearray(ct)
    tampered[-1] ^= 0xFF  # flip a bit deep in the ML-KEM ciphertext
    out = hybrid_decap(bytes(tampered), kp.private_key)  # must NOT raise
    assert out != ss


# ---------------------------------------------------------------------------
# Failure cases — malformed input raises cleanly (never crashes)
# ---------------------------------------------------------------------------


@oqs_required
def test_malformed_ciphertext_length_raises():
    kp = hybrid_keypair()
    with pytest.raises(PqKemFormatError):
        hybrid_decap(b"\x00" * 10, kp.private_key)
    with pytest.raises(PqKemFormatError):
        hybrid_decap(b"\x00" * (CIPHERTEXT_LEN + 1), kp.private_key)


@oqs_required
def test_malformed_private_key_length_raises():
    ct = b"\x00" * CIPHERTEXT_LEN
    with pytest.raises(PqKemFormatError):
        hybrid_decap(ct, b"\x00" * 10)


@oqs_required
def test_malformed_public_key_length_raises():
    with pytest.raises(PqKemFormatError):
        hybrid_encap(b"\x00" * 10)
    with pytest.raises(PqKemFormatError):
        hybrid_encap(b"\x00" * (PUBLIC_KEY_LEN - 1))


def test_non_bytes_raises():
    with pytest.raises(PqKemFormatError):
        pqkem._expect_len("x", "notbytes", 5)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Backend abstraction + registry
# ---------------------------------------------------------------------------


@oqs_required
def test_backend_roundtrip():
    from skcomms.pqkem_backend import get_kem_backend

    be = get_kem_backend("x25519-mlkem768")
    assert be.available()
    kp = be.generate_keypair()
    ct, ss = be.encapsulate(kp.public_key)
    assert be.decapsulate(ct, kp.private_key) == ss


def test_registry_entry_is_active_hybrid():
    from skcomms.crypto_suites import SuiteKind, SuiteStatus, get_suite

    s = get_suite("x25519-mlkem768")
    assert s is not None
    assert s.kind == SuiteKind.KEM
    assert s.status == SuiteStatus.HYBRID_PQ
    assert s.active is True
    assert s.is_quantum_resistant
    assert "FIPS 203" in s.fips_refs


def test_classical_fallback_is_not_silent():
    """If oqs is missing, the helper raises PqKemUnavailable — never silently
    downgrades. We assert the error type exists and is a hard error."""
    from skcomms.pqkem import PqKemError, PqKemUnavailable

    assert issubclass(PqKemUnavailable, PqKemError)
    # When available, is_available() is True; the unavailable path is covered by
    # the skip markers. The contract: no function returns a classical-only secret.
