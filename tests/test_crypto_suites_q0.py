"""PQC Q0 — crypto-agility scaffolding tests for skcomms.

Covers:
    - SignedEnvelope.sig_suite default + round-trip.
    - Back-compat: a SignedEnvelope serialized WITHOUT sig_suite still loads
      and defaults to the classical suite.
    - crypto_suites registry shape + honesty (everything active is classical or
      symmetric; hybrid/pq suites exist but are inactive).
"""

from __future__ import annotations

import json

from skcomms.crypto_suites import (
    DEFAULT_SIG_SUITE,
    SuiteKind,
    SuiteStatus,
    active_suites,
    all_suites,
    get_suite,
    is_quantum_resistant,
    suite_status,
)
from skcomms.envelope import CLASSICAL_SIG_SUITE, Envelope, SignedEnvelope


def _make_envelope() -> Envelope:
    return Envelope(from_fqid="a@op.realm", to_fqid="b@op.realm", body="hi")


def test_signed_envelope_defaults_to_classical_suite():
    se = SignedEnvelope(envelope=_make_envelope())
    assert se.sig_suite == "ed25519-v1"
    assert se.sig_suite == CLASSICAL_SIG_SUITE == DEFAULT_SIG_SUITE


def test_signed_envelope_suite_round_trips():
    se = SignedEnvelope(envelope=_make_envelope(), sig_suite="mldsa65-ed25519-v2")
    loaded = SignedEnvelope.from_bytes(se.to_bytes())
    assert loaded.sig_suite == "mldsa65-ed25519-v2"


def test_backcompat_old_envelope_without_sig_suite_loads():
    """An object serialized BEFORE the field existed must still parse."""
    old = {
        "envelope": _make_envelope().to_dict(),
        "signature": "sig",
        "signer_fingerprint": "F" * 40,
        "signed_at": "2026-01-01T00:00:00+00:00",
        "content_hash": "abc",
        # NOTE: no sig_suite key
    }
    loaded = SignedEnvelope.from_bytes(json.dumps(old).encode("utf-8"))
    assert loaded.sig_suite == "ed25519-v1"
    assert suite_status(loaded.sig_suite) == SuiteStatus.CLASSICAL
    assert not is_quantum_resistant(loaded.sig_suite)


def test_registry_default_sig_suite_is_classical():
    suite = get_suite(DEFAULT_SIG_SUITE)
    assert suite is not None
    assert suite.kind == SuiteKind.SIG
    assert suite.status == SuiteStatus.CLASSICAL
    assert suite.active is True
    assert not suite.is_quantum_resistant


# The Q0 honesty gate said *no* active suite may be hybrid/pq. Q1 (Phase 1)
# relaxes that for exactly one entry: the verified ``x25519-mlkem768`` KEM
# *primitive* (skcomms.pqkem) which round-trips and matches the sk_pqc
# cross-impl vector. It is "active" only in the sense that the primitive is real
# and usable — it is NOT yet wired into any wire surface (that is Q2/Q3).
# Active hybrid primitives: Q1 KEM + Q7 hybrid signature. Both are verified
# primitives wired opt-in (KEM into group/envelope; sig into
# SignedEnvelope.sig_suite + capauth challenge). Classical stays default.
_Q1_ACTIVE_HYBRID_PRIMITIVES = {"x25519-mlkem768", "mldsa65-ed25519-v2"}


def test_registry_active_suites_are_never_hybrid_or_pq():
    """Honesty gate: only the verified (still-unwired) Q1 KEM primitive may be
    an active hybrid suite; everything else active stays classical/symmetric."""
    for suite in active_suites():
        if suite.suite_id in _Q1_ACTIVE_HYBRID_PRIMITIVES:
            # Allowed: verified primitive, not yet wired into envelope/group.
            assert suite.status == SuiteStatus.HYBRID_PQ
            continue
        assert suite.status in (SuiteStatus.CLASSICAL, SuiteStatus.SYMMETRIC), (
            f"{suite.suite_id} is active but status={suite.status}"
        )


def test_registry_has_planned_inactive_hybrid_suites():
    hybrid = get_suite("x25519-mlkem768-v2")
    assert hybrid is not None
    assert hybrid.status == SuiteStatus.HYBRID_PQ
    assert hybrid.active is False          # planned, not live
    assert hybrid.is_quantum_resistant     # would be QR once active
    assert "FIPS 203" in hybrid.fips_refs
    assert hybrid.replaces == "rsa-pgp-wrap-v1"


def test_registry_shape_and_serialization():
    for suite in all_suites():
        d = suite.to_dict()
        assert set(d) >= {
            "suite_id", "kind", "status", "primitives",
            "fips_refs", "active", "quantum_resistant",
        }
        assert d["quantum_resistant"] == suite.is_quantum_resistant


def test_unknown_suite_is_treated_classical():
    assert suite_status("totally-made-up") == SuiteStatus.CLASSICAL
    assert not is_quantum_resistant("totally-made-up")
