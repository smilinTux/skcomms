"""CapAuth validator must FAIL CLOSED when verification cannot complete.

Security regression tests for the "fails open to the claimed identity"
finding: in permissive mode (``require_auth=False``, the SignalingBroker
default) the validator used to return the *self-asserted* fingerprint from a
signed-looking token whenever verification could not complete — no local
public key, pgpy missing, a raw verification exception, or a token missing its
signature part. A peer could therefore present ``<VICTIM_FP>.<ts>.<garbage>``
and be authenticated **as the victim**.

Verification-cannot-complete must deny (return ``None``), regardless of
``require_auth``. The only permissive conveniences that remain are the
documented dev handshakes: a missing token (-> ``"anonymous"``) and a
single-part plain-fingerprint dev token (explicit, no signature was ever
claimed).
"""

from __future__ import annotations

import time

import pytest

from skcomms.capauth_validator import CapAuthValidator

VICTIM_FP = "A" * 40


def _fresh_ts() -> str:
    return str(int(time.time()))


def test_permissive_missing_pubkey_fails_closed():
    """Signed-looking token whose key we cannot resolve must be rejected."""
    v = CapAuthValidator(require_auth=False)
    # 3-part token, valid format, but no public key exists for VICTIM_FP.
    token = f"{VICTIM_FP}.{_fresh_ts()}.{'x' * 40}"
    assert v.validate(token) is None


def test_permissive_two_part_token_fails_closed():
    """A token missing its signature part must not upgrade to the claimed id."""
    v = CapAuthValidator(require_auth=False)
    token = f"{VICTIM_FP}.{_fresh_ts()}"  # no signature
    assert v.validate(token) is None


def test_permissive_pgpy_missing_fails_closed(monkeypatch):
    """If pgpy is unavailable, we cannot verify — deny even in permissive mode."""
    import builtins

    real_import = builtins.__import__

    def _no_pgpy(name, *args, **kwargs):
        if name == "pgpy":
            raise ImportError("pgpy not installed (simulated)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_pgpy)

    v = CapAuthValidator(require_auth=False)
    token = f"{VICTIM_FP}.{_fresh_ts()}.{'x' * 40}"
    assert v.validate(token) is None


def test_permissive_verification_exception_fails_closed(monkeypatch):
    """A raw error mid-verification must deny, not fall through to the claim."""
    v = CapAuthValidator(require_auth=False)

    def _boom(_fp):
        raise RuntimeError("keyring exploded")

    monkeypatch.setattr(v, "_load_public_key", _boom)
    token = f"{VICTIM_FP}.{_fresh_ts()}.{'x' * 40}"
    assert v.validate(token) is None


def test_strict_mode_still_denies():
    """Strict mode was already fail-closed; keep it so."""
    v = CapAuthValidator(require_auth=True)
    token = f"{VICTIM_FP}.{_fresh_ts()}.{'x' * 40}"
    assert v.validate(token) is None


# --- Legitimate permissive conveniences that must be PRESERVED ---------------


def test_permissive_missing_token_is_anonymous():
    """No token at all -> documented dev 'anonymous', not a rejection."""
    v = CapAuthValidator(require_auth=False)
    assert v.validate(None) == "anonymous"
    assert v.validate("") == "anonymous"


def test_permissive_dev_plain_fingerprint_still_accepted():
    """Single-part plain-fingerprint dev token stays a documented bypass."""
    v = CapAuthValidator(require_auth=False)
    assert v.validate(VICTIM_FP) == VICTIM_FP
