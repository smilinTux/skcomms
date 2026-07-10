"""CapAuth validator must FAIL CLOSED when verification cannot complete.

Security regression tests for the "fails open to the claimed identity"
finding (coord 8e57a48a): in permissive mode (``require_auth=False``) the
validator used to return the *self-asserted* fingerprint from a signed-looking
token whenever verification could not complete: no local public key, pgpy
missing, a raw verification exception, or a token missing its signature part.
A peer could therefore present ``<VICTIM_FP>.<ts>.<garbage>`` and be
authenticated **as the victim**.

Verification-cannot-complete must deny (return ``None``), regardless of
``require_auth``. The only permissive conveniences that remain are the
documented dev handshakes: a missing token (-> ``"anonymous"``) and a
single-part plain-fingerprint dev token, which now ALSO requires the explicit
``SKCOMMS_DEV_AUTH=1`` environment gate (permissive mode alone is no longer
enough to accept an unverified claimed identity).

Also covered here:

- remote validation must honor the ``valid`` field of the CapAuth API
  response (a fingerprint without ``valid: true`` used to be accepted),
- remote validation must reject an identity swap (remote fingerprint that
  differs from the one claimed in the token),
- ``SignalingBroker`` now defaults to a strict validator.
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


# --- Dev plain-fingerprint bypass: requires the explicit env gate ------------


def test_permissive_plain_fingerprint_without_env_fails_closed(monkeypatch):
    """require_auth=False alone must NOT accept an unverified claimed identity."""
    monkeypatch.delenv("SKCOMMS_DEV_AUTH", raising=False)
    v = CapAuthValidator(require_auth=False)
    assert v.validate(VICTIM_FP) is None


def test_permissive_plain_fingerprint_with_env_gate_accepted(monkeypatch):
    """The dev bypass survives, but only behind the explicit SKCOMMS_DEV_AUTH gate."""
    monkeypatch.setenv("SKCOMMS_DEV_AUTH", "1")
    v = CapAuthValidator(require_auth=False)
    assert v.validate(VICTIM_FP) == VICTIM_FP


def test_strict_mode_ignores_dev_env_gate(monkeypatch):
    """SKCOMMS_DEV_AUTH must never weaken strict mode."""
    monkeypatch.setenv("SKCOMMS_DEV_AUTH", "1")
    v = CapAuthValidator(require_auth=True)
    assert v.validate(VICTIM_FP) is None


def test_dev_env_gate_falsy_values_stay_closed(monkeypatch):
    """Only explicit truthy values enable the bypass."""
    v = CapAuthValidator(require_auth=False)
    for val in ("0", "false", "no", "", "  "):
        monkeypatch.setenv("SKCOMMS_DEV_AUTH", val)
        assert v.validate(VICTIM_FP) is None


# --- Remote validation must honor the CapAuth verdict ------------------------


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        import json

        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_remote(monkeypatch, payload: dict) -> None:
    import urllib.request

    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: _FakeResponse(payload)
    )


def _signed_token() -> str:
    return f"{VICTIM_FP}.{_fresh_ts()}.{'x' * 40}"


def test_remote_valid_false_fails_closed(monkeypatch):
    """Remote naming a fingerprint but saying valid: false must deny."""
    _patch_remote(monkeypatch, {"fingerprint": VICTIM_FP, "valid": False})
    v = CapAuthValidator(capauth_url="https://capauth.test", require_auth=False)
    assert v.validate(_signed_token()) is None


def test_remote_missing_valid_field_fails_closed(monkeypatch):
    """A response without an explicit valid: true must deny (old fail-open)."""
    _patch_remote(monkeypatch, {"fingerprint": VICTIM_FP})
    v = CapAuthValidator(capauth_url="https://capauth.test", require_auth=True)
    assert v.validate(_signed_token()) is None


def test_remote_fingerprint_swap_fails_closed(monkeypatch):
    """Remote returning a different identity than the token claims must deny."""
    other_fp = "B" * 40
    _patch_remote(monkeypatch, {"fingerprint": other_fp, "valid": True})
    v = CapAuthValidator(capauth_url="https://capauth.test", require_auth=True)
    assert v.validate(_signed_token()) is None


def test_remote_valid_true_accepted(monkeypatch):
    """The happy path still works: valid: true + matching fingerprint."""
    _patch_remote(monkeypatch, {"fingerprint": VICTIM_FP, "valid": True})
    v = CapAuthValidator(capauth_url="https://capauth.test", require_auth=True)
    assert v.validate(_signed_token()) == VICTIM_FP


def test_remote_unreachable_strict_fails_closed(monkeypatch):
    """Strict mode denies outright when the remote cannot be reached."""
    import urllib.request

    def _boom(*a, **k):
        raise OSError("capauth unreachable (simulated)")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    v = CapAuthValidator(capauth_url="https://capauth.test", require_auth=True)
    assert v.validate(_signed_token()) is None


def test_remote_unreachable_permissive_falls_back_to_failclosed_local(monkeypatch):
    """Permissive fallback goes to LOCAL verification, which is fail-closed:
    an unverifiable signed-looking token is still denied."""
    import urllib.request

    def _boom(*a, **k):
        raise OSError("capauth unreachable (simulated)")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.delenv("SKCOMMS_DEV_AUTH", raising=False)
    v = CapAuthValidator(capauth_url="https://capauth.test", require_auth=False)
    # No local pubkey for VICTIM_FP, so local verification denies.
    assert v.validate(_signed_token()) is None
    # And the plain-fingerprint claim is denied too without the env gate.
    assert v.validate(VICTIM_FP) is None


# --- SignalingBroker defaults to strict ---------------------------------------


def test_signaling_broker_defaults_to_strict():
    """A bare SignalingBroker() must reject unauthenticated peers."""
    from skcomms.signaling import SignalingBroker

    broker = SignalingBroker()
    assert broker.authenticate(None) is None
    assert broker.authenticate(f"Bearer {VICTIM_FP}") is None


# --- Legitimate permissive conveniences that must be PRESERVED ---------------


def test_permissive_missing_token_is_anonymous():
    """No token at all -> documented dev 'anonymous', not a rejection."""
    v = CapAuthValidator(require_auth=False)
    assert v.validate(None) == "anonymous"
    assert v.validate("") == "anonymous"
