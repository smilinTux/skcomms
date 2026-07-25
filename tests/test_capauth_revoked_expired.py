"""CapAuth validator must reject REVOKED and EXPIRED signing keys.

Security regression tests for card 6abe9bef. Both ``_validate_local`` and
``verify_detached`` used to call ``pgpy.PGPKey.verify()`` directly, and pgpy
performs neither revocation nor expiry checks (its source literally warns
"Revocation checks are not yet implemented"). So a signature made by a key
that had been REVOKED or had EXPIRED still authenticated on the WebRTC
signaling / SDP auth path: a compromised-then-revoked agent key kept working.

The fix routes the usability decision through capauth's revocation/expiry
check (``capauth.crypto.pgpy_backend._assert_key_usable``, card a93b0528),
with an inline fallback that mirrors it. Revoked/expired keys must now fail
closed, while a healthy key still verifies.

Fail-before (on origin/main these assertions FAIL because the revoked/expired
signature was accepted) / pass-after.
"""

from __future__ import annotations

import base64
import time

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    EllipticCurveOID,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SignatureType,
    SymmetricKeyAlgorithm,
)

from skcomms.capauth_validator import (
    CapAuthValidator,
    _reject_reason_if_key_unusable,
)


def _make_signing_key(uid: str = "revtest"):
    """A fresh Ed25519 signing key with a Sign+Certify UID."""
    key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
    key.add_uid(
        pgpy.PGPUID.new(uid, email=f"{uid}@x.io"),
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    return key


def _revoke(key):
    """Attach a primary-key revocation signature."""
    rev = key.revoke(key, sigtype=SignatureType.KeyRevocation)
    key |= rev
    return key


def _fp(key) -> str:
    return str(key.fingerprint).replace(" ", "").upper()


def _local_token(key, ts: str | None = None) -> str:
    """Build a production ``fp.ts.sig`` token signed by ``key``."""
    fp = _fp(key)
    ts = ts or str(int(time.time()))
    signed_text = f"capauth:{fp}:{ts}"
    sig = key.sign(signed_text)
    sig_b64url = base64.urlsafe_b64encode(bytes(sig)).decode().rstrip("=")
    return f"{fp}.{ts}.{sig_b64url}"


# --------------------------------------------------------------------------- #
# _validate_local: signed token path                                          #
# --------------------------------------------------------------------------- #


def test_local_valid_key_still_passes(monkeypatch):
    """A healthy (non-revoked, non-expired) key must still authenticate."""
    key = _make_signing_key()
    token = _local_token(key)

    v = CapAuthValidator()
    monkeypatch.setattr(v, "_load_public_key", lambda fp: key.pubkey)
    assert v.validate(token) == _fp(key)


def test_local_revoked_key_rejected(monkeypatch):
    """A signature from a REVOKED key must be rejected (was accepted before)."""
    key = _make_signing_key()
    token = _local_token(key)  # signed while healthy
    _revoke(key)  # key later revoked

    v = CapAuthValidator()
    monkeypatch.setattr(v, "_load_public_key", lambda fp: key.pubkey)
    # The raw pgpy signature is still cryptographically "valid" (pgpy ignores
    # revocation), so ONLY the new revocation check can reject this token.
    assert v.validate(token) is None


# --------------------------------------------------------------------------- #
# verify_detached: SDP auth path                                              #
# --------------------------------------------------------------------------- #


def test_detached_valid_key_still_passes(monkeypatch):
    key = _make_signing_key()
    payload = "sdp-offer-payload"
    sig = key.sign(payload)

    v = CapAuthValidator()
    monkeypatch.setattr(v, "_load_public_key", lambda fp: key.pubkey)
    assert v.verify_detached(payload, str(sig), _fp(key)) is True


def test_detached_revoked_key_rejected(monkeypatch):
    key = _make_signing_key()
    payload = "sdp-offer-payload"
    sig = key.sign(payload)  # signed while healthy
    _revoke(key)

    v = CapAuthValidator()
    monkeypatch.setattr(v, "_load_public_key", lambda fp: key.pubkey)
    assert v.verify_detached(payload, str(sig), _fp(key)) is False


# --------------------------------------------------------------------------- #
# helper: revocation + expiry, and the inline fallback                        #
# --------------------------------------------------------------------------- #


def test_helper_passes_healthy_key():
    key = _make_signing_key()
    assert _reject_reason_if_key_unusable(key.pubkey, {key.pubkey.fingerprint.keyid}) is None


def test_helper_rejects_revoked_key():
    key = _make_signing_key()
    _revoke(key)
    reason = _reject_reason_if_key_unusable(key.pubkey, set())
    assert reason is not None
    assert "revocation" in reason.lower()


class _FakeExpiredKey:
    """Minimal stand-in exercising the expiry branch without a real self-sig."""

    def __init__(self):
        self.fingerprint = "F" * 40
        self.revocation_signatures = []
        self.is_expired = True
        self.subkeys = {}


def test_helper_rejects_expired_key():
    reason = _reject_reason_if_key_unusable(_FakeExpiredKey(), set())
    assert reason is not None
    assert "expired" in reason.lower()


def test_inline_fallback_rejects_revoked_when_capauth_unavailable(monkeypatch):
    """If capauth's helper cannot be imported, the inline check still rejects."""
    import builtins

    real_import = builtins.__import__

    def _no_capauth(name, *args, **kwargs):
        if name.startswith("capauth"):
            raise ImportError("capauth unavailable (simulated)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_capauth)

    key = _make_signing_key()
    _revoke(key)
    reason = _reject_reason_if_key_unusable(key.pubkey, set())
    assert reason is not None
    assert "revocation" in reason.lower()
