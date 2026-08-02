"""Hybrid PQ message sealing — the PQXDH-style wrap for DMs + envelope payloads.

This is **Phase 1 / Q3** of the PQC-MIGRATION epic (coord ``e1d6ba2a``; plan
``skchat/docs/quantum-resistance-architecture.md`` §3 S4/S6, §5 Phase 1). It is
the HNDL fix for two confidentiality surfaces:

    * skcomms envelope payload (``skcomms.crypto.EnvelopeCrypto``)
    * skchat 1:1 DM body (``skchat.crypto.ChatCrypto.encrypt_message``)

Both surfaces share ONE construction, defined here, so the crypto is written
once and never re-implemented per caller. It composes the vetted Q1 primitive
(:mod:`skcomms.pqkem`, ``x25519-mlkem768``) with AES-256-GCM + HKDF — exactly the
wrap/derive idiom Q2 established in :mod:`skchat.group_ratchet`.

The handshake (PQXDH-style)
---------------------------
1. The recipient publishes a **signed hybrid-KEM prekey** in their bundle (a
   :class:`PrekeyBundle`: the 1216-byte hybrid public key + the suite id, signed
   by the recipient's long-lived identity key so a sender can authenticate it —
   the *signature* stays classical for now, Phase 2 of the plan; the KEM it
   protects is what becomes quantum-resistant here).
2. A sender that sees a hybrid prekey **encapsulates to it** (``hybrid_encap``),
   derives an AES-256 message key from the shared secret, and AES-256-GCM-seals
   the body. The ~1.1 KB KEM ciphertext rides in the first/only message
   (PQXDH "first message carries the KEM ciphertext").

The sealed blob (the interop wire contract)::

    sealed = ct(1120) || nonce(12) || aesgcm(body)        # body + 16-byte tag

The combiner / wrap-key derivation mirrors group_ratchet::

    ss        = hybrid_encap(prekey_pub)                   # X25519 || ML-KEM-768
    wrap_key  = HKDF-SHA256(ss, salt=b"", info=_INFO_WRAP || aad)
    sealed    = ct || nonce || AES-256-GCM(wrap_key).encrypt(nonce, body, aad)

Crypto-agility + downgrade-lock
-------------------------------
The negotiated suite id is **bound into the AEAD AAD** (the transcript). A peer
that strips the hybrid prekey to force a classical downgrade changes the
negotiated suite the sender records and seals under — so a man-in-the-middle
cannot *silently* strip the PQ option: the recipient's AEAD open fails (the AAD
won't match) OR the recorded ``negotiated_suite`` on the resulting object no
longer says hybrid, which the per-conversation self-report surfaces. The lock is
the AAD binding (``downgrade_lock_aad``); detection is the self-report.

Honesty / fallback
------------------
This module performs hybrid sealing ONLY. It never silently downgrades: a caller
gates on whether a hybrid prekey is present (``PrekeyBundle.is_hybrid``). If the
recipient advertises no hybrid prekey, the caller keeps the existing **classical**
path byte-for-byte (negotiated downgrade) — hybrid is opt-in and applies only
when both sides advertise it. If liboqs is missing, hybrid sealing raises loudly
(via :mod:`skcomms.pqkem`); the classical path is unaffected.
"""

from __future__ import annotations

# --- coord 0a1f0a51: prefer the published sk_pqc lib; fall back to local impl --
# When the published ``sk_pqc`` package is installed this module re-exports its
# vetted primitives (byte-identical to the local definitions below, which were
# lifted verbatim into sk_pqc). On boxes WITHOUT sk-pqc (e.g. .41) the import
# fails and the UNCHANGED local definitions below are used — same behaviour
# either way. Hybrid security holds while EITHER leg (X25519 or ML-KEM-768)
# survives; this is never "quantum-proof". The footer lets the published lib win.
try:
    from sk_pqc.pqdm import *  # noqa: F401,F403  (published lib preferred)

    _SK_PQC_BACKED = True
except Exception:  # noqa: BLE001 — sk-pqc absent: use local fallback below
    _SK_PQC_BACKED = False
# --- local fallback definitions follow, UNCHANGED ----------------------------

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .pqkem import (
    CIPHERTEXT_LEN as HYBRID_CIPHERTEXT_LEN,
)
from .pqkem import (
    PUBLIC_KEY_LEN as HYBRID_PUBLIC_KEY_LEN,
)
from .pqkem import (
    PqKemError,
    hybrid_decap,
    hybrid_encap,
    hybrid_keypair,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The hybrid KEM suite id (matches ``skcomms.pqkem.SUITE_ID`` /
#: ``skcomms.crypto_suites`` / ``skchat.group_ratchet.HYBRID_KEM_SUITE``).
HYBRID_SUITE = "x25519-mlkem768"

#: The classical suite id a peer falls back to when it has no hybrid prekey.
#: (skcomms envelope / skchat DM PGP key-wrap; see ``crypto_suites``.)
CLASSICAL_SUITE = "x25519-pgp-wrap-v1"

#: HKDF domain-separation label for the DM/envelope wrap key (never reused
#: across layers — distinct from group_ratchet's epoch-wrap label).
_INFO_WRAP = b"skcomms/pqdm/wrap/v1"

_WRAP_NONCE_LEN = 12
_AESGCM_TAG_LEN = 16

#: Minimum sealed blob = ct(1120) + nonce(12) + tag(16) for an empty body.
SEALED_MIN_LEN = HYBRID_CIPHERTEXT_LEN + _WRAP_NONCE_LEN + _AESGCM_TAG_LEN


class PqDmError(Exception):
    """Base error for hybrid DM/envelope sealing."""


class PqDmFormatError(PqDmError, ValueError):
    """Malformed prekey bundle / sealed blob (never a crash)."""


class DowngradeDetected(PqDmError):  # noqa: N818 — deliberate name (a detection event)
    """Raised when the bound negotiated suite does not match on open.

    Signals a possible silent-downgrade / transcript-tamper attempt: the AAD the
    recipient reconstructs (from the suite it believes was negotiated) does not
    authenticate the sealed body. The caller should treat this as a security
    event, not retry as classical.
    """


# ---------------------------------------------------------------------------
# Prekey bundle (the published handshake material)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrekeyBundle:
    """A recipient's published hybrid-KEM prekey (PQXDH-style).

    A peer advertises this in their key bundle. A sender that sees a hybrid
    prekey encapsulates to it; a peer that advertises none gets the classical
    path (negotiated downgrade).

    Attributes:
        suite: The KEM suite this prekey is for. ``x25519-mlkem768`` => hybrid.
        hybrid_public_hex: Hex of the 1216-byte hybrid public key, or ``""`` for
            a classical-only peer (no hybrid prekey published).
        signature: Optional classical signature over the prekey by the
            recipient's identity key (authenticity of the prekey; the signature
            itself stays classical until Phase 2). Opaque here — verified by the
            caller's existing identity layer.
        key_id: Optional opaque prekey id (for rotation/selection).
    """

    suite: str = CLASSICAL_SUITE
    hybrid_public_hex: str = ""
    signature: Optional[str] = None
    key_id: Optional[str] = None

    @property
    def is_hybrid(self) -> bool:
        """Whether this bundle advertises a usable hybrid prekey."""
        return self.suite == HYBRID_SUITE and bool(self.hybrid_public_hex)

    def hybrid_public(self) -> bytes:
        """Decode + validate the hybrid public key bytes.

        Raises:
            PqDmFormatError: if no hybrid prekey or wrong length.
        """
        if not self.hybrid_public_hex:
            raise PqDmFormatError("bundle has no hybrid prekey")
        try:
            pub = bytes.fromhex(self.hybrid_public_hex)
        except ValueError as exc:
            raise PqDmFormatError(f"hybrid_public_hex not hex: {exc}") from exc
        if len(pub) != HYBRID_PUBLIC_KEY_LEN:
            raise PqDmFormatError(
                f"hybrid public key must be {HYBRID_PUBLIC_KEY_LEN} bytes, "
                f"got {len(pub)}"
            )
        return pub

    def to_dict(self) -> dict:
        """JSON-safe view (for publishing in a key bundle / peer record)."""
        return {
            "suite": self.suite,
            "hybrid_public_hex": self.hybrid_public_hex,
            "signature": self.signature,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "PrekeyBundle":
        """Parse a bundle from a peer record (tolerant — missing => classical).

        A peer record with no ``sk_pqc`` / prekey block yields a classical
        bundle (``is_hybrid == False``), which is exactly the negotiated
        downgrade: such a peer keeps the existing classical flow.
        """
        if not data:
            return cls()
        return cls(
            suite=data.get("suite", CLASSICAL_SUITE),
            hybrid_public_hex=data.get("hybrid_public_hex", "") or "",
            signature=data.get("signature"),
            key_id=data.get("key_id"),
        )


# ---------------------------------------------------------------------------
# Downgrade-lock AAD (binds the negotiated suite into the transcript)
# ---------------------------------------------------------------------------


def downgrade_lock_aad(
    negotiated_suite: str,
    sender: str = "",
    recipient: str = "",
    extra: Optional[bytes] = None,
) -> bytes:
    """Build the AEAD AAD that binds the negotiated suite into the transcript.

    The negotiated suite (and the conversation parties) are authenticated by the
    AEAD but NOT encrypted. A man-in-the-middle that strips the hybrid prekey to
    force a downgrade changes what the sender records as ``negotiated_suite`` and
    seals under — so the binding cannot be silently altered: tampering either
    fails the recipient's AEAD open (:class:`DowngradeDetected`) or is visible in
    the recorded suite (self-report). Deterministic + canonical (sorted JSON) so
    both sides derive identical bytes.

    Args:
        negotiated_suite: The suite both sides agreed on (hybrid or classical).
        sender / recipient: Optional party identifiers to bind into the AAD.
        extra: Optional extra context bytes appended verbatim.

    Returns:
        Canonical AAD bytes.
    """
    head = json.dumps(
        {
            "v": 1,
            "negotiated_suite": negotiated_suite,
            "sender": sender,
            "recipient": recipient,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return head + (extra or b"")


# ---------------------------------------------------------------------------
# Seal / open (the only original crypto — wiring pqkem + AES-256-GCM + HKDF)
# ---------------------------------------------------------------------------


def _wrap_key(shared: bytes, aad: bytes) -> bytes:
    """Derive the AES-256 wrap key from the hybrid shared secret + AAD.

    The AAD is folded into the HKDF ``info`` so the wrap key itself is bound to
    the negotiated suite/transcript (defence in depth alongside the AEAD AAD).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=_INFO_WRAP + b"|" + aad,
    ).derive(shared)


def seal(
    plaintext: bytes,
    bundle: PrekeyBundle,
    *,
    sender: str = "",
    recipient: str = "",
) -> bytes:
    """Hybrid-seal a plaintext body to a recipient's hybrid prekey.

    Encapsulates to the bundle's hybrid public key (X25519 || ML-KEM-768), derives
    an AES-256 wrap key, and AES-256-GCM-seals the body with the downgrade-lock
    AAD (binding ``negotiated_suite = x25519-mlkem768``). The KEM ciphertext rides
    in the sealed blob so the recipient can decapsulate.

    Args:
        plaintext: The body to seal (e.g. the DM / payload bytes).
        bundle: The recipient's prekey bundle (MUST be hybrid; callers gate via
            ``bundle.is_hybrid`` and take the classical path otherwise).
        sender / recipient: Party identifiers bound into the AAD.

    Returns:
        ``ct(1120) || nonce(12) || aesgcm(body+tag)`` bytes.

    Raises:
        PqDmFormatError: if the bundle is not hybrid / malformed.
        PqKemError / PqKemUnavailable: propagated from the KEM (never silently
            downgraded — a missing liboqs is a hard error on the hybrid path).
    """
    if not bundle.is_hybrid:
        raise PqDmFormatError(
            "seal() requires a hybrid prekey bundle; classical peers use the "
            "existing classical path (negotiated downgrade)"
        )
    pub = bundle.hybrid_public()
    aad = downgrade_lock_aad(HYBRID_SUITE, sender=sender, recipient=recipient)

    ciphertext, shared = hybrid_encap(pub)
    wrap_key = _wrap_key(shared, aad)
    nonce = os.urandom(_WRAP_NONCE_LEN)
    body = AESGCM(wrap_key).encrypt(nonce, bytes(plaintext), aad)
    return ciphertext + nonce + body


def open_sealed(
    sealed: bytes,
    hybrid_private: bytes,
    *,
    sender: str = "",
    recipient: str = "",
    expected_suite: str = HYBRID_SUITE,
) -> bytes:
    """Open a hybrid-sealed blob with the recipient's hybrid private key.

    Reconstructs the downgrade-lock AAD from the suite the recipient believes was
    negotiated (``expected_suite``); if a downgrade was attempted the AAD won't
    authenticate and the AEAD open fails -> :class:`DowngradeDetected`.

    Args:
        sealed: ``ct || nonce || aesgcm(body)`` from :func:`seal`.
        hybrid_private: The recipient's 2432-byte hybrid private key.
        sender / recipient: Party identifiers (MUST match the seal call).
        expected_suite: The suite the recipient believes was negotiated. Bound
            into the AAD — a mismatch (silent downgrade) fails the open.

    Returns:
        The decrypted plaintext body.

    Raises:
        PqDmFormatError: on malformed input.
        DowngradeDetected: if the AEAD open fails (tamper / suite mismatch).
        PqKemError / PqKemUnavailable: propagated from the KEM.
    """
    if not isinstance(sealed, (bytes, bytearray)):
        raise PqDmFormatError(
            f"sealed must be bytes, got {type(sealed).__name__}"
        )
    if len(sealed) < SEALED_MIN_LEN:
        raise PqDmFormatError(
            f"sealed blob must be >= {SEALED_MIN_LEN} bytes, got {len(sealed)}"
        )
    ciphertext = bytes(sealed[:HYBRID_CIPHERTEXT_LEN])
    nonce = bytes(
        sealed[HYBRID_CIPHERTEXT_LEN : HYBRID_CIPHERTEXT_LEN + _WRAP_NONCE_LEN]
    )
    body = bytes(sealed[HYBRID_CIPHERTEXT_LEN + _WRAP_NONCE_LEN :])

    aad = downgrade_lock_aad(expected_suite, sender=sender, recipient=recipient)
    shared = hybrid_decap(ciphertext, hybrid_private)
    wrap_key = _wrap_key(shared, aad)
    try:
        return AESGCM(wrap_key).decrypt(nonce, body, aad)
    except Exception as exc:  # GCM auth failure / wrong key / downgrade
        raise DowngradeDetected(
            "hybrid-sealed open failed — wrong key, tampered ciphertext, or a "
            f"suite-downgrade attempt (AAD bound suite={expected_suite!r}): {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Negotiation helper
# ---------------------------------------------------------------------------


def negotiate_suite(local_supports_hybrid: bool, bundle: PrekeyBundle) -> str:
    """Return the suite both sides agree on (the recorded ``negotiated_suite``).

    Hybrid only when BOTH the local side supports it AND the recipient advertises
    a hybrid prekey; otherwise the classical suite (negotiated downgrade). This
    is the single gate callers use so the recorded suite is honest.
    """
    if local_supports_hybrid and bundle.is_hybrid:
        return HYBRID_SUITE
    return CLASSICAL_SUITE


# ---------------------------------------------------------------------------
# pqdm2: multi-recipient (fanout) envelope
# ---------------------------------------------------------------------------
#
# One DM is sealed ONCE under a random 32-byte message key ``K``; ``K`` is then
# wrapped once per recipient device slot (its own hybrid_encap + HKDF + AESGCM),
# modelled on the audited ``group_ratchet`` per-member wrap. The recipient set is
# every peer device slot PLUS every one of the sender's own device slots, so all
# enrolled devices of both parties can open the message. See
# ``docs/superpowers/specs/2026-08-02-multi-device-dm-fanout-design.md`` section 4.
#
# Token layout (interop contract -- must match sk_pqc / sk-pqc-dart byte-for-byte)::
#
#     pqdm2: + b64(header_json) + "." + b64(slots) + "." + b64(nonce || ct)
#
#     header = {"v":2,"suite":...,"sender":...,"recipient":...,"kids":[key_id,...]}
#     slot   = key_id_len(1) || key_id || encap(1120) || wrappedK(48)
#
# AAD binds ``suite || sender || recipient || sha256("".join(sorted(kids)))`` so a
# store-writer that strips a slot (and its kid) breaks every remaining open: the
# slot-set is authenticated by the body AEAD.

#: Token scheme prefix for the multi-recipient envelope.
PQDM2_PREFIX = "pqdm2:"

#: Header codec version recorded for skew tolerance.
PQDM2_VERSION = 2

#: HKDF domain-separation label for the per-slot ``K`` wrap key. Distinct from
#: the single-recipient ``_INFO_WRAP`` label (never reuse a wrap label across
#: constructions).
_PQDM2_WRAP_INFO = b"pqdm2-wrap"

#: Bytes wrapping ``K``: 32-byte key + 16-byte GCM tag.
_PQDM2_WRAPPED_K_LEN = 32 + _AESGCM_TAG_LEN


def generate_hybrid_keypair() -> tuple[str, str]:
    """Generate a hybrid keypair as ``(public_hex, private_hex)``.

    Thin hex-encoding shim over :func:`skcomms.pqkem.hybrid_keypair` (the same
    primitive :func:`seal` encapsulates to). Exposed here so callers that speak in
    hex prekey material (the prekey store, the fanout sender, tests) have a single
    keygen entry point on the ``pqdm`` surface.

    Returns:
        ``(public_hex, private_hex)`` -- 1216-byte public / 2432-byte private,
        hex-encoded.

    Raises:
        PqKemUnavailable: if the liboqs/``oqs`` backend is missing.
    """
    kp = hybrid_keypair()
    return kp.public_key.hex(), kp.private_key.hex()


def _pqdm2_aad(suite: str, sender: str, recipient: str, kids: list[str]) -> bytes:
    """Build the pqdm2 body AAD, binding the suite, parties, and slot-set.

    ``suite || "|" || sender || "|" || recipient || "|" || sha256(sorted kids)``.
    The kid-set digest binds the envelope to its exact recipient list so a
    slot-stripping tamper fails the body open.
    """
    kid_digest = hashlib.sha256("".join(sorted(kids)).encode("utf-8")).digest()
    return (
        suite.encode("utf-8")
        + b"|"
        + sender.encode("utf-8")
        + b"|"
        + recipient.encode("utf-8")
        + b"|"
        + kid_digest
    )


def _pqdm2_wrap_key(shared: bytes) -> bytes:
    """Derive the AES-256 wrap key for one slot from that slot's shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=_PQDM2_WRAP_INFO,
    ).derive(shared)


def seal_multi(
    body: bytes,
    recipients: list,
    *,
    sender: str,
    recipient_id: str,
) -> str:
    """Seal ``body`` once, wrapped per recipient device slot -> a ``pqdm2:`` token.

    Args:
        body: The plaintext body (DM / payload bytes).
        recipients: List of ``{"key_id": str, "hybrid_public_hex": str}`` dicts,
            one per recipient device slot (peer devices + the sender's own).
        sender / recipient_id: Party identifiers bound into the AAD.

    Returns:
        A ``pqdm2:`` token: ``pqdm2:`` + b64(header_json) + "." + b64(slots) +
        "." + b64(nonce || ct).

    Raises:
        PqDmFormatError: if ``recipients`` is empty / malformed.
        PqKemError / PqKemUnavailable: propagated from the KEM.
    """
    if not recipients:
        raise PqDmFormatError("seal_multi() requires at least one recipient slot")

    kids = [r["key_id"] for r in recipients]
    aad = _pqdm2_aad(HYBRID_SUITE, sender, recipient_id, kids)

    message_key = os.urandom(32)
    nonce = os.urandom(_WRAP_NONCE_LEN)
    ct = AESGCM(message_key).encrypt(nonce, bytes(body), aad)

    slots = bytearray()
    for r in recipients:
        key_id = r["key_id"]
        kid_bytes = key_id.encode("utf-8")
        if len(kid_bytes) > 255:
            raise PqDmFormatError(f"key_id too long ({len(kid_bytes)} bytes)")
        try:
            pub = bytes.fromhex(r["hybrid_public_hex"])
        except (ValueError, KeyError, TypeError) as exc:
            raise PqDmFormatError(f"bad hybrid_public_hex for {key_id!r}: {exc}") from exc
        encap, shared = hybrid_encap(pub)
        wrap_key = _pqdm2_wrap_key(shared)
        wrapped_k = AESGCM(wrap_key).encrypt(nonce, message_key, None)
        slots.append(len(kid_bytes))
        slots += kid_bytes
        slots += encap
        slots += wrapped_k

    header = {
        "v": PQDM2_VERSION,
        "suite": HYBRID_SUITE,
        "sender": sender,
        "recipient": recipient_id,
        "kids": kids,
    }
    header_json = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    return (
        PQDM2_PREFIX
        + base64.b64encode(header_json).decode("ascii")
        + "."
        + base64.b64encode(bytes(slots)).decode("ascii")
        + "."
        + base64.b64encode(nonce + ct).decode("ascii")
    )


def _pqdm2_iter_slots(slots: bytes):
    """Yield ``(key_id, encap, wrapped_k)`` for each slot in the packed blob.

    Raises PqDmFormatError on a truncated / malformed slot region.
    """
    off = 0
    n = len(slots)
    while off < n:
        kid_len = slots[off]
        off += 1
        end_kid = off + kid_len
        end_encap = end_kid + HYBRID_CIPHERTEXT_LEN
        end_wrap = end_encap + _PQDM2_WRAPPED_K_LEN
        if end_wrap > n:
            raise PqDmFormatError("truncated pqdm2 slot")
        key_id = slots[off:end_kid].decode("utf-8", "replace")
        encap = bytes(slots[end_kid:end_encap])
        wrapped_k = bytes(slots[end_encap:end_wrap])
        off = end_wrap
        yield key_id, encap, wrapped_k


def open_multi(
    token: str,
    *,
    my_key_id: str,
    my_private_hex: str,
    sender: str,
    recipient_id: str,
) -> Optional[bytes]:
    """Open a ``pqdm2:`` token by unwrapping this device's slot.

    Recomputes the body AAD from the header's ``kids`` (slot-set binding) and the
    passed party identifiers, finds the slot whose ``key_id == my_key_id``,
    decapsulates + unwraps the message key, then opens the body.

    Returns:
        The plaintext body, or ``None`` if there is no matching slot, the token is
        malformed, or any AEAD open fails (tamper / slot-strip / wrong key). This
        function NEVER raises on a bad token.
    """
    try:
        if not token.startswith(PQDM2_PREFIX):
            return None
        rest = token[len(PQDM2_PREFIX):]
        h_b64, slots_b64, body_b64 = rest.split(".")
        header = json.loads(base64.b64decode(h_b64))
        slots = base64.b64decode(slots_b64)
        blob = base64.b64decode(body_b64)

        kids = header.get("kids", [])
        suite = header.get("suite", HYBRID_SUITE)
        aad = _pqdm2_aad(suite, sender, recipient_id, kids)

        nonce = blob[:_WRAP_NONCE_LEN]
        ct = blob[_WRAP_NONCE_LEN:]

        my_priv = bytes.fromhex(my_private_hex)

        for key_id, encap, wrapped_k in _pqdm2_iter_slots(slots):
            if key_id != my_key_id:
                continue
            shared = hybrid_decap(encap, my_priv)
            wrap_key = _pqdm2_wrap_key(shared)
            message_key = AESGCM(wrap_key).decrypt(nonce, wrapped_k, None)
            return AESGCM(message_key).decrypt(nonce, ct, aad)
        return None
    except Exception:  # noqa: BLE001 -- malformed / tamper / wrong key -> None
        return None


# --- coord 0a1f0a51: when sk-pqc is installed, the published lib is authoritative
# Re-export its public surface so the published objects WIN over the local
# fallbacks defined above (identity: this module's symbols ARE sk_pqc's symbols).
# When sk-pqc is absent this block is skipped and the local fallbacks stand.
if _SK_PQC_BACKED:
    from sk_pqc.pqdm import *  # noqa: F401,F403
