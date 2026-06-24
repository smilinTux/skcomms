"""Hybrid post-quantum signatures — **Ed25519 + ML-DSA-65**.

This is **Phase 2 / Q7** of the PQC-MIGRATION epic (coord ``e1d6ba2a``; plan
``skchat/docs/quantum-resistance-architecture.md`` §5 Phase 2, §6 Q7). It
delivers *one vetted hybrid-signature primitive* — the per-message authentication
analogue of the Q1 hybrid KEM (:mod:`skcomms.pqkem`). Q7's signing surfaces
(``skcomms.signing.EnvelopeSigner`` and capauth's DID/challenge) compose on top
of this module; **this module does not wire itself into signing.py / capauth.**

Suite id: ``mldsa65-ed25519-v2`` — the registry entry (see
:mod:`skcomms.crypto_suites`) for an Ed25519 + ML-DSA-65 composite signature.
The construction mirrors the OpenPGP PQC composite (draft-ietf-openpgp-pqc-17,
alg 30) and the standard "hybrid signature" combiner: BOTH legs are produced
over the SAME message and BOTH must verify.

GOLDEN RULE — we never implement the lattice or curve signature math:
    * **ML-DSA-65** leg -> ``oqs.Signature("ML-DSA-65")`` (binds liboqs, FIPS 204).
    * **Ed25519** leg   -> ``cryptography`` (pyca) Ed25519 (RFC 8032).

The *only* original cryptographic code is the **composite encode/verify glue**
(the length-prefixed, versioned, suite-tagged wire format below) and the
"both-legs-must-verify" AND gate.

Security model — strong-unforgeable if EITHER scheme holds
----------------------------------------------------------
A hybrid signature is **valid iff Ed25519 AND ML-DSA-65 both verify** over the
same message. This is the standard hybrid-signature construction: an adversary
who can forge one scheme still cannot produce a composite that passes, because
the *other* leg's verification fails. The composite is therefore secure (no
forgery) as long as *at least one* of the two schemes remains unforgeable —
classical security holds until BOTH Ed25519 and ML-DSA-65 are broken. (Contrast
with the hybrid *KEM* combiner in :mod:`skcomms.pqkem`, which is confidential if
either secret stays secret; for signatures the dual property is unforgeability,
achieved by requiring both legs.)

Wire format — the interop contract (MUST NOT change)
----------------------------------------------------
The composite signature is a self-describing, length-prefixed byte string. All
multi-byte integers are **big-endian**. ``ed25519_sig`` is fixed at 64 bytes;
the ML-DSA-65 leg is length-prefixed because, although ML-DSA-65 signatures are
3309 bytes today, the explicit length keeps the format robust to algorithm
agility (a different ML-DSA variant would carry a different fixed size)::

    offset  size            field
    ------  --------------  -------------------------------------------------
    0       4               MAGIC            = b"SKHS"  (SK Hybrid Sig)
    4       1               VERSION          = 0x01
    5       1               SUITE_TAG        = 0x01  (mldsa65-ed25519-v2)
    6       2               len(ed25519_sig) = 64       (uint16, big-endian)
    8       64              ed25519_sig                  (Ed25519 detached sig)
    72      2               len(mldsa_sig)   = 3309     (uint16, big-endian)
    74      3309            mldsa_sig                    (ML-DSA-65 signature)
    ------  --------------  -------------------------------------------------
    total = 3383 bytes (for the mldsa65-ed25519-v2 suite today)

The Ed25519 leg is signed FIRST, then the ML-DSA-65 leg (the same ordering
convention as the KEM combiner's "X25519 first"). Both legs sign the EXACT same
``message`` bytes — the caller is responsible for passing the canonical bytes
(e.g. ``Envelope.canonical_bytes()`` or the challenge bytes).

A composite produced by this module is byte-for-byte reproducible in its framing
(only the inner signatures vary, since ML-DSA signing is hedged-randomized).

Per-signer ML-DSA keypair (separate from the PGP identity)
----------------------------------------------------------
The hybrid sig needs a **per-signer ML-DSA-65 keypair** generated and persisted
ALONGSIDE the existing Ed25519 (PGP) identity — it is a *distinct* key, NOT
derived from and NOT touching the PGP root key. :class:`HybridSigKeypair` holds
the raw wire bytes for both legs. Persistence (where the ML-DSA private key
lives on disk) is the caller's concern; the helper
:func:`load_or_create_signer_keypair` provides a sane default location
(``~/.skcomms/pqc/<signer>_mldsa65.{key,pub}``), 0600 on the private half,
mirroring the KEM prekey store layout.

Honesty / fallback
------------------
If ``oqs`` (liboqs-python) is unavailable this module raises
:class:`PqSigUnavailable` loudly. It NEVER silently downgrades to an
Ed25519-only signature — a missing PQ binary is a hard error, not a degraded
success. Callers that want a classical-only signature must select the classical
suite explicitly via the registry (``crypto_suites.py``), not by accident. The
Ed25519 leg here is the SAME classical primitive the legacy path uses, so the
classical guarantee is never weakened by adding the ML-DSA leg.

liboqs lookup mirrors :mod:`skcomms.pqkem` (``ensure_liboqs_path``), reused here
so both PQ modules discover the same prebuilt shared library.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Reuse the exact liboqs discovery the KEM module established, so both PQ
# helpers point at the same prebuilt liboqs.so.
from .pqkem import ensure_liboqs_path

# ---------------------------------------------------------------------------
# Interop constants — DO NOT CHANGE (these define the on-wire contract).
# ---------------------------------------------------------------------------

#: Registry suite id for the hybrid signature (see crypto_suites.py).
SUITE_ID = "mldsa65-ed25519-v2"
MLDSA_ALG = "ML-DSA-65"

#: Composite framing magic + version + suite tag.
MAGIC = b"SKHS"  # "SK Hybrid Sig"
VERSION = 0x01
SUITE_TAG = 0x01  # 0x01 -> mldsa65-ed25519-v2 (the only suite tag today)

#: Fixed leg sizes (bytes) for the mldsa65-ed25519-v2 suite.
ED25519_SIG_LEN = 64        # RFC 8032 Ed25519 signature
ED25519_PUB_LEN = 32        # RFC 8032 Ed25519 public key
ED25519_SEED_LEN = 32       # Ed25519 private seed (raw)
MLDSA_PUB_LEN = 1952        # FIPS 204 ML-DSA-65 public key
MLDSA_SECRET_LEN = 4032     # FIPS 204 ML-DSA-65 private key
MLDSA_SIG_LEN = 3309        # FIPS 204 ML-DSA-65 signature

#: Header is MAGIC(4) + VERSION(1) + SUITE_TAG(1) = 6 bytes, then two
#: length-prefixed (uint16) legs.
_HEADER_LEN = len(MAGIC) + 2
_LEN_PREFIX = 2  # uint16 big-endian length prefix per leg

#: Total composite size for this suite (for tests / size budgeting).
COMPOSITE_SIG_LEN = (
    _HEADER_LEN
    + _LEN_PREFIX + ED25519_SIG_LEN
    + _LEN_PREFIX + MLDSA_SIG_LEN
)  # = 3383


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PqSigError(Exception):
    """Base error for the hybrid signature helper."""


class PqSigUnavailable(PqSigError):  # noqa: N818 — deliberate name (not *Error)
    """Raised when the post-quantum backend (liboqs via ``oqs``) is missing.

    Deliberately a *hard* error: we never silently fall back to an
    Ed25519-only signature. A caller that wants a classical-only signature must
    select a classical suite explicitly.
    """


class PqSigFormatError(PqSigError, ValueError):
    """Raised on malformed/wrong-length keys or composite signatures.

    A malformed composite is a *format* failure (it never crashes the
    verifier); a well-formed-but-invalid composite simply returns ``False`` from
    :func:`hybrid_verify`.
    """


# ---------------------------------------------------------------------------
# liboqs lazy import (shares pqkem's discovery)
# ---------------------------------------------------------------------------


def _import_oqs():
    """Import ``oqs`` lazily, raising :class:`PqSigUnavailable` if missing."""
    ensure_liboqs_path()
    try:
        import oqs  # type: ignore
    except Exception as exc:  # ImportError or liboqs load/build failure
        raise PqSigUnavailable(
            "Post-quantum signature backend unavailable: could not import 'oqs' "
            "(liboqs-python). Install with `pip install liboqs-python` and ensure "
            "a liboqs shared library is reachable (e.g. ~/.local/lib/liboqs.so; "
            "set OQS_INSTALL_PATH or SK_PQC_LIBOQS). This is a hard error — the "
            "hybrid signature never silently downgrades to Ed25519-only. "
            f"({exc})"
        ) from exc
    return oqs


def is_available() -> bool:
    """Return True iff the PQ backend (liboqs via ``oqs``) can be imported."""
    try:
        _import_oqs()
        return True
    except PqSigUnavailable:
        return False


# ---------------------------------------------------------------------------
# Keypair container
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HybridSigKeypair:
    """A hybrid SIGNING keypair (both legs), held as raw wire bytes.

    This is a *separate* key from the PGP/Ed25519 *identity* key — the ML-DSA-65
    half is freshly generated and persisted alongside it, never derived from the
    PGP root. The Ed25519 half here is a raw key the hybrid helper owns; in
    practice the caller may instead pass an existing Ed25519 identity key into
    :func:`hybrid_sign` (the two legs are independent).

    Attributes:
        ed25519_priv: 32-byte Ed25519 private seed.
        ed25519_pub: 32-byte Ed25519 public key.
        mldsa_priv: 4032-byte ML-DSA-65 private key.
        mldsa_pub: 1952-byte ML-DSA-65 public key.
    """

    ed25519_priv: bytes
    ed25519_pub: bytes
    mldsa_priv: bytes
    mldsa_pub: bytes


def generate_keypair() -> HybridSigKeypair:
    """Generate a fresh hybrid signing keypair (Ed25519 + ML-DSA-65).

    Returns:
        HybridSigKeypair with raw wire bytes for both legs.

    Raises:
        PqSigUnavailable: if the liboqs/``oqs`` backend is missing.
    """
    oqs = _import_oqs()

    ed_priv = Ed25519PrivateKey.generate()
    ed_seed = ed_priv.private_bytes_raw()
    ed_pub = ed_priv.public_key().public_bytes_raw()

    with oqs.Signature(MLDSA_ALG) as signer:
        mldsa_pub = signer.generate_keypair()
        mldsa_secret = signer.export_secret_key()

    _expect_len("ML-DSA public key", mldsa_pub, MLDSA_PUB_LEN)
    _expect_len("ML-DSA secret key", mldsa_secret, MLDSA_SECRET_LEN)

    return HybridSigKeypair(
        ed25519_priv=bytes(ed_seed),
        ed25519_pub=bytes(ed_pub),
        mldsa_priv=bytes(mldsa_secret),
        mldsa_pub=bytes(mldsa_pub),
    )


# ---------------------------------------------------------------------------
# Composite encode / decode (the only original "crypto-adjacent" code)
# ---------------------------------------------------------------------------


def _encode_composite(ed_sig: bytes, mldsa_sig: bytes) -> bytes:
    """Frame the two legs into the versioned, length-prefixed composite."""
    _expect_len("Ed25519 signature", ed_sig, ED25519_SIG_LEN)
    if len(mldsa_sig) > 0xFFFF:
        raise PqSigFormatError("ML-DSA signature too large to length-prefix")
    out = bytearray()
    out += MAGIC
    out.append(VERSION)
    out.append(SUITE_TAG)
    out += len(ed_sig).to_bytes(_LEN_PREFIX, "big")
    out += ed_sig
    out += len(mldsa_sig).to_bytes(_LEN_PREFIX, "big")
    out += mldsa_sig
    return bytes(out)


def decode_composite(composite: bytes) -> tuple[bytes, bytes]:
    """Parse a composite signature into ``(ed25519_sig, mldsa_sig)``.

    Validates the magic, version, suite tag, and both length prefixes. This is
    public so a verifier can introspect the legs (e.g. for diagnostics) without
    re-implementing the framing.

    Args:
        composite: The composite signature bytes.

    Returns:
        ``(ed25519_sig, mldsa_sig)`` — the two raw leg signatures.

    Raises:
        PqSigFormatError: if the framing is malformed (wrong magic/version/tag,
            truncated, or trailing garbage).
    """
    if not isinstance(composite, (bytes, bytearray)):
        raise PqSigFormatError(
            f"composite must be bytes, got {type(composite).__name__}"
        )
    buf = bytes(composite)
    if len(buf) < _HEADER_LEN + _LEN_PREFIX:
        raise PqSigFormatError("composite signature truncated (header)")
    if buf[: len(MAGIC)] != MAGIC:
        raise PqSigFormatError("bad composite magic (not a SKHS hybrid signature)")
    pos = len(MAGIC)
    version = buf[pos]
    pos += 1
    if version != VERSION:
        raise PqSigFormatError(
            f"unsupported composite version {version} (expected {VERSION})"
        )
    suite_tag = buf[pos]
    pos += 1
    if suite_tag != SUITE_TAG:
        raise PqSigFormatError(
            f"unknown composite suite tag {suite_tag} (expected {SUITE_TAG} "
            f"-> {SUITE_ID})"
        )

    # Ed25519 leg.
    if pos + _LEN_PREFIX > len(buf):
        raise PqSigFormatError("composite truncated (ed25519 length)")
    ed_len = int.from_bytes(buf[pos : pos + _LEN_PREFIX], "big")
    pos += _LEN_PREFIX
    if pos + ed_len > len(buf):
        raise PqSigFormatError("composite truncated (ed25519 body)")
    ed_sig = buf[pos : pos + ed_len]
    pos += ed_len

    # ML-DSA leg.
    if pos + _LEN_PREFIX > len(buf):
        raise PqSigFormatError("composite truncated (ml-dsa length)")
    mldsa_len = int.from_bytes(buf[pos : pos + _LEN_PREFIX], "big")
    pos += _LEN_PREFIX
    if pos + mldsa_len > len(buf):
        raise PqSigFormatError("composite truncated (ml-dsa body)")
    mldsa_sig = buf[pos : pos + mldsa_len]
    pos += mldsa_len

    if pos != len(buf):
        raise PqSigFormatError("composite signature has trailing garbage")
    if ed_len != ED25519_SIG_LEN:
        raise PqSigFormatError(
            f"ed25519 leg must be {ED25519_SIG_LEN} bytes, got {ed_len}"
        )
    return ed_sig, mldsa_sig


# ---------------------------------------------------------------------------
# Public API — sign / verify
# ---------------------------------------------------------------------------


def hybrid_sign(
    message: bytes, ed25519_priv: bytes, mldsa_priv: bytes
) -> bytes:
    """Produce a hybrid composite signature over ``message``.

    Both legs sign the EXACT same ``message`` bytes. The Ed25519 leg is produced
    first, then the ML-DSA-65 leg; they are framed into the composite wire
    format documented at module scope.

    Args:
        message: The exact bytes to sign (caller-canonicalized).
        ed25519_priv: 32-byte raw Ed25519 private seed.
        mldsa_priv: 4032-byte ML-DSA-65 private key.

    Returns:
        The composite signature (``COMPOSITE_SIG_LEN`` bytes for this suite).

    Raises:
        PqSigFormatError: if a key is the wrong size.
        PqSigUnavailable: if the liboqs/``oqs`` backend is missing.
    """
    oqs = _import_oqs()
    if not isinstance(message, (bytes, bytearray)):
        raise PqSigFormatError(
            f"message must be bytes, got {type(message).__name__}"
        )
    _expect_len("Ed25519 private seed", ed25519_priv, ED25519_SEED_LEN)
    _expect_len("ML-DSA private key", mldsa_priv, MLDSA_SECRET_LEN)
    message = bytes(message)

    # Ed25519 leg (classical — same primitive as the legacy path).
    try:
        ed_key = Ed25519PrivateKey.from_private_bytes(bytes(ed25519_priv))
    except Exception as exc:
        raise PqSigFormatError(f"invalid Ed25519 private key: {exc}") from exc
    ed_sig = ed_key.sign(message)

    # ML-DSA-65 leg (FIPS 204, liboqs). Signing is hedged-randomized.
    with oqs.Signature(MLDSA_ALG, secret_key=bytes(mldsa_priv)) as signer:
        try:
            mldsa_sig = signer.sign(message)
        except Exception as exc:
            raise PqSigFormatError(f"ML-DSA signing failed: {exc}") from exc
    _expect_len("ML-DSA signature", mldsa_sig, MLDSA_SIG_LEN)

    return _encode_composite(bytes(ed_sig), bytes(mldsa_sig))


def hybrid_verify(
    message: bytes,
    composite_sig: bytes,
    ed25519_pub: bytes,
    mldsa_pub: bytes,
) -> bool:
    """Verify a hybrid composite signature.

    The composite is valid **iff BOTH the Ed25519 leg AND the ML-DSA-65 leg
    verify** over ``message`` (the standard hybrid-signature AND gate). A
    failure in either leg — or a tampered message — yields ``False``.

    A malformed *composite* (bad framing) raises :class:`PqSigFormatError`; a
    well-formed-but-invalid composite returns ``False`` (never raises). This
    keeps "the bytes are not a valid SKHS object" (programmer/transport error)
    distinct from "the signature does not verify" (authentication failure).

    Args:
        message: The exact bytes that were signed.
        composite_sig: The composite signature from :func:`hybrid_sign`.
        ed25519_pub: 32-byte raw Ed25519 public key.
        mldsa_pub: 1952-byte ML-DSA-65 public key.

    Returns:
        True iff both legs verify; False otherwise.

    Raises:
        PqSigFormatError: if the composite framing or a public key is malformed.
        PqSigUnavailable: if the liboqs/``oqs`` backend is missing.
    """
    oqs = _import_oqs()
    if not isinstance(message, (bytes, bytearray)):
        raise PqSigFormatError(
            f"message must be bytes, got {type(message).__name__}"
        )
    _expect_len("Ed25519 public key", ed25519_pub, ED25519_PUB_LEN)
    _expect_len("ML-DSA public key", mldsa_pub, MLDSA_PUB_LEN)
    message = bytes(message)

    # Parse the framing first (malformed framing is a format error, not a
    # silent "invalid").
    ed_sig, mldsa_sig = decode_composite(composite_sig)

    # Ed25519 leg.
    try:
        ed_key = Ed25519PublicKey.from_public_bytes(bytes(ed25519_pub))
    except Exception as exc:
        raise PqSigFormatError(f"invalid Ed25519 public key: {exc}") from exc
    try:
        ed_key.verify(ed_sig, message)
        ed_ok = True
    except InvalidSignature:
        ed_ok = False

    # ML-DSA-65 leg. liboqs ``verify`` returns a bool (no exception on bad sig).
    try:
        with oqs.Signature(MLDSA_ALG) as verifier:
            mldsa_ok = bool(verifier.verify(message, mldsa_sig, bytes(mldsa_pub)))
    except Exception as exc:
        # A wrong-length pubkey would have been caught above; a genuine backend
        # error is surfaced as a format error rather than a silent False.
        raise PqSigFormatError(f"ML-DSA verification error: {exc}") from exc

    # Hybrid AND gate: BOTH legs required.
    return ed_ok and mldsa_ok


# ---------------------------------------------------------------------------
# Per-signer key persistence (default store; caller may override)
# ---------------------------------------------------------------------------


def default_key_dir() -> Path:
    """Return the default per-signer ML-DSA key directory (``~/.skcomms/pqc``).

    Mirrors the KEM prekey store layout. Created lazily by
    :func:`load_or_create_signer_keypair`.
    """
    return Path.home() / ".skcomms" / "pqc"


def load_or_create_signer_keypair(
    signer: str, key_dir: Path | None = None
) -> HybridSigKeypair:
    """Load (or generate + persist) a per-signer hybrid signing keypair.

    The ML-DSA-65 private key lives at ``<key_dir>/<signer>_mldsa65.key`` (0600);
    its public half at ``<signer>_mldsa65.pub``. The Ed25519 raw key the hybrid
    helper owns lives at ``<signer>_ed25519.key`` / ``.pub``. This key is
    SEPARATE from — and never derived from — the PGP identity key; the PGP root
    is untouched. Callers that already have an Ed25519 identity key can ignore
    the persisted Ed25519 half and pass their own into :func:`hybrid_sign`.

    Args:
        signer: A stable signer id (e.g. an agent name or fingerprint) used in
            the filenames.
        key_dir: Override the directory (defaults to :func:`default_key_dir`).

    Returns:
        The loaded-or-created :class:`HybridSigKeypair`.

    Raises:
        PqSigUnavailable: if the PQ backend is missing (cannot create the
            ML-DSA half).
    """
    kd = key_dir or default_key_dir()
    kd.mkdir(parents=True, exist_ok=True)
    safe = signer.replace("/", "_").replace(":", "_")
    ed_key_f = kd / f"{safe}_ed25519.key"
    ed_pub_f = kd / f"{safe}_ed25519.pub"
    md_key_f = kd / f"{safe}_mldsa65.key"
    md_pub_f = kd / f"{safe}_mldsa65.pub"

    if all(f.exists() for f in (ed_key_f, ed_pub_f, md_key_f, md_pub_f)):
        kp = HybridSigKeypair(
            ed25519_priv=ed_key_f.read_bytes(),
            ed25519_pub=ed_pub_f.read_bytes(),
            mldsa_priv=md_key_f.read_bytes(),
            mldsa_pub=md_pub_f.read_bytes(),
        )
        # Validate sizes; regenerate on corruption rather than silently using a
        # bad key.
        try:
            _expect_len("Ed25519 private seed", kp.ed25519_priv, ED25519_SEED_LEN)
            _expect_len("ML-DSA private key", kp.mldsa_priv, MLDSA_SECRET_LEN)
            return kp
        except PqSigFormatError:
            pass  # fall through to regenerate

    kp = generate_keypair()
    md_key_f.write_bytes(kp.mldsa_priv)
    ed_key_f.write_bytes(kp.ed25519_priv)
    md_pub_f.write_bytes(kp.mldsa_pub)
    ed_pub_f.write_bytes(kp.ed25519_pub)
    for f in (md_key_f, ed_key_f):
        try:
            f.chmod(0o600)
        except OSError:
            pass
    return kp


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expect_len(label: str, value: bytes, expected: int) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise PqSigFormatError(f"{label} must be bytes, got {type(value).__name__}")
    if len(value) != expected:
        raise PqSigFormatError(f"{label} must be {expected} bytes, got {len(value)}")
