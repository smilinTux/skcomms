"""Cryptographic suite registry — the single source of truth for what every
crypto suite-id *means* and whether it is quantum-resistant.

This is **Phase 0 (Q0)** of the PQC-MIGRATION epic: pure agility scaffolding.
It introduces **no new algorithms** and changes **no crypto**. It only gives
every encrypted/signed object a machine-readable *suite identifier* and a
registry that maps that id → primitives + quantum-resistance status + FIPS
references. This is what makes future algorithm swaps non-breaking
(policy/mechanism separation, NIST CSWP 39) and what lets the runtime
self-report make honest, evidence-backed claims (see §0/§4.4 of
``docs/quantum-resistance-architecture.md``).

Honesty rule (enforced here by the ``status`` field): until Phase 1 lands,
**everything we actually use is ``classical``**. The hybrid-PQ suites are
seeded as ``active=False`` placeholders so the registry can describe the
*planned* migration target without ever implying it is live.

A "suite" is one of three *kinds*:
    - ``kem``  — key encapsulation / key exchange (confidentiality, HNDL-relevant)
    - ``sig``  — digital signature (authentication, future-forgery-relevant)
    - ``aead`` — symmetric authenticated encryption (already quantum-acceptable)

Nothing in this module performs cryptography. It is a lookup table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SuiteKind(str, Enum):
    """What a suite does."""

    KEM = "kem"
    SIG = "sig"
    AEAD = "aead"


class SuiteStatus(str, Enum):
    """Quantum-resistance posture of a suite.

    Deliberately three honest states — never "quantum-proof"/"quantum-safe".
    """

    CLASSICAL = "classical"        # Shor- or Grover-relevant classical primitive(s)
    HYBRID_PQ = "hybrid-pq"        # classical ‖ PQ combiner (secure if *either* holds)
    PQ = "pq"                      # pure post-quantum (no classical component)
    SYMMETRIC = "symmetric"        # symmetric/hash — Grover-only, quantum-acceptable


@dataclass(frozen=True)
class CryptoSuite:
    """A single registered cipher suite.

    Attributes:
        suite_id: Stable machine-readable identifier (e.g. ``"ed25519-v1"``).
            This is the value that travels on the wire in ``sig_suite`` /
            ``kem_suite`` fields.
        kind: Whether this is a KEM, signature, or AEAD suite.
        status: Quantum-resistance posture (``classical`` today for everything
            we ship; hybrid/pq are planned, not active).
        primitives: Ordered human-readable list of underlying primitives.
        fips_refs: FIPS / RFC references backing the claim (e.g.
            ``["FIPS 203"]``). Classical suites cite the relevant RFCs.
        description: One-line human summary.
        active: Whether this suite is *actually wired into running code*.
            Phase-0 honesty gate: hybrid/PQ suites are seeded ``False`` so the
            self-report cannot overclaim. Flipped to ``True`` only when the
            corresponding Phase-1/2 implementation lands.
        replaces: Optional suite_id this is the migration target for (agility
            breadcrumb, no behavioural effect).
    """

    suite_id: str
    kind: SuiteKind
    status: SuiteStatus
    primitives: tuple[str, ...]
    fips_refs: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""
    active: bool = True
    replaces: Optional[str] = None

    @property
    def is_quantum_resistant(self) -> bool:
        """True only for hybrid-PQ, pure-PQ, or symmetric suites.

        Classical asymmetric suites are *not* quantum-resistant. This is the
        single predicate the self-report uses so no caller hand-rolls the
        (over-claimable) logic.
        """
        return self.status in (
            SuiteStatus.HYBRID_PQ,
            SuiteStatus.PQ,
            SuiteStatus.SYMMETRIC,
        )

    def to_dict(self) -> dict:
        """JSON-safe view (for the self-report)."""
        return {
            "suite_id": self.suite_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "primitives": list(self.primitives),
            "fips_refs": list(self.fips_refs),
            "description": self.description,
            "active": self.active,
            "quantum_resistant": self.is_quantum_resistant,
            "replaces": self.replaces,
        }


# ---------------------------------------------------------------------------
# The registry — seeded with current classical suites + planned hybrids.
# ---------------------------------------------------------------------------

#: Default suite id for ``SignedEnvelope.sig_suite`` (skcomms today).
DEFAULT_SIG_SUITE = "ed25519-v1"

#: Default suite id for ``GroupChat.kem_suite`` (skchat group key wrap today).
DEFAULT_KEM_SUITE = "rsa-pgp-wrap-v1"

#: Default suite id for capauth identity signing today.
DEFAULT_IDENTITY_SUITE = "ed25519-v1"

#: Default suite id for the at-rest symmetric layer today.
DEFAULT_AT_REST_SUITE = "aes256-gcm-v1"


_SUITES: dict[str, CryptoSuite] = {}


def register(suite: CryptoSuite) -> CryptoSuite:
    """Register a suite (idempotent by suite_id, last-write-wins)."""
    _SUITES[suite.suite_id] = suite
    return suite


def _seed() -> None:
    """Seed the registry. Idempotent."""
    suites = [
        # ---- Classical signature suites (LIVE today) ------------------------
        CryptoSuite(
            suite_id="ed25519-v1",
            kind=SuiteKind.SIG,
            status=SuiteStatus.CLASSICAL,
            primitives=("Ed25519", "SHA-256"),
            fips_refs=("RFC 8032", "RFC 9580"),
            description="Classical Ed25519 detached PGP signature (skcomms/capauth today).",
            active=True,
        ),
        CryptoSuite(
            suite_id="rsa4096-v1",
            kind=SuiteKind.SIG,
            status=SuiteStatus.CLASSICAL,
            primitives=("RSA-4096", "SHA-256"),
            fips_refs=("RFC 8017", "RFC 9580"),
            description="Classical RSA-4096 PGP signature (legacy capauth keys).",
            active=True,
        ),
        # ---- Classical KEM / key-wrap suites (LIVE today) -------------------
        CryptoSuite(
            suite_id="rsa-pgp-wrap-v1",
            kind=SuiteKind.KEM,
            status=SuiteStatus.CLASSICAL,
            primitives=("PGP key-wrap (Curve25519/RSA)", "AES-256 session key"),
            fips_refs=("RFC 9580",),
            description="Classical PGP key-wrap of an AES-256 group/session key "
            "(skchat group-key distribution today).",
            active=True,
        ),
        CryptoSuite(
            suite_id="x25519-pgp-wrap-v1",
            kind=SuiteKind.KEM,
            status=SuiteStatus.CLASSICAL,
            primitives=("X25519 (Curve25519) PGP key-wrap", "AES-256 session key"),
            fips_refs=("RFC 7748", "RFC 9580"),
            description="Classical X25519 PGP key-wrap of an AES-256 session key "
            "(skcomms envelope payload / DM wrap today).",
            active=True,
        ),
        # ---- Symmetric / at-rest (already quantum-acceptable) ---------------
        CryptoSuite(
            suite_id="aes256-gcm-v1",
            kind=SuiteKind.AEAD,
            status=SuiteStatus.SYMMETRIC,
            primitives=("AES-256-GCM", "HKDF-SHA256"),
            fips_refs=("FIPS 197", "SP 800-38D", "SP 800-108"),
            description="AES-256-GCM bulk cipher — Grover-only (~128-bit), "
            "quantum-acceptable. Do not migrate.",
            active=True,
        ),
        # ---- ACTIVE hybrid-PQ KEM (Phase 1 / Q1 — LIVE primitive) -----------
        # The verified hybrid KEM primitive shipped in ``skcomms.pqkem`` /
        # ``skcomms.pqkem_backend`` (X25519 + ML-KEM-768, HKDF-SHA256 combiner).
        # It is byte-for-byte interoperable with the sk_pqc Dart package
        # (cross-impl vector). ACTIVE because the primitive round-trips and
        # matches the cross-impl KAT — but NOTE it is *not yet wired* into
        # group.py / envelope.py (that is Q2/Q3). "active" here means the
        # primitive is real and usable, not that any surface has migrated.
        CryptoSuite(
            suite_id="x25519-mlkem768",
            kind=SuiteKind.KEM,
            status=SuiteStatus.HYBRID_PQ,
            primitives=(
                "X25519 (ephemeral-static DHKEM)",
                "ML-KEM-768 (FIPS 203, liboqs)",
                "HKDF-SHA256 concat-KDF combiner",
            ),
            fips_refs=("FIPS 203", "RFC 7748", "RFC 5869"),
            description="LIVE hybrid X25519 || ML-KEM-768 key-encapsulation "
            "primitive (skcomms.pqkem). Secret unless BOTH primitives break. "
            "Cross-impl interoperable with sk_pqc (Dart). Verified primitive "
            "only — NOT yet wired into envelope/group (Q2/Q3).",
            active=True,
            replaces="x25519-pgp-wrap-v1",
        ),
        # ---- Planned hybrid-PQ suites (NOT active — Phase 1/2 targets) ------
        CryptoSuite(
            suite_id="x25519-mlkem768-v2",
            kind=SuiteKind.KEM,
            status=SuiteStatus.HYBRID_PQ,
            primitives=(
                "X25519",
                "ML-KEM-768",
                "HKDF-SHA256 concat-KDF combiner",
            ),
            fips_refs=("FIPS 203", "RFC 7748"),
            description="PLANNED (Phase 1): hybrid X25519 ‖ ML-KEM-768 key "
            "encapsulation. Secret unless BOTH primitives break. NOT YET ACTIVE.",
            active=False,
            replaces="rsa-pgp-wrap-v1",
        ),
        # ---- ACTIVE hybrid-PQ signature (Phase 2 / Q7 — LIVE primitive) -----
        # The verified hybrid signature primitive shipped in ``skcomms.pqsig``
        # (Ed25519 + ML-DSA-65 composite, BOTH legs required). ACTIVE because the
        # primitive round-trips + matches the FIPS 204 KAT and is wired into
        # ``skcomms.signing.HybridEnvelopeSigner`` (opt-in, negotiated). "active"
        # means the primitive is real + usable; classical ``ed25519-v1`` remains
        # the DEFAULT for unmigrated/old envelopes (either-or verify).
        CryptoSuite(
            suite_id="mldsa65-ed25519-v2",
            kind=SuiteKind.SIG,
            status=SuiteStatus.HYBRID_PQ,
            primitives=(
                "Ed25519 (RFC 8032)",
                "ML-DSA-65 (FIPS 204, liboqs)",
                "length-prefixed SKHS composite (both legs required)",
            ),
            fips_refs=("FIPS 204", "RFC 8032"),
            description="LIVE hybrid Ed25519 + ML-DSA-65 composite signature "
            "(skcomms.pqsig). Valid iff BOTH legs verify; unforgeable while "
            "EITHER scheme holds. Opt-in/negotiated on SignedEnvelope.sig_suite "
            "+ capauth challenge; classical ed25519-v1 stays the default for old "
            "peers (either-or verify). NOTE: the ROOT PGP identity key is NOT "
            "migrated (Phase-2 Sequoia, gated) — this is the per-message / "
            "challenge signing layer only.",
            active=True,
            replaces="ed25519-v1",
        ),
        CryptoSuite(
            suite_id="slh-dsa-shake-256-v2",
            kind=SuiteKind.SIG,
            status=SuiteStatus.PQ,
            primitives=("SLH-DSA-SHAKE-256",),
            fips_refs=("FIPS 205",),
            description="PLANNED (Phase 2): hash-based SLH-DSA root-of-trust "
            "signer (sovereign root only). NOT YET ACTIVE.",
            active=False,
        ),
    ]
    for s in suites:
        register(s)


_seed()


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def get_suite(suite_id: str) -> Optional[CryptoSuite]:
    """Return the registered suite for ``suite_id`` (or ``None`` if unknown)."""
    return _SUITES.get(suite_id)


def all_suites() -> list[CryptoSuite]:
    """Return all registered suites (stable order: classical first)."""
    return sorted(
        _SUITES.values(),
        key=lambda s: (not s.active, s.status.value, s.suite_id),
    )


def active_suites() -> list[CryptoSuite]:
    """Return only suites wired into running code (all classical today)."""
    return [s for s in all_suites() if s.active]


def suite_status(suite_id: str) -> SuiteStatus:
    """Return the status of a suite id, defaulting to CLASSICAL if unknown.

    Unknown ids are treated as classical for honesty: an unrecognized suite
    must never be reported as quantum-resistant.
    """
    suite = get_suite(suite_id)
    return suite.status if suite else SuiteStatus.CLASSICAL


def is_quantum_resistant(suite_id: str) -> bool:
    """Whether the given suite id is quantum-resistant (False if unknown)."""
    suite = get_suite(suite_id)
    return bool(suite and suite.is_quantum_resistant)
