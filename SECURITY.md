# Security Policy — skcomms

`skcomms` is the **sovereign realm-aware comms protocol**: it defines the signed
Envelope v1, verifies inter-agent signatures, wraps message payloads, tracks
sender-bound ACKs, and serves the SKFed S2S federation surface. It is a
**confidentiality + authenticity** surface, so it carries the honest-claim rules and a
hard quantum-resistance requirement. Read the **honest-claim posture** and the **threat
model** before relying on it or reporting an issue.

> ⚠️ **Experimental · pre-1.0 · NOT independently security-audited.** No third-party
> security audit, fuzzing, or formal review has been performed. skcomms binds vetted
> libraries (PGPy / `cryptography` / liboqs-`oqs`) behind suite abstractions; the
> original code is the envelope schema, the signing/verify wiring, the ACK/replay layer,
> the transport router, and the federation service. A passing test suite proves interop
> and behavior — **not** the absence of side-channels or protocol flaws. **Review it
> yourself before production use.**

---

## Honest claims (what skcomms does and does NOT promise)

Per the sk-standards
[CRYPTOGRAPHY_STANDARD](https://github.com/smilinTux/sk-standards/blob/main/standards/CRYPTOGRAPHY_STANDARD.md),
every claim is scoped to **surface + FIPS/RFC number + hybrid-vs-classical**.

- ✅ **Authentic, tamper-evident messages.** Every Envelope v1 carries a detached PGP
  signature over stable `canonical_bytes()`, with a SHA-256 tamper pre-check; verify
  order is signature → freshness → replay.
- ✅ **ACK sender-binding.** An ACK whose `sender` is not the intended recipient of the
  original envelope is rejected as third-party forgery (`ack.py`).
- ✅ **Post-quantum payload wrap on the negotiated surface (🟢 when both peers support
  it).** `crypto.py:EnvelopeCrypto` negotiates **hybrid X25519 + ML-KEM-768** (FIPS 203)
  by default when the peer bundle supports it, combining as
  `K = HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` — concatenate-then-KDF, never XOR, never
  pure-PQ. Harvest-Now-Decrypt-Later is neutralised **only** on that hybrid-negotiated
  leg.
- ✅ **Crypto-agile + downgrade-detectable.** Machine-readable `sig_suite`/`kem_suite`
  ids + the `skcomms.crypto_suites` registry + a single negotiation gate; the negotiated
  suite id is bound into the result so a stripped hybrid leg no longer reports hybrid.
- ✅ **Quantum-acceptable symmetric floor.** AES-256-GCM bulk + SHA-256 integrity are
  Grover-only (≥128-bit worst case). **Do not "fix" them** — AES-256 is not broken by
  quantum.
- ❌ **Signatures are classical by default.** The default `sig_suite` is `ed25519-v1`;
  the `mldsa65-ed25519-v2` hybrid suite (FIPS 204) is wired but not the default. So
  signatures are **classically forgeable post-quantum** (future-forgery, deferrable — not
  HNDL). Do not describe the signature surface as quantum-resistant yet.
- ❌ **Classical-only peers get a classical wrap.** If a peer does not support hybrid,
  the payload wrap negotiates to classical PGP (Curve25519/RSA over an AES-256 session
  key) and is **HNDL-vulnerable**. The hybrid claim is per-conversation, not blanket.
- ❌ **Never** "quantum-proof," "quantum-safe," "unbreakable," "CNSA 2.0 compliant,"
  "FIPS 206," or "Falcon." Say **"quantum-resistant" / "post-quantum"** at the **-768
  hybrid tier** and cite the FIPS number + the surface.
- ❌ **Not the identity root-of-trust.** Key custody, FQID resolution, and the signing
  key come from [capauth](https://github.com/smilinTux/capauth); skcomms consumes them.
- ❌ **Federation endpoints are public-by-design, not access-controlled by transport.**
  Authenticity is the envelope signature, not the socket. The `:9384` API and `:8765`
  daemon-proxy must stay on loopback / tailnet; only Funnel `:443` is public (see
  [SOP.md §5](SOP.md)).

---

## Threat model

### In scope

- **Envelope forgery / tampering.** A modified body or a signature from a key other than
  the sender's pinned (TOFU) fingerprint fails `EnvelopeVerifier`.
- **ACK forgery.** A third party ACKing on behalf of the real recipient is rejected by
  sender-binding.
- **Replay / stale-envelope injection.** Freshness + replay checks after signature.
- **Downgrade of the hybrid KEM.** The negotiated suite id is bound into the result and
  self-reported, so a stripped hybrid leg is detectable.
- **False crypto labels.** A classical surface (default signatures, classical-peer wrap)
  described as "quantum-resistant" is a defect.

### Out of scope (you MUST handle these elsewhere)

- **Harvest-Now-Decrypt-Later on a classical-only leg.** If a peer cannot negotiate
  hybrid, that conversation's payload wrap is classical and HNDL-exposed — upgrade the
  peer.
- **Post-quantum signatures by default.** Until the hybrid `sig_suite` becomes the
  default, envelope signatures are classical (deferrable future-forgery risk).
- **Key custody / passphrase storage.** Owned by capauth / gpg-agent / skvault.
- **Transport confidentiality of non-federation legs.** Tailnet, WebRTC media, and the
  CoT/TAK stream are the operator's network responsibility (tailnet + firewall).
- **Side channels in bound libraries.** Constant-time / correctness come from PGPy,
  `cryptography`, and liboqs; skcomms does not re-audit them.

### Trust roots / dependencies

| Surface | Library | Assurance basis |
|---|---|---|
| Envelope sign / verify (default) | PGPy | RFC 4880 / 9580 (Ed25519) |
| Hybrid signature suite (wired) | PGPy + liboqs (`oqs`) | FIPS 204 (ML-DSA-65) + RFC 8032 (Ed25519) |
| Payload wrap — hybrid KEM (negotiated) | `cryptography` (X25519, HKDF) + liboqs (`oqs`) | FIPS 203 (ML-KEM-768) + RFC 7748 / 5869 |
| Payload wrap — classical fallback | PGPy | RFC 4880 (Curve25519/RSA over AES-256 session key) |
| Bulk cipher / integrity | AES-256-GCM, SHA-256 | quantum-acceptable (Grover-only) |

The hybrid key-wrap combines as `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` —
concatenate-then-KDF, **never XOR, never pure-PQ**. skcomms **binds** these libraries; it
does **not** hand-roll OpenPGP, lattice, or curve primitives.

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ current |
| < 0.1.6 | ❌ pre-release / best-effort |

Until 1.0, only the latest published `0.x` line receives security fixes
(per [VERSION_LIFECYCLE](https://github.com/smilinTux/sk-standards/blob/main/standards/VERSION_LIFECYCLE.md):
Active always; older = critical only).

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

- **Primary:** GitHub **private vulnerability reporting** — "Report a vulnerability" on
  the Security tab of [`smilinTux/skcomms`](https://github.com/smilinTux/skcomms).
- **Secondary (out-of-band):** contact the maintainers (smilinTux / SKWorld) via the
  address on the GitHub org; encrypt sensitive reports to the maintainer's sovereign
  capauth/`sk_pgp` PGP key (fingerprint published on the org profile).

Please include: affected version, Python version, whether liboqs/`oqs` is present, the
negotiated suite in play, and a minimal reproduction. We aim to **acknowledge within 72
hours** and to ship a fix or mitigation within 90 days, coordinating a disclosure date.
**Safe harbour:** good-faith research under coordinated disclosure will not be pursued.
Credit is given unless you ask otherwise.

### What we especially want to hear about

- An envelope that verifies against a signature the sender did **not** produce (forgery /
  canonicalization ambiguity / TOFU rebinding).
- An ACK accepted from a `sender` other than the intended recipient (sender-binding
  bypass).
- A replay or stale envelope accepted past the freshness/replay checks.
- A hybrid-KEM **downgrade** that is *not* reflected in the self-reported negotiated
  suite (silent downgrade).
- A crypto-label overclaim — a classical surface (default signatures, classical-peer
  wrap) described as "quantum-resistant."
- Any skcomms socket reachable on a public interface (should be loopback / tailnet;
  Funnel `:443` only).

---

**License:** GPL-3.0-or-later. **Standards:** RFC 4880 / 9580 (OpenPGP); RFC 7748 / 8032
(X25519 / Ed25519); RFC 5869 (HKDF); FIPS 203 / 204 (ML-KEM / ML-DSA); ISO/IEC 29147 &
30111 (disclosure); CVSS v4.0; NIST CSWP 39 (crypto-agility).
