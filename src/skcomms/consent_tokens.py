"""Per-contact capability tokens — the delivery credential (gate 4).

The public directory entry is only ever a *knock* endpoint (gate 5,
:mod:`skcomms.consent`); a **token** is what makes ``known contact``
cryptographically enforced. On accept, the recipient issues a per-contact
capability token::

    token = HKDF-SHA256(per_agent_secret_seed, info=contact_fqid)

returned as hex. The contact attaches it to every later message and the inbox
recomputes + constant-time-compares it. This is the answer to the design's open
problem (A) — token issue/rotate/revoke in a *public, federated* directory:

* **Per-contact distinct tokens** (not Signal's single profile-key token). Each
  accepted contact's token is derived independently, so a token issued for one
  contact never authenticates another.
* **Independent revocation.** Blocking ONE contact = drop THAT one fqid from the
  valid set — no re-sharing a single secret with everyone (Signal's weakness).

The per-agent secret seed is generated **once** and persisted under
``skcomms_home()/consent/<agent>/token_seed.bin`` (next to the gate-5
:mod:`skcomms.consent` SQLite stores), so a fresh :class:`TokenStore` over the
same home re-derives identical tokens. Per-agent seeds are independent, so one
agent's tokens are meaningless to another.

Design: ``docs/skfed-consent-design.md`` (FINAL spec gate 4 + problem (A)).
This is purely additive — it shares the ``consent/<agent>/`` directory with
:mod:`skcomms.consent` but edits nothing there. The gate composes the two: on
``RequestQueue.accept_request`` (promote to known) the node also calls
:meth:`TokenStore.issue`; on block it calls :meth:`TokenStore.revoke`.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import time
from pathlib import Path

from .home import skcomms_home

#: Length of the per-agent secret seed (256-bit).
_SEED_BYTES = 32
#: Length of the derived capability token (256-bit → 64 hex chars).
_TOKEN_BYTES = 32
#: Domain-separation label folded into the HKDF info (versioned for future rotation).
_INFO_PREFIX = b"skcomms/consent-token/v1:"


def _consent_dir(agent: str) -> Path:
    """Resolve (and create) the per-agent consent directory.

    Mirrors :func:`skcomms.consent._consent_dir` so the token seed lives beside
    the gate-5 contact/request SQLite stores under ``consent/<agent>/``.
    """
    d = skcomms_home() / "consent" / agent
    d.mkdir(parents=True, exist_ok=True)
    return d


def _hkdf_sha256(seed: bytes, info: bytes, length: int = _TOKEN_BYTES) -> bytes:
    """HKDF-SHA256 (RFC 5869) extract-then-expand, stdlib-only.

    The per-agent ``seed`` is the input keying material; ``info`` binds the
    derivation to a specific contact (domain-separated by :data:`_INFO_PREFIX`).
    Implemented with :mod:`hmac` to avoid a hard third-party crypto dependency
    in the consent gate's hot path.
    """
    # Extract: a fixed all-zero salt is RFC-compliant; the seed itself is the
    # high-entropy secret, so an explicit salt adds nothing here.
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, seed, hashlib.sha256).digest()
    # Expand
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


class TokenStore:
    """Per-agent issuer/verifier of per-contact capability tokens.

    Args:
        agent: Short agent name (e.g. ``"lumina"``). Each agent gets an
            isolated seed + valid-set under its own ``consent/<agent>/`` dir.
    """

    def __init__(self, agent: str) -> None:
        self.agent = agent
        self._dir = _consent_dir(agent)
        self._seed_path = self._dir / "token_seed.bin"
        self._db = self._dir / "tokens.db"
        self._seed = self._load_or_create_seed()
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS tokens "
                "(fqid TEXT PRIMARY KEY, issued_at REAL NOT NULL)"
            )

    # -- seed -------------------------------------------------------------

    def _load_or_create_seed(self) -> bytes:
        """Load the persisted per-agent seed, generating it ONCE if absent.

        The seed must never rotate on its own — every previously issued token
        would silently break — so creation is one-time and read-back is exact.
        """
        if self._seed_path.exists():
            data = self._seed_path.read_bytes()
            if len(data) >= _SEED_BYTES:
                return data
        seed = os.urandom(_SEED_BYTES)
        # Write atomically and lock down perms (the seed is the agent's secret).
        tmp = self._seed_path.with_suffix(".bin.tmp")
        tmp.write_bytes(seed)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._seed_path)
        return seed

    # -- store ------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db))

    def _derive(self, contact_fqid: str) -> str:
        """Deterministically derive the hex token for *contact_fqid*."""
        info = _INFO_PREFIX + contact_fqid.encode("utf-8")
        return _hkdf_sha256(self._seed, info).hex()

    def _is_valid_contact(self, contact_fqid: str) -> bool:
        with self._conn() as c:
            row = c.execute(
                "SELECT 1 FROM tokens WHERE fqid=?", (contact_fqid,)
            ).fetchone()
        return row is not None

    # -- public API -------------------------------------------------------

    def issue(self, contact_fqid: str) -> str:
        """Issue (or re-issue) the capability token for an accepted contact.

        Records *contact_fqid* in the valid set and returns its deterministic
        hex token. Idempotent: re-issuing for the same contact (same seed)
        returns the identical token, so an accept can be retried safely.

        Args:
            contact_fqid: The accepted contact's FQID (``a@o.r``).

        Returns:
            str: The hex capability token to hand back in the accept.
        """
        with self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO tokens (fqid, issued_at) VALUES (?,?)",
                (contact_fqid, time.time()),
            )
        return self._derive(contact_fqid)

    def verify(self, contact_fqid: str, token: str) -> bool:
        """Constant-time-check a presented *token* for *contact_fqid*.

        Returns ``True`` only if the contact is currently in the valid set
        (never revoked) AND the presented token matches the seed-derived token.
        Fails closed on any malformed input.

        Args:
            contact_fqid: The claimed sender FQID.
            token: The hex token the sender attached.

        Returns:
            bool: Whether delivery is token-authorized for this contact.
        """
        if not isinstance(token, str) or not token:
            return False
        if not self._is_valid_contact(contact_fqid):
            return False
        expected = self._derive(contact_fqid)
        # Constant-time compare over the hex strings (equal length here).
        return hmac.compare_digest(expected, token)

    def revoke(self, contact_fqid: str) -> bool:
        """Revoke *contact_fqid*'s token — drop it from the valid set.

        Blocking one contact removes only that fqid; every other contact's
        token keeps verifying (the explicit fix vs Signal's single token).

        Args:
            contact_fqid: The contact to revoke.

        Returns:
            bool: ``True`` if a token was present and removed.
        """
        with self._conn() as c:
            cur = c.execute("DELETE FROM tokens WHERE fqid=?", (contact_fqid,))
            return cur.rowcount > 0

    def is_issued(self, contact_fqid: str) -> bool:
        """Whether *contact_fqid* currently holds a valid (un-revoked) token."""
        return self._is_valid_contact(contact_fqid)

    def list_issued(self) -> list[str]:
        """All contact FQIDs currently in the valid set."""
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT fqid FROM tokens ORDER BY fqid")]
