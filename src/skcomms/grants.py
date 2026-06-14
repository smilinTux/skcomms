"""Cross-operator collection consent tokens (T10, ``a68c54ce``).

skcomms is the **producer** of recall-consent grants; skmemory T9 is the
**consumer**. A consent token grants a remote agent read access to one of this
operator's memory collections across an operator/realm boundary. The token is
PGP-signed by the granter so the consumer can verify authenticity without a
live channel.

The shared on-disk contract (read by skmemory T9) lives at
``${SKCOMMS_HOME:-~/.skcapstone/skcomms}/recall_collections_consent.json``::

    {
      "tokens": [
        {
          "collection":  "<operator>.<realm>/<name>",
          "granted_to":  "<fqid>",          # the reader allowed access
          "granted_by":  "<fqid>",          # the granter (== self at mint time)
          "expires":     "<iso8601>",
          "signature":   "<pgp armor>"      # detached sig over canonical_bytes
        }
      ]
    }

A token grants read when: the collection matches, ``granted_to`` == the reader
fqid, it is not expired, and the signature verifies against the granter's key.

Public API:
    ConsentToken                       -- the token model + canonical_bytes()
    mint_grant(collection, to, expires) -> dict   -- build + sign a token
    verify_grant(token, pubkey=None)   -> GrantVerification
    accept_grant(token, pubkey=None)   -> dict    -- verify + merge into file
    list_grants()                      -> list[dict]

CROSS-REPO NOTE: skmemory T9 left ``_verify_consent_signature()`` stubbed to
return ``True``. Wiring it to call :func:`verify_grant` here (passing the
granter's pubkey from the peer/TOFU store) is the remaining follow-up; it is
intentionally NOT done from this repo. See ``verify_grant`` for the entry point.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .home import skcomms_home
from .identity import resolve_self_identity
from .signing import EnvelopeSigner
from .tofu import TofuStatus, verify_fingerprint

logger = logging.getLogger("skcomms.grants")

_CONSENT_NAME = "recall_collections_consent.json"

# Fields that make up a token's stable identity (everything but the signature).
_TOKEN_FIELDS = ("collection", "granted_to", "granted_by", "expires")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Token model
# ---------------------------------------------------------------------------


class ConsentToken(BaseModel):
    """A signed cross-operator collection read-consent grant.

    Attributes:
        collection: ``<operator>.<realm>/<name>`` collection identifier.
        granted_to: FQID of the reader being granted access.
        granted_by: FQID of the granter (the signer; ``self`` at mint time).
        expires: ISO-8601 expiry timestamp.
        signature: ASCII-armored PGP detached signature over
            :meth:`canonical_bytes`. Excluded from the canonical bytes.
    """

    collection: str
    granted_to: str
    granted_by: str
    expires: str
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Stable bytes to sign — sorted compact JSON, signature excluded.

        Deterministic regardless of field-construction order. The signature is
        never part of what it signs, so it is omitted here.
        """
        data = {k: getattr(self, k) for k in _TOKEN_FIELDS}
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def to_t9_dict(self) -> dict:
        """Serialize to the exact dict shape skmemory T9 reads."""
        return {
            "collection": self.collection,
            "granted_to": self.granted_to,
            "granted_by": self.granted_by,
            "expires": self.expires,
            "signature": self.signature,
        }

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Whether the token's expiry is in the past."""
        now = now or _utc_now()
        try:
            exp = datetime.fromisoformat(self.expires)
        except ValueError:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= now


@dataclass
class GrantVerification:
    """Outcome of verifying a consent token.

    Attributes:
        valid: Whether the token is authentic and currently in force.
        reason: Human-readable explanation.
        fingerprint: The granter key fingerprint (if a key was supplied).
    """

    valid: bool
    reason: str = ""
    fingerprint: Optional[str] = None


# ---------------------------------------------------------------------------
# expiry parsing
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(r"^\s*(\d+)\s*d\s*$", re.IGNORECASE)


def _resolve_expires(expires: str) -> str:
    """Resolve an *expires* spec to an ISO-8601 timestamp.

    Accepts either a duration in days (``"30d"``) relative to now, or an
    already-iso8601 timestamp (passed through, normalized to include a
    timezone).

    Args:
        expires: ``"<N>d"`` or an ISO-8601 datetime string.

    Returns:
        An ISO-8601 timestamp string with timezone offset.

    Raises:
        ValueError: If *expires* is neither a ``Nd`` duration nor parseable
            as ISO-8601.
    """
    m = _DURATION_RE.match(expires)
    if m:
        return (_utc_now() + timedelta(days=int(m.group(1)))).isoformat()
    try:
        dt = datetime.fromisoformat(expires)
    except ValueError as exc:
        raise ValueError(
            f"invalid --expires {expires!r}: use '<N>d' (e.g. 30d) or an ISO-8601 date"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# signer / key loading (monkeypatched in tests)
# ---------------------------------------------------------------------------


def _agent_identity_dir(agent: str) -> Path:
    """Path to the agent's CapAuth identity dir.

    Canonical: ``~/.skcapstone/agents/<agent>/capauth/identity`` (mirrors
    :func:`skcomms.mailbox._agent_identity_dir`); falls back to the legacy
    bare ``identity`` dir. The bare-only path missed the real per-agent key
    and fell through to the operator key under ``~/.capauth``.
    """
    base = Path.home() / ".skcapstone" / "agents" / agent
    capauth_dir = base / "capauth" / "identity"
    if capauth_dir.exists():
        return capauth_dir
    return base / "identity"


def _load_signer(agent: str) -> EnvelopeSigner:
    """Load the granter's signing key from its CapAuth profile.

    Mirrors :func:`skcomms.mailbox._load_signer`. Monkeypatched in tests.

    Raises:
        FileNotFoundError: If no private key can be located.
    """
    candidates = [
        _agent_identity_dir(agent) / "private.asc",
        _agent_identity_dir(agent) / "agent.private.asc",
        Path.home() / ".capauth" / "identity" / "private.asc",
    ]
    for path in candidates:
        if path.exists():
            passphrase = os.environ.get("SKCOMMS_KEY_PASSPHRASE", "")
            return EnvelopeSigner(path.read_text(encoding="utf-8"), passphrase)
    raise FileNotFoundError(
        f"no PGP private key for {agent!r}; looked in {[str(c) for c in candidates]}"
    )


# ---------------------------------------------------------------------------
# mint
# ---------------------------------------------------------------------------


def mint_grant(collection: str, to_fqid: str, expires: str) -> dict:
    """Build and sign a consent token granting *to_fqid* read on *collection*.

    The granter (``granted_by``) is the resolved self identity; the token's
    :meth:`ConsentToken.canonical_bytes` is signed with the granter's PGP key
    via :class:`~skcomms.signing.EnvelopeSigner`.

    Args:
        collection: ``<operator>.<realm>/<name>`` collection identifier.
        to_fqid: FQID of the reader to grant access to.
        expires: ``"<N>d"`` duration or an ISO-8601 expiry timestamp.

    Returns:
        The signed token as a plain dict (T9 schema, see
        :meth:`ConsentToken.to_t9_dict`).

    Raises:
        ValueError: If the self fqid cannot be resolved or *expires* is bad.
    """
    ident = resolve_self_identity()
    granted_by = ident.get("fqid")
    if not granted_by:
        raise ValueError("cannot resolve granter fqid (cluster.json missing?)")

    token = ConsentToken(
        collection=collection,
        granted_to=to_fqid,
        granted_by=granted_by,
        expires=_resolve_expires(expires),
    )

    agent = ident.get("agent") or granted_by.split("@", 1)[0]
    signer = _load_signer(agent)
    token.signature = _detached_sig(signer, token.canonical_bytes())

    logger.debug("minted grant %s -> %s on %s", granted_by, to_fqid, collection)
    return token.to_t9_dict()


def _detached_sig(signer: EnvelopeSigner, canonical: bytes) -> str:
    """Produce an armored PGP signature over *canonical* via *signer*'s key."""
    import pgpy

    key = signer._key  # reuse the loaded key (same as EnvelopeSigner internals)
    pgp_message = pgpy.PGPMessage.new(canonical, cleartext=False)
    ctx = (
        key.unlock(signer._passphrase)
        if key.is_protected
        else contextlib.nullcontext()
    )
    with ctx:
        sig = key.sign(pgp_message)
    return str(sig)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def verify_grant(token: dict, pubkey: Optional[str] = None) -> GrantVerification:
    """Verify a consent token's signature, granter trust, and expiry.

    Checks, in order:

    1. The PGP signature over :meth:`ConsentToken.canonical_bytes` is valid
       against the granter's public key.
    2. The granter's key fingerprint is TOFU-trusted for ``granted_by`` via
       :func:`skcomms.tofu.verify_fingerprint` — a CONFLICT (a different key
       than previously seen for that fqid) fails verification.
    3. The token is not expired.

    Args:
        token: The token dict (T9 schema).
        pubkey: ASCII-armored granter public key. When ``None``, the key is
            resolved from the peers/TOFU store via :func:`_resolve_granter_pubkey`.

    Returns:
        A :class:`GrantVerification`.
    """
    tok = _coerce(token)

    armor = pubkey or _resolve_granter_pubkey(tok.granted_by)
    if not armor:
        return GrantVerification(
            valid=False, reason=f"no public key for granter {tok.granted_by}"
        )

    if not tok.signature:
        return GrantVerification(valid=False, reason="token has no signature")

    try:
        import pgpy

        pub_key, _ = pgpy.PGPKey.from_blob(armor)
        sig = pgpy.PGPSignature.from_blob(tok.signature)
        pgp_message = pgpy.PGPMessage.new(tok.canonical_bytes(), cleartext=False)
        pgp_message |= sig
        sig_ok = bool(pub_key.verify(pgp_message))
    except Exception as exc:  # malformed sig/key
        logger.warning("grant verify error: %s", exc)
        return GrantVerification(valid=False, reason=f"signature error: {exc}")

    if not sig_ok:
        return GrantVerification(valid=False, reason="invalid PGP signature")

    fingerprint = str(pub_key.fingerprint).replace(" ", "")

    # TOFU-trust the granter's key (T3). A CONFLICT means a *different* key has
    # been seen for this fqid before — reject rather than silently accept.
    tofu = verify_fingerprint(tok.granted_by, fingerprint, pubkey=armor)
    if tofu.status == TofuStatus.CONFLICT:
        return GrantVerification(
            valid=False,
            reason=(
                f"granter key fingerprint conflict for {tok.granted_by} "
                f"(stored {tofu.stored_fingerprint}, got {fingerprint})"
            ),
            fingerprint=fingerprint,
        )

    if tok.is_expired():
        return GrantVerification(
            valid=False, reason="grant expired", fingerprint=fingerprint
        )

    return GrantVerification(valid=True, reason="grant valid", fingerprint=fingerprint)


def _resolve_granter_pubkey(granted_by: str) -> Optional[str]:
    """Resolve the granter's pubkey from the TOFU store or a peers file.

    Prefers a pubkey cached in the TOFU store (T3); falls back to a
    ``<home>/peers/<fqid>.asc`` file. Returns ``None`` if neither is found.
    """
    from .tofu import _load_store

    entry = _load_store().get(granted_by)
    if entry and entry.get("pubkey"):
        return entry["pubkey"]
    peer_asc = skcomms_home() / "peers" / f"{granted_by}.asc"
    if peer_asc.exists():
        return peer_asc.read_text(encoding="utf-8")
    return None


def _coerce(token) -> ConsentToken:
    """Coerce a dict or ConsentToken into a ConsentToken."""
    if isinstance(token, ConsentToken):
        return token
    return ConsentToken.model_validate(token)


# ---------------------------------------------------------------------------
# consent file (T9 contract) — accept + list
# ---------------------------------------------------------------------------


def consent_path() -> Path:
    """Path to the recall consent file (read by skmemory T9)."""
    return skcomms_home() / _CONSENT_NAME


def _load_consent() -> dict:
    """Load the consent file, returning the ``{"tokens": [...]}`` structure."""
    path = consent_path()
    if not path.exists():
        return {"tokens": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("consent file unreadable (%s): %s", path, exc)
        return {"tokens": []}
    if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
        return {"tokens": []}
    return data


def _save_consent(data: dict) -> None:
    """Persist the consent file atomically under SKCOMMS_HOME."""
    path = consent_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def _dedup_key(t: dict) -> tuple:
    """Identity of a held grant for idempotent merge (collection+to+by)."""
    return (t.get("collection"), t.get("granted_to"), t.get("granted_by"))


def accept_grant(token: dict, pubkey: Optional[str] = None) -> dict:
    """Verify a token, then merge it into the consent file (idempotent).

    On success the token lands in
    ``${SKCOMMS_HOME:-~/.skcapstone/skcomms}/recall_collections_consent.json`` in the
    EXACT schema skmemory T9 reads. Re-accepting the same grant (same
    collection + granted_to + granted_by) replaces the prior entry rather than
    appending a duplicate.

    Args:
        token: The token dict (T9 schema).
        pubkey: ASCII-armored granter public key (resolved if omitted).

    Returns:
        The accepted token as a T9-schema dict.

    Raises:
        ValueError: If verification fails (the consent file is not modified).
    """
    tok = _coerce(token)
    result = verify_grant(tok.to_t9_dict(), pubkey=pubkey)
    if not result.valid:
        raise ValueError(f"refusing to accept invalid grant: {result.reason}")

    entry = tok.to_t9_dict()
    data = _load_consent()
    tokens = [t for t in data["tokens"] if _dedup_key(t) != _dedup_key(entry)]
    tokens.append(entry)
    data["tokens"] = tokens
    _save_consent(data)
    logger.debug("accepted grant on %s for %s", tok.collection, tok.granted_to)
    return entry


def list_grants() -> list[dict]:
    """List the consent tokens currently held in the consent file."""
    return list(_load_consent()["tokens"])
