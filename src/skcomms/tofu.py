"""PGP fingerprint TOFU trust store (T3, ``bcf32eea``).

Canonical agent identity in skcomms is the **PGP fingerprint** — the fqid
(``<agent>@<operator>.<realm>``) is just a human-readable handle. This module
implements Trust-On-First-Use (SSH host-key style): the first fingerprint seen
for an fqid is recorded; later contacts must match it. A *different*
fingerprint for a known fqid is a CONFLICT and is rejected — never silently
overwritten.

Store layout (``${SKCOMMS_HOME:-~/.skcapstone/skcomms}/known_fingerprints.json``)::

    {
      "lumina@chef.skworld": {
        "fingerprint": "AAAA...5555",
        "first_seen": "2026-06-10T12:00:00+00:00",
        "pubkey": "-----BEGIN PGP PUBLIC KEY BLOCK----- ..."   # optional
      },
      ...
    }

Public API:
    record_fingerprint(fqid, fingerprint, pubkey=None)  -- TOFU first-contact record
    fingerprint_for(fqid) -> str | None                 -- lookup
    verify_fingerprint(fqid, fingerprint) -> TofuResult  -- TRUST_NEW/MATCH/CONFLICT
    repin_fingerprint(fqid, fingerprint, ...)            -- EXPLICIT operator re-pin
        after a verified key rotation (coord 7d5344f2); never called from any
        receive path, records previous_fingerprint + repinned_at for audit
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from .home import skcomms_home

logger = logging.getLogger("skcomms.tofu")

_STORE_NAME = "known_fingerprints.json"


def _utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with offset."""
    return datetime.now(timezone.utc).isoformat()


def _normalize(fingerprint: str) -> str:
    """Normalize a fingerprint for comparison (strip spaces, upper-case)."""
    return fingerprint.replace(" ", "").upper()


class TofuStatus(str, Enum):
    """Outcome of a :func:`verify_fingerprint` call.

    Attributes:
        TRUST_NEW: First sight of this fqid — fingerprint recorded, trusted.
        TRUST_MATCH: Presented fingerprint matches the stored one — trusted.
        CONFLICT: Presented fingerprint differs from the stored one — rejected
            (the stored value is left untouched).
    """

    TRUST_NEW = "trust_new"
    TRUST_MATCH = "trust_match"
    CONFLICT = "conflict"


@dataclass
class TofuResult:
    """Result of verifying a fingerprint against the TOFU store.

    Attributes:
        status: The :class:`TofuStatus` outcome.
        fqid: The fqid that was verified.
        presented_fingerprint: The fingerprint presented for verification.
        stored_fingerprint: The previously-stored fingerprint (``None`` on
            first sight).
    """

    status: TofuStatus
    fqid: str
    presented_fingerprint: str
    stored_fingerprint: Optional[str] = None

    @property
    def trusted(self) -> bool:
        """Whether this result should be treated as trusted.

        ``True`` for TRUST_NEW and TRUST_MATCH; ``False`` for CONFLICT.
        """
        return self.status in (TofuStatus.TRUST_NEW, TofuStatus.TRUST_MATCH)


def store_path() -> Path:
    """Path to the ``known_fingerprints.json`` store under SKCOMMS_HOME."""
    return skcomms_home() / _STORE_NAME


def _load_store() -> dict:
    """Load the known-fingerprints store (``{}`` if absent or corrupt)."""
    path = store_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("tofu store unreadable (%s): %s", path, exc)
        return {}


def _save_store(store: dict) -> None:
    """Persist the store atomically under SKCOMMS_HOME."""
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def record_fingerprint(
    fqid: str, fingerprint: str, pubkey: Optional[str] = None
) -> dict:
    """Record a fingerprint for *fqid* (TOFU first-contact).

    Writes (or overwrites) the entry for *fqid*. This is the low-level setter;
    callers wanting TOFU-safe semantics (reject conflicts) should use
    :func:`verify_fingerprint`, which only records on first sight.

    Args:
        fqid: The peer FQID handle.
        fingerprint: The PGP fingerprint (the canonical identity).
        pubkey: Optional ASCII-armored public key to cache alongside.

    Returns:
        The stored entry dict (``fingerprint``, ``first_seen``, ``pubkey?``).
    """
    store = _load_store()
    entry: dict = {
        "fingerprint": _normalize(fingerprint),
        "first_seen": _utc_now_iso(),
    }
    if pubkey is not None:
        entry["pubkey"] = pubkey
    store[fqid] = entry
    _save_store(store)
    logger.debug("recorded fingerprint for %s: %s", fqid, entry["fingerprint"])
    return entry


def repin_fingerprint(
    fqid: str,
    fingerprint: str,
    pubkey: Optional[str] = None,
    reason: str = "",
) -> dict:
    """EXPLICITLY re-pin *fqid* to a new fingerprint after a key rotation.

    This is the ONLY sanctioned way to replace a stored fingerprint. It is
    an operator action (``skcomms identity repin``), never called from any
    receive/verify path, so the TOFU CONFLICT semantics of
    :func:`verify_fingerprint` stay fail-closed. The previous fingerprint
    and the re-pin timestamp are recorded for audit.

    Use ONLY after verifying the new fingerprint out of band (voice, video,
    or an existing trusted channel). Runbook: skcomms SOP.md section 11.

    Args:
        fqid: The peer FQID handle being re-pinned.
        fingerprint: The NEW fingerprint (verified out of band).
        pubkey: Optional new ASCII-armored public key to cache.
        reason: Optional operator note stored with the entry.

    Returns:
        The stored entry dict, including ``previous_fingerprint`` and
        ``repinned_at`` when a prior pin existed.
    """
    presented = _normalize(fingerprint)
    store = _load_store()
    previous = store.get(fqid) or {}
    entry: dict = {
        "fingerprint": presented,
        "first_seen": previous.get("first_seen") or _utc_now_iso(),
        "repinned_at": _utc_now_iso(),
    }
    if previous.get("fingerprint"):
        entry["previous_fingerprint"] = previous["fingerprint"]
    if reason:
        entry["repin_reason"] = reason
    if pubkey is not None:
        entry["pubkey"] = pubkey
    elif "pubkey" in previous:
        # A stale pubkey for a rotated key is worse than none: drop it.
        logger.warning("repin for %s drops the cached pubkey (rotated key)", fqid)
    store[fqid] = entry
    _save_store(store)
    logger.warning(
        "TOFU RE-PIN for %s: %s -> %s (operator action%s)",
        fqid,
        previous.get("fingerprint") or "<none>",
        presented,
        f", reason: {reason}" if reason else "",
    )
    return entry


def fingerprint_for(fqid: str) -> Optional[str]:
    """Look up the stored fingerprint for *fqid*.

    Args:
        fqid: The peer FQID handle.

    Returns:
        The stored 40-char fingerprint, or ``None`` if the fqid is unknown.
    """
    entry = _load_store().get(fqid)
    if not entry:
        return None
    return entry.get("fingerprint")


def verify_fingerprint(
    fqid: str, fingerprint: str, pubkey: Optional[str] = None
) -> TofuResult:
    """Verify *fingerprint* against the TOFU store for *fqid*.

    SSH host-key style TOFU:

    * **TRUST_NEW** — first sight of *fqid*: the fingerprint is recorded and
      trusted.
    * **TRUST_MATCH** — the presented fingerprint matches the stored one:
      trusted.
    * **CONFLICT** — the presented fingerprint differs from the stored one:
      rejected. The stored value is **not** changed (no silent overwrite).

    Args:
        fqid: The peer FQID handle.
        fingerprint: The fingerprint presented this contact.
        pubkey: Optional pubkey to cache on first sight (TRUST_NEW only).

    Returns:
        A :class:`TofuResult` carrying the status and both fingerprints.
    """
    presented = _normalize(fingerprint)
    stored = fingerprint_for(fqid)

    if stored is None:
        record_fingerprint(fqid, presented, pubkey=pubkey)
        return TofuResult(
            status=TofuStatus.TRUST_NEW,
            fqid=fqid,
            presented_fingerprint=presented,
            stored_fingerprint=None,
        )

    if stored == presented:
        return TofuResult(
            status=TofuStatus.TRUST_MATCH,
            fqid=fqid,
            presented_fingerprint=presented,
            stored_fingerprint=stored,
        )

    logger.warning(
        "TOFU CONFLICT for %s: stored=%s presented=%s (rejecting)",
        fqid,
        stored,
        presented,
    )
    return TofuResult(
        status=TofuStatus.CONFLICT,
        fqid=fqid,
        presented_fingerprint=presented,
        stored_fingerprint=stored,
    )
