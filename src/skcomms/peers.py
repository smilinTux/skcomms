"""Peer connectivity registry — Syncthing device + PGP key wiring (T8, ``1314e0ff``).

A *peer* is another agent in some realm whose message tree we replicate over
Syncthing. Adding a peer binds three things together:

    1. the peer's FQID (``<agent>@<operator>.<realm>``) — the human handle,
    2. the peer's PGP **fingerprint** — the canonical identity (TOFU-pinned),
    3. the peer's **Syncthing device id** — how the realm tree actually moves.

The PGP key is read with pure ``pgpy`` (the same library the rest of the repo
uses) so the fingerprint is derived with **no global keyring side effects** —
nothing is written to ``~/.gnupg`` and ``gpg`` is never shelled out to. This
keeps the operation fully testable against a tmp ``SKCOMMS_HOME`` + an
in-process key.

The binding is recorded via the TOFU store (:mod:`skcomms.tofu`): the first
fingerprint seen for an fqid is trusted; a *different* fingerprint on re-add is
a CONFLICT and is **refused** — never silently rebound.

Store layout (``${SKCOMMS_HOME:-~/.skcapstone/skcomms}/peers.json``)::

    {
      "peers": {
        "opus@casey.douno": {
          "syncthing_device_id": "ABCDEF1-...-2345678",
          "fingerprint": "AAAA...5555",
          "added_at": "2026-06-10T12:00:00+00:00"
        }
      }
    }

Public API:
    add_peer(fqid, syncthing_device_id, pubkey_path) -> dict
    show_peer(fqid) -> dict | None
    list_peers() -> dict[fqid, entry]
    peers_path() -> Path
    fingerprint_from_pubkey(armor) -> str   -- pure-pgpy, no keyring
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from .home import skcomms_home
from .tofu import TofuStatus, verify_fingerprint

logger = logging.getLogger("skcomms.peers")

_PEERS_NAME = "peers.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# fqid validation
# ---------------------------------------------------------------------------


def _validate_fqid(fqid: str) -> tuple[str, str, str]:
    """Validate an fqid's ``<agent>@<operator>.<realm>`` shape.

    Returns the ``(agent, operator, realm)`` triple.

    Raises:
        ValueError: If *fqid* is not a well-formed ``a@o.r`` handle.
    """
    if not isinstance(fqid, str) or "@" not in fqid:
        raise ValueError(
            f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)"
        )
    agent, rest = fqid.split("@", 1)
    if not agent or "." not in rest:
        raise ValueError(
            f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)"
        )
    operator, realm = rest.split(".", 1)
    if not operator or not realm:
        raise ValueError(
            f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)"
        )
    return agent, operator, realm


# ---------------------------------------------------------------------------
# pure-pgpy fingerprint extraction (no keyring / no gpg shell)
# ---------------------------------------------------------------------------


def fingerprint_from_pubkey(armor: str) -> str:
    """Derive a PGP fingerprint from an ASCII-armored public key.

    Uses pure ``pgpy`` — no ``~/.gnupg`` writes, no ``gpg`` subprocess. The
    fingerprint is normalized (spaces stripped, upper-cased) to match the
    canonical form used by :mod:`skcomms.tofu` and :class:`skcomms.signing.EnvelopeSigner`.

    Args:
        armor: ASCII-armored PGP public key block.

    Returns:
        The 40-char hex fingerprint.

    Raises:
        ValueError: If *armor* is not a parseable PGP key.
    """
    import pgpy

    try:
        key, _ = pgpy.PGPKey.from_blob(armor)
    except Exception as exc:  # malformed armor
        raise ValueError(f"could not parse PGP public key: {exc}") from exc
    return str(key.fingerprint).replace(" ", "").upper()


# ---------------------------------------------------------------------------
# peers.json store
# ---------------------------------------------------------------------------


def peers_path() -> Path:
    """Path to ``peers.json`` under SKCOMMS_HOME."""
    return skcomms_home() / _PEERS_NAME


def _load_peers() -> dict:
    """Load the peers store, returning the ``{"peers": {...}}`` structure."""
    path = peers_path()
    if not path.exists():
        return {"peers": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("peers store unreadable (%s): %s", path, exc)
        return {"peers": {}}
    if not isinstance(data, dict) or not isinstance(data.get("peers"), dict):
        return {"peers": {}}
    return data


def _save_peers(data: dict) -> None:
    """Persist the peers store atomically under SKCOMMS_HOME."""
    path = peers_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# add / show / list
# ---------------------------------------------------------------------------


def add_peer(
    fqid: str,
    syncthing_device_id: str,
    pubkey_path: Union[str, Path],
) -> dict:
    """Add (or idempotently re-add) a peer's Syncthing + PGP binding.

    Steps:

    1. Validate *fqid* shape (``<agent>@<operator>.<realm>``).
    2. Read the armored public key from *pubkey_path* and derive its
       fingerprint via pure ``pgpy`` (no keyring side effects).
    3. TOFU-bind the fqid -> fingerprint via
       :func:`skcomms.tofu.verify_fingerprint`. A **CONFLICT** (a different
       fingerprint than previously pinned for this fqid) is **refused**.
    4. Persist ``fqid -> {syncthing_device_id, fingerprint, added_at}`` in
       ``peers.json`` (idempotent; ``added_at`` is preserved across re-adds).

    Args:
        fqid: The peer FQID handle.
        syncthing_device_id: The peer's Syncthing device id.
        pubkey_path: Path to the peer's ASCII-armored public key.

    Returns:
        The stored peer record plus the TOFU ``status`` and ``fqid``.

    Raises:
        ValueError: On a bad fqid, an unparseable key, or a fingerprint
            CONFLICT with the existing TOFU binding.
        FileNotFoundError: If *pubkey_path* does not exist.
    """
    _validate_fqid(fqid)

    path = Path(pubkey_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"pubkey not found: {path}")
    armor = path.read_text(encoding="utf-8")
    fingerprint = fingerprint_from_pubkey(armor)

    # TOFU-bind: first sight records; a different fingerprint is a CONFLICT.
    tofu = verify_fingerprint(fqid, fingerprint, pubkey=armor)
    if tofu.status == TofuStatus.CONFLICT:
        raise ValueError(
            f"fingerprint conflict for {fqid}: stored {tofu.stored_fingerprint}, "
            f"got {fingerprint} (refusing to rebind — never silently overwrite)"
        )

    data = _load_peers()
    existing = data["peers"].get(fqid)
    added_at = existing["added_at"] if existing else _utc_now_iso()
    entry = {
        "syncthing_device_id": syncthing_device_id,
        "fingerprint": fingerprint,
        "added_at": added_at,
    }
    data["peers"][fqid] = entry
    _save_peers(data)

    logger.debug(
        "added peer %s device=%s fp=%s (%s)",
        fqid,
        syncthing_device_id,
        fingerprint,
        tofu.status.value,
    )
    return {"fqid": fqid, "status": tofu.status.value, **entry}


def show_peer(fqid: str) -> Optional[dict]:
    """Return the stored record for *fqid*, or ``None`` if unknown."""
    return _load_peers()["peers"].get(fqid)


def list_peers() -> dict:
    """Return the full ``fqid -> entry`` peer mapping."""
    return dict(_load_peers()["peers"])
