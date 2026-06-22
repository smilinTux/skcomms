"""Federation outbox migration (SKFed S7).

Reconciles the historical mix of payloads sitting in the
:class:`~skcomms.outbox.PersistentOutbox` pending queue onto the canonical
federation wire format: an :class:`~skcomms.envelope.SignedEnvelope`
(Envelope v1).

Per-entry policy
----------------
- **already SignedEnvelope** (``signed``) -> leave in place.
- **bare Envelope v1** (``envelope_v1``) -> leave in place (already canonical;
  it will be wrapped/signed at send time).
- **legacy MessageEnvelope** (``legacy``) -> rewrite into an Envelope v1
  (``sender``->``from_fqid``, ``recipient``->``to_fqid``,
  ``payload.content``->``body``, ``payload.content_type``->``content_type``),
  wrap in an **unsigned** :class:`SignedEnvelope`, and re-queue. Signing happens
  later at send time (``core.send`` signs with the capauth key); the converted
  entry is flagged ``needs_sign`` in its ``last_error`` so it is visible as
  pending-unsigned.
- **corrupt** (unparseable / unknown shape) -> move to ``archive/`` with a
  reason.
- **file:// local dead-end** (a legacy entry whose only destination is a
  ``file://`` path with no real federation recipient) -> move to ``archive/``
  with a reason (these are pre-federation local-file deliveries, not routable
  over S2S).

Idempotent: re-running over an already-migrated outbox converts nothing
(everything is ``signed`` / ``envelope_v1`` or already archived) and returns
all-zero/skipped counts.

Returns a summary dict: ``{"converted", "archived", "skipped"}``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .outbox import OutboxEntry, PersistentOutbox, classify_envelope_json

logger = logging.getLogger("skcomms.outbox_migrate")

# Marker stored in last_error for converted-but-unsigned entries.
NEEDS_SIGN_FLAG = "needs_sign:migrated-from-legacy-MessageEnvelope"


def _is_file_dead_end(value: Optional[str]) -> bool:
    """Whether an address string is a non-routable ``file://`` dead-end."""
    return isinstance(value, str) and value.strip().lower().startswith("file://")


def _legacy_to_signed_json(data: dict) -> Optional[str]:
    """Convert a legacy MessageEnvelope dict to an unsigned SignedEnvelope JSON.

    Returns ``None`` if the legacy entry is a ``file://`` local dead-end with no
    real federation destination (caller archives those instead).

    Args:
        data: The parsed legacy MessageEnvelope dict.

    Returns:
        Optional[str]: Serialized unsigned SignedEnvelope JSON, or None for a
        file:// dead-end.
    """
    from .envelope import Envelope, SignedEnvelope

    sender = data.get("sender") or ""
    recipient = data.get("recipient") or ""

    # A legacy entry whose destination is only a file:// path is a
    # pre-federation local dead-end -- not routable over S2S.
    if _is_file_dead_end(recipient) or (not recipient.strip()):
        return None

    payload = data.get("payload") or {}
    body = payload.get("content", "") if isinstance(payload, dict) else ""
    content_type = (
        payload.get("content_type", "text/plain")
        if isinstance(payload, dict)
        else "text/plain"
    )

    metadata = data.get("metadata") or {}
    thread_id = metadata.get("thread_id") if isinstance(metadata, dict) else None
    reply_to = metadata.get("in_reply_to") if isinstance(metadata, dict) else None

    env_kwargs: dict = {
        "from_fqid": sender or "unknown@local",
        "to_fqid": recipient,
        "content_type": str(content_type),
        "body": body if isinstance(body, str) else json.dumps(body),
        "thread_id": thread_id,
        "reply_to": reply_to,
    }
    # Preserve the original message id when present so dedup stays stable.
    if data.get("envelope_id"):
        env_kwargs["id"] = data["envelope_id"]

    envelope = Envelope(**env_kwargs)
    signed = SignedEnvelope(envelope=envelope)  # unsigned: signed at send time
    return signed.to_bytes().decode("utf-8")


def migrate_outbox(
    outbox: PersistentOutbox | str | Path = None,  # type: ignore[assignment]
) -> dict[str, int]:
    """Migrate a PersistentOutbox pending queue onto the canonical wire format.

    Args:
        outbox: A :class:`PersistentOutbox`, or a path to the outbox root dir,
            or None to use the default outbox location.

    Returns:
        dict[str, int]: ``{"converted", "archived", "skipped"}``.
    """
    if outbox is None:
        outbox = PersistentOutbox()
    elif isinstance(outbox, (str, Path)):
        outbox = PersistentOutbox(outbox_dir=outbox)

    summary = {"converted": 0, "archived": 0, "skipped": 0}

    for entry_path in sorted(outbox.pending_dir.glob("*.json")):
        try:
            raw = entry_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Cannot read outbox entry %s: %s", entry_path.name, exc)
            continue

        # Try to load as a wrapped OutboxEntry first; fall back to treating the
        # whole file as a raw serialized envelope (defensive).
        try:
            entry = OutboxEntry.model_validate_json(raw)
            envelope_json = entry.envelope_json
        except (json.JSONDecodeError, ValueError):
            entry = None
            envelope_json = raw

        kind = classify_envelope_json(envelope_json)

        if kind in ("signed", "envelope_v1"):
            summary["skipped"] += 1
            continue

        if kind == "corrupt":
            _archive(outbox, entry_path, "corrupt: unparseable / unknown envelope shape")
            summary["archived"] += 1
            continue

        # kind == "legacy"
        try:
            data = json.loads(envelope_json)
            converted_json = _legacy_to_signed_json(data)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            _archive(outbox, entry_path, f"legacy-convert-failed: {exc}")
            summary["archived"] += 1
            continue

        if converted_json is None:
            _archive(
                outbox,
                entry_path,
                "file:// local dead-end: no routable federation destination",
            )
            summary["archived"] += 1
            continue

        # Rewrite the entry in place with the converted, unsigned SignedEnvelope.
        if entry is not None:
            entry.envelope_json = converted_json
            entry.last_error = NEEDS_SIGN_FLAG
            _rewrite(outbox, entry_path, entry)
        else:
            # Bare-envelope file: re-wrap into a proper OutboxEntry.
            from .envelope import SignedEnvelope

            signed = SignedEnvelope.from_bytes(converted_json.encode("utf-8"))
            new_entry = OutboxEntry(
                envelope_id=signed.envelope.id,
                recipient=signed.envelope.to_fqid,
                envelope_json=converted_json,
                last_error=NEEDS_SIGN_FLAG,
            )
            entry_path.unlink(missing_ok=True)
            _rewrite(outbox, outbox.pending_dir / f"{new_entry.envelope_id}.json", new_entry)

        summary["converted"] += 1

    logger.info(
        "migrate_outbox: converted=%d archived=%d skipped=%d",
        summary["converted"],
        summary["archived"],
        summary["skipped"],
    )
    return summary


def _rewrite(outbox: PersistentOutbox, target_path: Path, entry: OutboxEntry) -> None:
    """Write ``entry`` to ``target_path`` (pending), removing a stale source."""
    target_path.write_text(entry.model_dump_json(indent=2), encoding="utf-8")


def _archive(outbox: PersistentOutbox, source_path: Path, reason: str) -> None:
    """Move a pending entry file into the archive dir with a reason sidecar.

    The original file content is preserved verbatim under ``archive/`` and a
    ``.reason`` sidecar records why it was archived. Idempotent on name.

    Args:
        outbox: The outbox.
        source_path: The pending file to archive.
        reason: Human-readable archive reason.
    """
    dest = outbox.archive_dir / source_path.name
    try:
        content = source_path.read_text(encoding="utf-8")
    except OSError:
        content = ""
    dest.write_text(content, encoding="utf-8")
    dest.with_suffix(".reason").write_text(reason, encoding="utf-8")
    source_path.unlink(missing_ok=True)
    logger.info("Archived outbox entry %s (%s)", source_path.name, reason)
