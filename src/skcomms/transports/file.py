"""
File transport — the simplest possible delivery mechanism.

Writes envelopes as JSON files to a shared directory. Works over
NFS, SSHFS, CIFS, USB drives, Nextcloud sync, or any shared
filesystem. No network stack, no daemons, no configuration beyond
a pair of paths.

This is the sneakernet transport. If you can copy a file, you can
deliver a message.

Directory layout:
    outbox_path/          # Sender writes here
    └── {id}.skc.json     # One file per envelope

    inbox_path/           # Receiver reads here
    └── {id}.skc.json     # Appears when the filesystem syncs
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ..transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

logger = logging.getLogger("skcomms.transports.file")

ENVELOPE_SUFFIX = ".skc.json"

# Chunked file upload constants
LARGE_FILE_THRESHOLD = 10 * 1024 * 1024  # 10 MB — threshold to trigger chunking
TRANSFER_CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB  — size of each chunk


def _prune_dir_by_ttl(directory: Path, ttl_hours: float, log: logging.Logger) -> int:
    """Delete regular files in *directory* older than *ttl_hours* (by mtime).

    Shared TTL sweep used by the archive pruners of the file and syncthing
    transports. Hidden files (dot-prefixed, e.g. in-flight ``.tmp`` writes)
    are skipped. Non-recursive: only direct children are considered.

    Args:
        directory: The directory to sweep. Missing directory prunes nothing.
        ttl_hours: Age threshold in hours. Values <= 0 prune nothing.
        log: Logger for per-file warnings and the summary line.

    Returns:
        int: The number of files deleted.
    """
    if ttl_hours <= 0 or not directory.exists():
        return 0

    cutoff = time.time() - (ttl_hours * 3600.0)
    deleted = 0

    for entry in directory.iterdir():
        if entry.name.startswith(".") or not entry.is_file():
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink()
                deleted += 1
        except OSError as exc:
            log.warning("Failed to prune %s: %s", entry, exc)

    if deleted:
        log.info("Pruned %d file(s) older than %sh from %s", deleted, ttl_hours, directory)
    return deleted


@dataclass
class _ChunkRecord:
    """Per-chunk state for a resumable file transfer."""

    index: int
    offset: int
    size: int
    sha256: str
    verified: bool = False


@dataclass
class _TransferState:
    """Mutable transfer state persisted to ~/.skcapstone/transfers/{id}.json.

    Written after each chunk so the transfer can resume safely if
    interrupted.  ``verified=True`` on a chunk means the chunk's
    SHA-256 was confirmed against the source file and the chunk
    envelope was successfully written to the outbox.
    """

    transfer_id: str
    file_path: str
    filename: str
    file_size: int
    file_sha256: str
    recipient: str
    sender: str = ""
    total_chunks: int = 0
    chunk_size: int = TRANSFER_CHUNK_SIZE
    created_at: str = ""
    completed: bool = False
    chunks: list = field(default_factory=list)  # list[_ChunkRecord]

    def save(self, state_dir: Path) -> None:
        """Persist state to state_dir/{transfer_id}.json (atomic write)."""
        state_dir.mkdir(parents=True, exist_ok=True)
        path = state_dir / f"{self.transfer_id}.json"
        tmp = state_dir / f".{self.transfer_id}.json.tmp"
        tmp.write_text(json.dumps(asdict(self), indent=2, default=str), encoding="utf-8")
        tmp.rename(path)

    @classmethod
    def load(cls, transfer_id: str, state_dir: Path) -> "_TransferState":
        """Load state from state_dir/{transfer_id}.json."""
        path = state_dir / f"{transfer_id}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        chunks_raw = data.pop("chunks", [])
        state = cls(**data)
        state.chunks = [_ChunkRecord(**c) for c in chunks_raw]
        return state


class FileTransport(Transport):
    """Filesystem-based transport for shared directories.

    Unlike the Syncthing transport which uses per-peer subdirectories,
    the file transport uses flat outbox/inbox paths. The filesystem
    sharing mechanism (NFS, SSHFS, Nextcloud, USB) handles propagation.

    Attributes:
        name: Always "file".
        priority: Default 2 (after Syncthing, which is always-on).
        category: FILE_BASED — works offline, pure filesystem I/O.
    """

    name: str = "file"
    priority: int = 2
    category: TransportCategory = TransportCategory.FILE_BASED

    def __init__(
        self,
        outbox_path: Optional[Path] = None,
        inbox_path: Optional[Path] = None,
        priority: int = 2,
        archive: bool = True,
        archive_path: Optional[Path] = None,
        poll_interval_ms: int = 1000,
        **kwargs,
    ):
        """Initialize the file transport.

        Args:
            outbox_path: Directory to write outgoing envelopes.
            inbox_path: Directory to read incoming envelopes.
            priority: Transport priority (lower = higher).
            archive: Whether to archive processed inbox files.
            archive_path: Override archive directory location.
            poll_interval_ms: Suggested polling interval (informational).
        """
        self.priority = priority
        self._archive = archive
        self._poll_interval_ms = poll_interval_ms

        self._outbox = (
            Path(outbox_path).expanduser()
            if outbox_path
            else Path("~/.skcapstone/skcomms/outbox").expanduser()
        )
        self._inbox = (
            Path(inbox_path).expanduser() if inbox_path else Path("~/.skcapstone/skcomms/inbox").expanduser()
        )
        self._archive_dir = (
            Path(archive_path).expanduser() if archive_path else self._inbox.parent / "archive"
        )

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys: outbox_path, inbox_path,
                    archive, archive_path, poll_interval_ms.
        """
        if "outbox_path" in config:
            self._outbox = Path(config["outbox_path"]).expanduser()
        if "inbox_path" in config:
            self._inbox = Path(config["inbox_path"]).expanduser()
        if "archive_path" in config:
            self._archive_dir = Path(config["archive_path"]).expanduser()
        if "archive" in config:
            self._archive = config["archive"]
        if "poll_interval_ms" in config:
            self._poll_interval_ms = config["poll_interval_ms"]

    def is_available(self) -> bool:
        """Check if outbox and inbox directories are accessible.

        Returns:
            True if directories exist or can be created.
        """
        try:
            self._outbox.mkdir(parents=True, exist_ok=True)
            self._inbox.mkdir(parents=True, exist_ok=True)
            return True
        except OSError:
            return False

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Write an envelope file to the outbox directory.

        Atomic write (tmp then rename) to prevent readers from
        seeing partial files.

        Args:
            envelope_bytes: Serialized MessageEnvelope bytes.
            recipient: Recipient identifier (logged, not used for routing).

        Returns:
            SendResult with success/failure and timing.
        """
        start = time.monotonic()
        envelope_id = self._extract_id(envelope_bytes)

        try:
            self._outbox.mkdir(parents=True, exist_ok=True)

            filename = f"{envelope_id}{ENVELOPE_SUFFIX}"
            target = self._outbox / filename
            tmp_target = self._outbox / f".{filename}.tmp"

            tmp_target.write_bytes(envelope_bytes)
            tmp_target.rename(target)

            elapsed = (time.monotonic() - start) * 1000
            logger.info("Wrote %s to %s (%0.1fms)", envelope_id[:8], target, elapsed)

            # A shared-filesystem write is a QUEUE hand-off, not confirmed
            # receipt: the file only reaches the recipient once the filesystem
            # syncs and the recipient polls its inbox. Report queued=True so the
            # router/sender keeps a durable outbox entry pending an ACK instead
            # of treating the sneakernet write as a delivered message.
            return SendResult(
                success=True,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                queued=True,
            )

        except OSError as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("Failed to write envelope: %s", exc)
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error=str(exc),
            )

    def receive(self) -> list[bytes]:
        """Poll the inbox directory for new envelope files.

        Returns:
            List of raw envelope bytes from inbox files.
        """
        received: list[bytes] = []

        if not self._inbox.exists():
            return received

        for env_file in sorted(self._inbox.glob(f"*{ENVELOPE_SUFFIX}")):
            if env_file.name.startswith("."):
                continue

            try:
                data = env_file.read_bytes()
                received.append(data)

                if self._archive:
                    self._archive_file(env_file)
                else:
                    env_file.unlink()

                logger.debug("Received: %s", env_file.name)

            except OSError as exc:
                logger.warning("Failed to read %s: %s", env_file, exc)

        return received

    def health_check(self) -> HealthStatus:
        """Check filesystem accessibility and report status.

        Returns:
            HealthStatus with directory info and pending counts.
        """
        start = time.monotonic()
        details: dict = {}

        try:
            self._outbox.mkdir(parents=True, exist_ok=True)
            self._inbox.mkdir(parents=True, exist_ok=True)
            latency = (time.monotonic() - start) * 1000

            outbox_count = len(list(self._outbox.glob(f"*{ENVELOPE_SUFFIX}")))
            inbox_count = len(list(self._inbox.glob(f"*{ENVELOPE_SUFFIX}")))

            details = {
                "outbox_path": str(self._outbox),
                "inbox_path": str(self._inbox),
                "pending_outbox": outbox_count,
                "pending_inbox": inbox_count,
                "poll_interval_ms": self._poll_interval_ms,
            }

            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.AVAILABLE,
                latency_ms=latency,
                details=details,
            )

        except OSError as exc:
            latency = (time.monotonic() - start) * 1000
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.UNAVAILABLE,
                latency_ms=latency,
                error=str(exc),
                details=details,
            )

    # ── Chunked file transfer ─────────────────────────────────────────────────

    def _default_state_dir(self) -> Path:
        """Default directory for transfer state JSON files."""
        return Path("~/.skcapstone/transfers").expanduser()

    def send_file(
        self,
        file_path: Path,
        recipient: str,
        transfer_id: Optional[str] = None,
        state_dir: Optional[Path] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> str:
        """Send a file with chunked upload and resume support.

        Files > 10 MB are split into 1 MB chunks.  Each chunk's SHA-256
        is stored in ``state_dir/{transfer_id}.json`` so interrupted
        transfers can be resumed — already-verified chunks are skipped.

        Args:
            file_path: Path to the file to send.
            recipient: Recipient identifier.
            transfer_id: Optional existing transfer ID (for resume).
                Auto-generated (12-char hex UUID) if not provided.
            state_dir: Directory for state JSON files.
                Defaults to ``~/.skcapstone/transfers/``.
            progress_callback: Called as ``(transfer_id, chunk_idx, total)``
                after each chunk envelope is written to the outbox.

        Returns:
            transfer_id string.

        Raises:
            FileNotFoundError: If the source file does not exist.
            ValueError: If a chunk's SHA-256 doesn't match the source.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        sdir = state_dir or self._default_state_dir()
        if not transfer_id:
            transfer_id = uuid.uuid4().hex[:12]

        state_path = sdir / f"{transfer_id}.json"
        if state_path.exists():
            state = _TransferState.load(transfer_id, sdir)
            verified = sum(1 for c in state.chunks if c.verified)
            logger.info(
                "Resuming transfer %s: %d/%d chunks already verified",
                transfer_id,
                verified,
                state.total_chunks,
            )
        else:
            file_data = file_path.read_bytes()
            file_size = len(file_data)
            file_sha256 = hashlib.sha256(file_data).hexdigest()
            chunk_size = TRANSFER_CHUNK_SIZE if file_size > LARGE_FILE_THRESHOLD else file_size
            total_chunks = max(1, (file_size + chunk_size - 1) // chunk_size)

            chunks = []
            for i in range(total_chunks):
                offset = i * chunk_size
                end = min(offset + chunk_size, file_size)
                chunks.append(
                    _ChunkRecord(
                        index=i,
                        offset=offset,
                        size=end - offset,
                        sha256=hashlib.sha256(file_data[offset:end]).hexdigest(),
                    )
                )

            state = _TransferState(
                transfer_id=transfer_id,
                file_path=str(file_path),
                filename=file_path.name,
                file_size=file_size,
                file_sha256=file_sha256,
                recipient=recipient,
                total_chunks=total_chunks,
                chunk_size=chunk_size,
                created_at=datetime.now(timezone.utc).isoformat(),
                chunks=chunks,
            )
            state.save(sdir)

        return self._dispatch_chunks(file_path, state, sdir, progress_callback)

    def resume_file(
        self,
        transfer_id: str,
        state_dir: Optional[Path] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> str:
        """Resume an interrupted chunked file transfer.

        Reads state from ``state_dir/{transfer_id}.json``.  For each
        chunk marked verified, the SHA-256 is re-confirmed against the
        source file before skipping — preventing silently corrupt
        partial transfers.  All remaining chunks are (re-)sent.

        Args:
            transfer_id: The transfer ID to resume.
            state_dir: Directory containing state JSON files.
                Defaults to ``~/.skcapstone/transfers/``.
            progress_callback: Called as ``(transfer_id, chunk_idx, total)``.

        Returns:
            transfer_id string.

        Raises:
            FileNotFoundError: If the state file is not found.
        """
        sdir = state_dir or self._default_state_dir()
        state = _TransferState.load(transfer_id, sdir)
        file_path = Path(state.file_path)

        # Re-verify already-verified chunks against the source file so
        # that any corruption since the last run is caught and re-sent.
        if file_path.exists():
            file_data = file_path.read_bytes()
            for chunk in state.chunks:
                if not chunk.verified:
                    continue
                actual = hashlib.sha256(
                    file_data[chunk.offset : chunk.offset + chunk.size]
                ).hexdigest()
                if actual != chunk.sha256:
                    logger.warning(
                        "Chunk %d sha256 mismatch on resume (transfer %s) — will resend",
                        chunk.index,
                        transfer_id,
                    )
                    chunk.verified = False
            state.save(sdir)

        return self._dispatch_chunks(file_path, state, sdir, progress_callback)

    def _dispatch_chunks(
        self,
        file_path: Path,
        state: _TransferState,
        state_dir: Path,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> str:
        """Write unverified chunk envelopes to outbox; persist state after each.

        Skips chunks already marked ``verified=True``.  Verifies each
        chunk's SHA-256 from the source file before writing.
        """
        self._outbox.mkdir(parents=True, exist_ok=True)
        file_data = file_path.read_bytes()

        for chunk in state.chunks:
            if chunk.verified:
                logger.debug(
                    "Skip verified chunk %d/%d (transfer %s)",
                    chunk.index + 1,
                    state.total_chunks,
                    state.transfer_id,
                )
                continue

            chunk_data = file_data[chunk.offset : chunk.offset + chunk.size]

            # Verify integrity before sending
            actual = hashlib.sha256(chunk_data).hexdigest()
            if actual != chunk.sha256:
                raise ValueError(
                    f"Chunk {chunk.index} integrity error for transfer "
                    f"{state.transfer_id}: expected {chunk.sha256[:16]}..., "
                    f"got {actual[:16]}..."
                )

            envelope = {
                "skcomms_version": "1.0.0",
                "envelope_id": uuid.uuid4().hex,
                "type": "file_chunk",
                "transfer_id": state.transfer_id,
                "chunk_index": chunk.index,
                "total_chunks": state.total_chunks,
                "filename": state.filename,
                "file_size": state.file_size,
                "file_sha256": state.file_sha256,
                "chunk_sha256": chunk.sha256,
                "chunk_size": chunk.size,
                "offset": chunk.offset,
                "data": base64.b64encode(chunk_data).decode("ascii"),
                "sender": state.sender,
                "recipient": state.recipient,
            }
            envelope_bytes = json.dumps(envelope).encode("utf-8")

            filename = f"{state.transfer_id}-chunk-{chunk.index:04d}.skc.json"
            target = self._outbox / filename
            tmp = self._outbox / f".{filename}.tmp"
            tmp.write_bytes(envelope_bytes)
            tmp.rename(target)

            chunk.verified = True
            state.save(state_dir)

            logger.debug(
                "Wrote chunk %d/%d → %s",
                chunk.index + 1,
                state.total_chunks,
                filename,
            )

            if progress_callback:
                progress_callback(state.transfer_id, chunk.index + 1, state.total_chunks)

        state.completed = True
        state.save(state_dir)
        logger.info(
            "Transfer %s complete: %s (%d chunks, %d bytes)",
            state.transfer_id,
            state.filename,
            state.total_chunks,
            state.file_size,
        )
        return state.transfer_id

    def prune_outbox(self, max_age_hours: float = 48.0) -> int:
        """Delete stale envelope files from the outbox (self-trim safety valve).

        Removes ``*.skc.json`` files in the flat outbox directory whose
        modification time is older than *max_age_hours*. Mirrors
        :meth:`skcomms.transports.syncthing.SyncthingTransport.prune_outbox`
        for the flat (non per-peer) layout. Nothing else ever deletes sender
        outbox files, so without this the outbox grows without bound (the
        140k-file leak that pegged Syncthing on a fleet laptop). Call it from
        a periodic maintenance task or daemon loop, not on every send.

        Args:
            max_age_hours: Age threshold in hours. Files older than this (by
                mtime) are deleted. Defaults to 48.0. Values <= 0 prune nothing.

        Returns:
            int: The number of envelope files deleted.
        """
        if max_age_hours <= 0 or not self._outbox.exists():
            return 0

        cutoff = time.time() - (max_age_hours * 3600.0)
        deleted = 0

        for env_file in self._outbox.glob(f"*{ENVELOPE_SUFFIX}"):
            if env_file.name.startswith("."):
                continue
            try:
                if env_file.stat().st_mtime < cutoff:
                    env_file.unlink()
                    deleted += 1
            except OSError as exc:
                logger.warning("Failed to prune envelope %s: %s", env_file, exc)

        if deleted:
            logger.info(
                "Pruned %d stale outbox envelope(s) older than %sh", deleted, max_age_hours
            )
        return deleted

    def prune_archive(self, ttl_hours: float = 168.0) -> int:
        """Delete archived (already-processed) files older than *ttl_hours*.

        The receive path moves processed inbox files into the archive
        directory and nothing ever deletes them, so the archive grows
        without bound. This trims it on a TTL. Default 168h (7 days).

        Args:
            ttl_hours: Age threshold in hours. Files older than this (by
                mtime) are deleted. Values <= 0 prune nothing.

        Returns:
            int: The number of archive files deleted.
        """
        return _prune_dir_by_ttl(self._archive_dir, ttl_hours, logger)

    def _archive_file(self, path: Path) -> None:
        """Move a processed file to the archive directory."""
        self._archive_dir.mkdir(parents=True, exist_ok=True)
        dest = self._archive_dir / path.name
        if dest.exists():
            dest = self._archive_dir / f"{int(time.time())}-{path.name}"
        shutil.move(str(path), str(dest))

    @staticmethod
    def _extract_id(envelope_bytes: bytes) -> str:
        """Best-effort envelope_id extraction from raw bytes."""
        try:
            parsed = json.loads(envelope_bytes)
            return parsed.get("envelope_id", f"unknown-{int(time.time())}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return f"unknown-{int(time.time())}"


def create_transport(
    priority: int = 2,
    outbox_path: Optional[str] = None,
    inbox_path: Optional[str] = None,
    archive: bool = True,
    **kwargs,
) -> FileTransport:
    """Factory function for the router's transport loader.

    Args:
        priority: Transport priority (lower = higher).
        outbox_path: Override outbox directory.
        inbox_path: Override inbox directory.
        archive: Whether to archive processed files.

    Returns:
        Configured FileTransport instance.
    """
    return FileTransport(
        outbox_path=Path(outbox_path) if outbox_path else None,
        inbox_path=Path(inbox_path) if inbox_path else None,
        priority=priority,
        archive=archive,
    )
