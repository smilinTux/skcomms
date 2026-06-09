"""
Syncthing transport — file-based P2P messaging over the Syncthing mesh.

Uses the existing Syncthing sync folder (same one used for vault sync)
as a message transport. Envelopes are written as JSON files to per-peer
outbox directories. Syncthing propagates them bidirectionally.

When Syncthing syncs a single shared folder between machines, a message
sent from Machine A to "Lumina" lands in ``outbox/Lumina/`` on *both*
machines.  The receiver picks up from ``inbox/`` directories **and** from
any ``outbox/`` subdirectory whose name matches its own identity (case-
insensitive).  This handles the common single-shared-folder topology
without requiring separate send/receive Syncthing folders.

This is the DEFAULT, always-on transport because Syncthing is already
running for vault sync. No additional infrastructure needed.

Directory layout:
    {comms_root}/
    ├── outbox/
    │   └── {peer}/           # One directory per recipient
    │       └── {id}.skc.json # Envelope files awaiting propagation
    ├── inbox/
    │   └── {peer}/           # One directory per sender
    │       └── {id}.skc.json # Received envelope files
    └── archive/
        └── {id}.skc.json     # Processed envelopes (optional)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Optional

from ..transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

logger = logging.getLogger("skcomm.transports.syncthing")

ENVELOPE_SUFFIX = ".skc.json"
LOCK_SUFFIX = ".skc.lock"


class SyncthingTransport(Transport):
    """File-based transport using Syncthing for P2P propagation.

    Writes envelopes as JSON files to outbox/{peer}/ directories.
    Syncthing detects the new files and syncs them to connected
    devices. The receiver's daemon polls inbox/{peer}/ for new files.

    Attributes:
        name: Always "syncthing".
        priority: Default 1 (highest priority — always-on transport).
        category: FILE_BASED — works offline, no direct network calls.
    """

    name: str = "syncthing"
    priority: int = 1
    category: TransportCategory = TransportCategory.FILE_BASED

    def __init__(
        self,
        comms_root: Optional[Path] = None,
        priority: int = 1,
        archive: bool = True,
        **kwargs,
    ):
        """Initialize the Syncthing transport.

        Args:
            comms_root: Root directory for comms folders. Defaults to
                        ~/.skcapstone/comms/ (same Syncthing share as vault sync).
            priority: Transport priority for routing (lower = higher priority).
            archive: Whether to move processed envelopes to archive/.
        """
        self.priority = priority
        self._archive = archive
        self._local_names: list[str] = []

        # Auto-add agent name from env so per-agent receive works
        agent_name = os.environ.get("SKAGENT") or os.environ.get("SKCAPSTONE_AGENT")
        if agent_name:
            self._local_names.append(agent_name)

        self._agents_mode: str | None = None  # "auto" or None

        if comms_root is None:
            self._root = Path("~/.skcapstone/comms").expanduser()
        else:
            self._root = Path(comms_root)

        self._outbox = self._root / "outbox"
        self._inbox = self._root / "inbox"
        self._archive_dir = self._root / "archive"

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys: comms_root, archive, identity, agents.
                    identity (str or list[str]): local agent names so the
                    transport can pick up messages from outbox/{name}/ dirs
                    that arrive via bidirectional Syncthing sync.
                    agents (str): Set to ``"auto"`` to auto-discover all agent
                    names from ``~/.skcapstone/agents/`` and add them to the
                    identity list. This lets a single daemon receive for
                    every agent on the machine.
        """
        if "comms_root" in config:
            self._root = Path(config["comms_root"]).expanduser()
            self._outbox = self._root / "outbox"
            self._inbox = self._root / "inbox"
            self._archive_dir = self._root / "archive"

        self._archive = config.get("archive", self._archive)

        identity = config.get("identity")
        if identity:
            if isinstance(identity, str):
                self._local_names = [identity]
            elif isinstance(identity, list):
                self._local_names = list(identity)

        # Auto-detect agent name from SKAGENT env var so that
        # per-agent receive works on shared machines (e.g. Jarvis receives
        # from outbox/jarvis/ even though the global config identity is
        # "Queen Lumina").
        agent_name = os.environ.get("SKAGENT") or os.environ.get("SKCAPSTONE_AGENT")
        if agent_name and agent_name not in self._local_names:
            self._local_names.append(agent_name)

        # Multi-agent mode: discover all agent directories and add their
        # names so a single daemon can receive for every local agent.
        agents_cfg = config.get("agents")
        if agents_cfg == "auto":
            self._agents_mode = "auto"
            self._discover_agents()

    def _set_identity(self, name: str) -> None:
        """Set the local identity name for outbox scanning.

        Called by the core SKComm engine so the transport knows which
        outbox/{name}/ subdirectories contain messages for this agent.

        Args:
            name: The local agent's display name.
        """
        if name and name not in self._local_names:
            self._local_names.append(name)

    def _discover_agents(self) -> None:
        """Auto-discover agent names from ~/.skcapstone/agents/.

        Scans the agents directory for subdirectories and adds each
        name to ``_local_names``. This enables a single receive daemon
        to pick up messages for every agent on the machine.
        """
        skcapstone_home = os.environ.get("SKCAPSTONE_HOME", "")
        if skcapstone_home:
            agents_dir = Path(skcapstone_home) / "agents"
        else:
            agents_dir = Path("~/.skcapstone/agents").expanduser()

        if not agents_dir.is_dir():
            return

        for entry in agents_dir.iterdir():
            if (
                entry.is_dir()
                and not entry.name.startswith(".")
                and not entry.name.endswith("-template")
                and entry.name not in self._local_names
            ):
                self._local_names.append(entry.name)
                logger.debug("Auto-discovered agent: %s", entry.name)

    def is_available(self) -> bool:
        """Check if the comms directories are accessible.

        Returns:
            True if the outbox and inbox directories exist or can be created.
        """
        try:
            self._ensure_dirs()
            return True
        except OSError:
            return False

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Write an envelope file to the recipient's outbox directory.

        The file is written atomically (write to .tmp then rename) to
        prevent Syncthing from syncing partial files.

        Args:
            envelope_bytes: Serialized MessageEnvelope bytes.
            recipient: Recipient agent name (used as subdirectory name).

        Returns:
            SendResult with success/failure and timing.
        """
        start = time.monotonic()
        envelope_id = self._extract_id(envelope_bytes)

        try:
            peer_outbox = self._outbox / recipient
            peer_outbox.mkdir(parents=True, exist_ok=True)

            filename = f"{envelope_id}{ENVELOPE_SUFFIX}"
            target = peer_outbox / filename
            tmp_target = peer_outbox / f".{filename}.tmp"

            # Reason: atomic write prevents Syncthing from syncing partial files
            tmp_target.write_bytes(envelope_bytes)
            tmp_target.rename(target)

            elapsed = (time.monotonic() - start) * 1000
            logger.info(
                "Wrote envelope %s to %s (%0.1fms)",
                envelope_id[:8],
                target,
                elapsed,
            )

            return SendResult(
                success=True,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
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
        """Poll inbox and outbox directories for inbound envelopes.

        Scans ``inbox/{peer}/`` (traditional layout) **and** any
        ``outbox/{name}/`` subdirectory whose name matches the local
        identity.  The outbox scan handles the common case where
        Syncthing bidirectionally syncs a single shared comms folder:
        messages sent *to* this agent land in ``outbox/{my_name}/``
        on the local machine.

        Optionally archives processed files.

        Returns:
            List of raw envelope bytes, one per received file.
        """
        self._ensure_dirs()
        received: list[bytes] = []

        # Collect directories to scan: all inbox peer dirs + matching outbox dirs
        scan_dirs: list[Path] = []

        if self._inbox.exists():
            scan_dirs.extend(d for d in self._inbox.iterdir() if d.is_dir())

        # Also scan outbox/{local_name}/ for messages arriving via
        # bidirectional Syncthing sync.
        if self._local_names and self._outbox.exists():
            lower_names = {n.lower() for n in self._local_names}
            for outbox_dir in self._outbox.iterdir():
                if outbox_dir.is_dir() and outbox_dir.name.lower() in lower_names:
                    scan_dirs.append(outbox_dir)

        for peer_dir in scan_dirs:
            for env_file in sorted(peer_dir.glob(f"*{ENVELOPE_SUFFIX}")):
                if env_file.name.startswith("."):
                    continue

                try:
                    data = env_file.read_bytes()
                    received.append(data)

                    if self._archive:
                        self._archive_file(env_file)
                    else:
                        env_file.unlink()

                    logger.debug("Received envelope from %s: %s", peer_dir.name, env_file.name)

                except OSError as exc:
                    logger.warning("Failed to read envelope %s: %s", env_file, exc)

        return received

    def health_check(self) -> HealthStatus:
        """Check the health of the Syncthing transport.

        Verifies directory accessibility, checks disk space, and reports
        any issues. Warns when free space is low enough to trigger
        Syncthing's minDiskFree threshold (default 1% of volume).

        Returns:
            HealthStatus with current state.
        """
        start = time.monotonic()
        details: dict = {}

        try:
            self._ensure_dirs()
            latency = (time.monotonic() - start) * 1000

            outbox_peers = (
                [d.name for d in self._outbox.iterdir() if d.is_dir()]
                if self._outbox.exists()
                else []
            )
            inbox_peers = (
                [d.name for d in self._inbox.iterdir() if d.is_dir()]
                if self._inbox.exists()
                else []
            )
            inbox_count = sum(
                len(list((self._inbox / p).glob(f"*{ENVELOPE_SUFFIX}"))) for p in inbox_peers
            )

            disk_warning = self._check_disk_space()
            status = TransportStatus.AVAILABLE
            error = None
            if disk_warning:
                status = TransportStatus.DEGRADED
                error = disk_warning
                logger.warning("Disk space low: %s", disk_warning)

            details = {
                "comms_root": str(self._root),
                "outbox_peers": outbox_peers,
                "inbox_peers": inbox_peers,
                "pending_inbox": inbox_count,
            }
            if disk_warning:
                details["disk_warning"] = disk_warning

            return HealthStatus(
                transport_name=self.name,
                status=status,
                latency_ms=latency,
                error=error,
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

    def _check_disk_space(self) -> Optional[str]:
        """Check if disk space is low enough to block Syncthing sync.

        Syncthing's default minDiskFree is 1% of the volume. On large
        drives (e.g. 2TB) this means ~20GB free is required. If the
        drive is near capacity, Syncthing silently refuses to sync new
        files — no UI warning, just errors in the REST API. This has
        bitten us in production (2026-02-25: 1395 files blocked on a
        1.9TB drive with 2GB free).

        Returns:
            Warning string if space is low, None if OK.
        """
        import shutil as _shutil

        try:
            usage = _shutil.disk_usage(self._root)
            free_pct = (usage.free / usage.total) * 100
            free_gb = usage.free / (1024**3)

            if free_gb < 1.0:
                return (
                    f"Only {free_gb:.1f}GB free ({free_pct:.1f}%). "
                    f"Sync may be blocked if Syncthing minDiskFree exceeds "
                    f"available space. Free disk space or lower minDiskFree "
                    f"via Syncthing API."
                )
        except OSError:
            pass
        return None

    def pending_outbox(self, peer: Optional[str] = None) -> list[Path]:
        """List envelope files waiting in the outbox.

        Args:
            peer: Optional peer name to filter by.

        Returns:
            List of Path objects for pending envelope files.
        """
        if not self._outbox.exists():
            return []

        if peer:
            peer_dir = self._outbox / peer
            if not peer_dir.exists():
                return []
            return sorted(peer_dir.glob(f"*{ENVELOPE_SUFFIX}"))

        files = []
        for peer_dir in self._outbox.iterdir():
            if peer_dir.is_dir():
                files.extend(sorted(peer_dir.glob(f"*{ENVELOPE_SUFFIX}")))
        return files

    def pending_inbox(self, peer: Optional[str] = None) -> list[Path]:
        """List envelope files waiting in the inbox.

        Args:
            peer: Optional peer name to filter by.

        Returns:
            List of Path objects for pending envelope files.
        """
        if not self._inbox.exists():
            return []

        if peer:
            peer_dir = self._inbox / peer
            if not peer_dir.exists():
                return []
            return sorted(peer_dir.glob(f"*{ENVELOPE_SUFFIX}"))

        files = []
        for peer_dir in self._inbox.iterdir():
            if peer_dir.is_dir():
                files.extend(sorted(peer_dir.glob(f"*{ENVELOPE_SUFFIX}")))
        return files

    def _ensure_dirs(self) -> None:
        """Create the comms directory structure if it doesn't exist."""
        self._outbox.mkdir(parents=True, exist_ok=True)
        self._inbox.mkdir(parents=True, exist_ok=True)
        if self._archive:
            self._archive_dir.mkdir(parents=True, exist_ok=True)

    def _archive_file(self, path: Path) -> None:
        """Move a processed envelope file to the archive directory."""
        self._archive_dir.mkdir(parents=True, exist_ok=True)
        dest = self._archive_dir / path.name
        # Reason: avoid collisions from identically-named files across peers
        if dest.exists():
            dest = self._archive_dir / f"{path.parent.name}-{path.name}"
        shutil.move(str(path), str(dest))

    @staticmethod
    def _extract_id(envelope_bytes: bytes) -> str:
        """Best-effort extraction of envelope_id from raw bytes.

        Args:
            envelope_bytes: Raw JSON envelope.

        Returns:
            The envelope_id string, or a timestamp-based fallback.
        """
        try:
            parsed = json.loads(envelope_bytes)
            return parsed.get("envelope_id", f"unknown-{int(time.time())}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return f"unknown-{int(time.time())}"


def create_transport(
    priority: int = 1,
    comms_root: Optional[str] = None,
    archive: bool = True,
    identity: Optional[list | str] = None,
    **kwargs,
) -> SyncthingTransport:
    """Factory function for the router's transport loader.

    Args:
        priority: Transport priority (lower = higher).
        comms_root: Override comms directory root.
        archive: Whether to archive processed envelopes.
        identity: Local agent name(s) for outbox scanning. When Syncthing
                  syncs a single shared folder, messages addressed to the
                  local agent land in outbox/{name}/. Providing identity
                  names here lets the transport pick them up.

    Returns:
        Configured SyncthingTransport instance.
    """
    root = Path(comms_root).expanduser() if comms_root else None
    transport = SyncthingTransport(comms_root=root, priority=priority, archive=archive)

    if identity:
        names = [identity] if isinstance(identity, str) else list(identity)
        for name in names:
            transport._set_identity(name)

    return transport
