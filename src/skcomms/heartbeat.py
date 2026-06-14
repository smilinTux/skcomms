"""
SKComms heartbeat protocol — alive/dead detection across the mesh.

v1: Each agent periodically writes a lightweight heartbeat file to the
shared comms directory. Syncthing propagates it to all peers. Any
agent can read the heartbeat files to determine who is alive.

v2: Active health beacon with richer state — capabilities, resource
metrics, claimed tasks, and loaded models. One file per node under
~/.skcapstone/sync/heartbeats/{node_id}.json — conflict-free because
no node ever writes to another node's file.

Heartbeat file layout (v2):
    {sync_root}/heartbeats/{node_id}.json

Liveness classification (v1/legacy):
    ALIVE:   heartbeat received within alive_timeout (default 2 min)
    STALE:   heartbeat received within stale_timeout (default 5 min)
    DEAD:    no heartbeat for longer than stale_timeout
    UNKNOWN: never seen a heartbeat from this peer
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from . import integration as _integration

logger = logging.getLogger("skcomms.heartbeat")

# ---------------------------------------------------------------------------
# v1 constants (kept for backward compatibility)
# ---------------------------------------------------------------------------

HEARTBEAT_DIR = "heartbeats"
HEARTBEAT_SUFFIX = ".heartbeat.json"

DEFAULT_ALIVE_TIMEOUT = 120
DEFAULT_STALE_TIMEOUT = 300
DEFAULT_COMMS_ROOT = "~/.skcapstone/comms"

# ---------------------------------------------------------------------------
# v2 constants
# ---------------------------------------------------------------------------

V2_HEARTBEAT_DIR = "heartbeats"
V2_SYNC_ROOT = "~/.skcapstone/sync"


# ---------------------------------------------------------------------------
# v1 models (kept for backward compatibility)
# ---------------------------------------------------------------------------


class PeerLiveness(str, Enum):
    """Liveness state of a peer based on heartbeat timing."""

    ALIVE = "alive"
    STALE = "stale"
    DEAD = "dead"
    UNKNOWN = "unknown"


class HeartbeatPayload(BaseModel):
    """Data written to the v1 heartbeat file.

    Attributes:
        agent: Agent name (matches the filename).
        timestamp: When this heartbeat was emitted (UTC ISO format).
        fingerprint: PGP fingerprint, if available.
        nostr_pubkey: Nostr x-only hex pubkey, if available.
        transports: List of transport names this agent supports.
        version: Heartbeat protocol version.
    """

    agent: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    fingerprint: Optional[str] = None
    nostr_pubkey: Optional[str] = None
    transports: list[str] = Field(default_factory=list)
    version: str = "1.0.0"


class PeerHeartbeat(BaseModel):
    """Status report for a single peer.

    Attributes:
        name: Agent name.
        status: Current liveness state.
        last_heartbeat: When the peer last emitted a heartbeat.
        age_seconds: Seconds since the last heartbeat.
        transports: What transports the peer reported supporting.
        fingerprint: PGP fingerprint from the heartbeat.
    """

    name: str
    status: PeerLiveness
    last_heartbeat: Optional[datetime] = None
    age_seconds: Optional[float] = None
    transports: list[str] = Field(default_factory=list)
    fingerprint: Optional[str] = None


# ---------------------------------------------------------------------------
# v2 models
# ---------------------------------------------------------------------------


class HeartbeatConfig(BaseModel):
    """Configuration for the v2 heartbeat publisher.

    Attributes:
        node_id: Unique identifier for this node (e.g. "jarvis-desktop").
        agent_name: Human-readable agent name (e.g. "jarvis").
        capabilities: List of capability tags advertised by this node.
        publish_interval_seconds: How often to write the heartbeat file.
        ttl_seconds: How long peers should consider this heartbeat valid.
        sync_root: Root of the Syncthing-shared directory.
        skcomms_status: Reported skcomms connectivity state.
        version: Heartbeat schema version.
    """

    node_id: str
    agent_name: str = ""
    capabilities: list[str] = Field(default_factory=list)
    publish_interval_seconds: int = 60
    ttl_seconds: int = 120
    sync_root: Path = Field(default_factory=lambda: Path(V2_SYNC_ROOT).expanduser())
    skcomms_status: str = "online"
    version: str = "0.1.0"


class NodeResources(BaseModel):
    """System resource snapshot for a node.

    Attributes:
        cpu_percent: Current CPU usage percentage.
        ram_total_gb: Total installed RAM in gigabytes.
        ram_used_gb: Currently used RAM in gigabytes.
        disk_free_gb: Free disk space in gigabytes on sync root's volume.
        gpu_available: Whether a CUDA/nvidia GPU is available.
    """

    cpu_percent: float = 0.0
    ram_total_gb: float = 0.0
    ram_used_gb: float = 0.0
    disk_free_gb: float = 0.0
    gpu_available: bool = False


class NodeHeartbeat(BaseModel):
    """Full v2 heartbeat payload written to disk for a single node.

    Attributes:
        node_id: Unique node identifier.
        timestamp: UTC ISO-8601 timestamp of when this was published.
        ttl_seconds: Validity window in seconds.
        state: High-level node state ("active", "idle", "busy", "offline").
        agent_name: Human-readable agent name.
        capabilities: Advertised capability tags.
        resources: System resource snapshot.
        claimed_tasks: Task IDs currently claimed by this node.
        loaded_models: AI models currently loaded.
        skcomms_status: skcomms connectivity state.
        version: Heartbeat schema version.
    """

    node_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: int = 120
    state: str = "active"
    agent_name: str = ""
    capabilities: list[str] = Field(default_factory=list)
    resources: NodeResources = Field(default_factory=NodeResources)
    claimed_tasks: list[str] = Field(default_factory=list)
    loaded_models: list[str] = Field(default_factory=list)
    skcomms_status: str = "online"
    version: str = "0.1.0"

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Check whether this heartbeat has exceeded its TTL.

        Args:
            now: Reference time (defaults to UTC now).

        Returns:
            True if the heartbeat is older than ttl_seconds.
        """
        ref = now or datetime.now(timezone.utc)
        age = (ref - self.timestamp).total_seconds()
        return age > self.ttl_seconds


# ---------------------------------------------------------------------------
# Resource detection helpers
# ---------------------------------------------------------------------------


def _collect_resources(sync_root: Path) -> NodeResources:
    """Gather live system resource metrics.

    Uses psutil for CPU/RAM/disk. Falls back to zeros if psutil is not
    installed. Detects GPU via nvidia-smi subprocess.

    Args:
        sync_root: Path used to measure disk free space.

    Returns:
        NodeResources populated with current metrics.
    """
    cpu_pct = 0.0
    ram_total = 0.0
    ram_used = 0.0
    disk_free = 0.0

    try:
        import psutil  # type: ignore[import]

        cpu_pct = psutil.cpu_percent(interval=0.1)
        vm = psutil.virtual_memory()
        ram_total = round(vm.total / (1024**3), 2)
        ram_used = round(vm.used / (1024**3), 2)

        try:
            target = sync_root.expanduser()
            target.mkdir(parents=True, exist_ok=True)
            du = psutil.disk_usage(str(target))
            disk_free = round(du.free / (1024**3), 2)
        except OSError:
            pass

    except ImportError:
        logger.debug("psutil not installed — resource metrics will be zero")

    gpu = _detect_gpu()
    return NodeResources(
        cpu_percent=cpu_pct,
        ram_total_gb=ram_total,
        ram_used_gb=ram_used,
        disk_free_gb=disk_free,
        gpu_available=gpu,
    )


def _detect_gpu() -> bool:
    """Detect whether a CUDA GPU is available via nvidia-smi.

    Returns:
        True if nvidia-smi exits cleanly, False otherwise.
    """
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def _read_claimed_tasks(sync_root: Path) -> list[str]:
    """Read task IDs currently claimed by this node from the coord board.

    Looks for a coord JSON file at {sync_root}/coord/board.json and
    returns the list of tasks marked as claimed by this process.

    Args:
        sync_root: Root of the shared sync directory.

    Returns:
        List of task ID strings (empty if no coord board found).
    """
    board_path = sync_root.expanduser() / "coord" / "board.json"
    if not board_path.exists():
        return []
    try:
        data = json.loads(board_path.read_text())
        tasks = data.get("tasks", [])
        if isinstance(tasks, list):
            return [str(t.get("id", "")) for t in tasks if t.get("status") == "claimed"]
        return []
    except Exception as exc:
        logger.debug("Could not read coord board: %s", exc)
        return []


# ---------------------------------------------------------------------------
# v2 HeartbeatPublisher
# ---------------------------------------------------------------------------


class HeartbeatPublisher:
    """Publishes this node's heartbeat file on a regular interval.

    Each node writes only its own file, making the operation conflict-free
    across a Syncthing-shared directory.

    Args:
        config: HeartbeatConfig for this node.
        state: Initial node state string.
        loaded_models: AI models currently loaded.
    """

    def __init__(
        self,
        config: HeartbeatConfig,
        state: str = "active",
        loaded_models: Optional[list[str]] = None,
    ) -> None:
        self._cfg = config
        self._state = state
        self._loaded_models = loaded_models or []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def heartbeat_dir(self) -> Path:
        """Directory where heartbeat files are stored."""
        return self._cfg.sync_root.expanduser() / V2_HEARTBEAT_DIR

    @property
    def heartbeat_path(self) -> Path:
        """Path to this node's heartbeat file."""
        return self.heartbeat_dir / f"{self._cfg.node_id}.json"

    def publish(self) -> Path:
        """Write this node's heartbeat file to disk (atomic, conflict-free).

        Collects live resource metrics, reads claimed tasks from the coord
        board, then writes a JSON file named after this node's ID. An
        atomic rename ensures readers never see a partial file.

        Raises:
            ValueError: If both node_id and agent_name are empty — a heartbeat
                with no identity would silently overwrite the empty-string
                filename ``{sync_root}/heartbeats/.json`` and is never useful.

        Returns:
            Path to the written heartbeat file.
        """
        if not self._cfg.node_id.strip() and not self._cfg.agent_name.strip():
            raise ValueError(
                "HeartbeatPublisher: both node_id and agent_name are empty — "
                "cannot publish an anonymous heartbeat"
            )
        sync_root = self._cfg.sync_root.expanduser()
        hb_dir = sync_root / V2_HEARTBEAT_DIR
        hb_dir.mkdir(parents=True, exist_ok=True)

        resources = _collect_resources(sync_root)
        claimed = _read_claimed_tasks(sync_root)

        hb = NodeHeartbeat(
            node_id=self._cfg.node_id,
            ttl_seconds=self._cfg.ttl_seconds,
            state=self._state,
            agent_name=self._cfg.agent_name or self._cfg.node_id,
            capabilities=list(self._cfg.capabilities),
            resources=resources,
            claimed_tasks=claimed,
            loaded_models=list(self._loaded_models),
            skcomms_status=self._cfg.skcomms_status,
            version=self._cfg.version,
        )

        target = hb_dir / f"{self._cfg.node_id}.json"
        tmp = hb_dir / f".{self._cfg.node_id}.json.tmp"
        tmp.write_text(hb.model_dump_json(indent=2))
        tmp.rename(target)

        logger.debug("Published v2 heartbeat to %s", target)
        return target

    def start(self) -> None:
        """Start a background thread that publishes on the configured interval.

        Safe to call multiple times; subsequent calls are no-ops if the
        thread is already running.
        """
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()

        def _loop() -> None:
            while not self._stop_event.is_set():
                try:
                    self.publish()
                except Exception as exc:
                    logger.warning("Heartbeat publish failed: %s", exc)
                    _integration.alert(
                        "heartbeat_publish_failed",
                        {"node_id": self._cfg.node_id, "error": str(exc)},
                        level="warn",
                    )
                self._stop_event.wait(self._cfg.publish_interval_seconds)

        self._thread = threading.Thread(target=_loop, daemon=True, name="heartbeat-publisher")
        self._thread.start()
        logger.info(
            "HeartbeatPublisher started (interval=%ds)", self._cfg.publish_interval_seconds
        )
        # Register with skcapstone fleet when present (idempotent).
        _integration.ensure_schedule()
        _integration.register_self()

    def stop(self) -> None:
        """Stop the background publish thread gracefully."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("HeartbeatPublisher stopped")


# ---------------------------------------------------------------------------
# v2 HeartbeatMonitor (node-centric, TTL-based)
# ---------------------------------------------------------------------------


class NodeHeartbeatMonitor:
    """Reads v2 heartbeat files written by other nodes.

    Nodes write to {sync_root}/heartbeats/{node_id}.json. This monitor
    reads those files to provide liveness, capability, and resource data.

    Args:
        sync_root: Root of the Syncthing-shared directory.
    """

    def __init__(self, sync_root: Optional[Path] = None) -> None:
        self._sync_root = (sync_root or Path(V2_SYNC_ROOT)).expanduser()
        self._hb_dir = self._sync_root / V2_HEARTBEAT_DIR

    @property
    def heartbeat_dir(self) -> Path:
        """Directory where v2 heartbeat files are stored."""
        return self._hb_dir

    def _load_all(self) -> list[NodeHeartbeat]:
        """Read all valid v2 heartbeat files from disk.

        Returns:
            List of NodeHeartbeat objects (invalid files are skipped).
        """
        if not self._hb_dir.exists():
            return []

        results: list[NodeHeartbeat] = []
        for path in sorted(self._hb_dir.glob("*.json")):
            if path.name.startswith("."):
                continue
            try:
                results.append(NodeHeartbeat.model_validate_json(path.read_text()))
            except Exception as exc:
                logger.warning("Invalid v2 heartbeat file %s: %s", path.name, exc)
        return results

    def get_node(self, node_id: str) -> Optional[NodeHeartbeat]:
        """Read the heartbeat for a specific node.

        Args:
            node_id: The node ID to look up.

        Returns:
            NodeHeartbeat or None if the file does not exist or is invalid.
        """
        path = self._hb_dir / f"{node_id}.json"
        if not path.exists():
            return None
        try:
            return NodeHeartbeat.model_validate_json(path.read_text())
        except Exception as exc:
            logger.warning("Failed to read v2 heartbeat for %s: %s", node_id, exc)
            return None

    def discover_nodes(self) -> list[NodeHeartbeat]:
        """Return all nodes whose TTL has not expired.

        Returns:
            List of NodeHeartbeat for live nodes, sorted by node_id.
        """
        now = datetime.now(timezone.utc)
        return [hb for hb in self._load_all() if not hb.is_expired(now)]

    def stale_nodes(self) -> list[NodeHeartbeat]:
        """Return all nodes whose TTL has expired.

        Returns:
            List of NodeHeartbeat for expired (stale) nodes.
        """
        now = datetime.now(timezone.utc)
        return [hb for hb in self._load_all() if hb.is_expired(now)]

    def find_capable(self, capability: str) -> list[NodeHeartbeat]:
        """Find live nodes that advertise a specific capability.

        Args:
            capability: Capability tag to search for (case-insensitive).

        Returns:
            List of live NodeHeartbeat entries advertising the capability.
        """
        cap_lower = capability.lower()
        return [
            hb for hb in self.discover_nodes() if cap_lower in [c.lower() for c in hb.capabilities]
        ]

    def all_nodes(self) -> list[NodeHeartbeat]:
        """Return all nodes regardless of TTL status.

        Returns:
            List of all NodeHeartbeat entries on disk.
        """
        return self._load_all()


# ---------------------------------------------------------------------------
# v1 HeartbeatMonitor (kept for backward compatibility)
# ---------------------------------------------------------------------------


class HeartbeatMonitor:
    """File-based heartbeat monitor for mesh peer liveness (v1).

    Writes heartbeat files to the shared comms directory and
    reads peer heartbeats to determine their liveness status.
    Designed to work with Syncthing propagation.

    Args:
        agent_name: This agent's name.
        comms_root: Root of the shared comms directory.
        fingerprint: PGP fingerprint to include in heartbeats.
        nostr_pubkey: Nostr pubkey to include in heartbeats.
        transports: List of transport names this agent supports.
        alive_timeout: Seconds before a peer is considered stale.
        stale_timeout: Seconds before a peer is considered dead.
    """

    def __init__(
        self,
        agent_name: str,
        comms_root: Optional[Path] = None,
        fingerprint: Optional[str] = None,
        nostr_pubkey: Optional[str] = None,
        transports: Optional[list[str]] = None,
        alive_timeout: int = DEFAULT_ALIVE_TIMEOUT,
        stale_timeout: int = DEFAULT_STALE_TIMEOUT,
    ):
        self._name = agent_name
        self._root = (comms_root or Path(DEFAULT_COMMS_ROOT)).expanduser()
        self._hb_dir = self._root / HEARTBEAT_DIR
        self._fingerprint = fingerprint
        self._nostr_pubkey = nostr_pubkey
        self._transports = transports or []
        self._alive_timeout = alive_timeout
        self._stale_timeout = stale_timeout

    @property
    def heartbeat_dir(self) -> Path:
        """Directory where heartbeat files are stored."""
        return self._hb_dir

    def emit(self) -> Path:
        """Write this agent's heartbeat file.

        Creates or overwrites the heartbeat JSON file in the
        shared comms directory. Syncthing propagates the updated
        file to all connected peers.

        Returns:
            Path to the written heartbeat file.
        """
        self._hb_dir.mkdir(parents=True, exist_ok=True)
        payload = HeartbeatPayload(
            agent=self._name,
            fingerprint=self._fingerprint,
            nostr_pubkey=self._nostr_pubkey,
            transports=self._transports,
        )
        path = self._hb_dir / f"{self._name}{HEARTBEAT_SUFFIX}"
        tmp = self._hb_dir / f".{self._name}{HEARTBEAT_SUFFIX}.tmp"

        data = payload.model_dump_json(indent=2)
        tmp.write_text(data)
        tmp.rename(path)

        logger.debug("Emitted heartbeat to %s", path)
        return path

    def read_peer(self, peer_name: str) -> Optional[HeartbeatPayload]:
        """Read a specific peer's heartbeat file.

        Args:
            peer_name: Name of the peer to check.

        Returns:
            HeartbeatPayload or None if no heartbeat file exists.
        """
        path = self._hb_dir / f"{peer_name}{HEARTBEAT_SUFFIX}"
        if not path.exists():
            return None
        try:
            return HeartbeatPayload.model_validate_json(path.read_text())
        except Exception as exc:
            logger.warning("Failed to read heartbeat for %s: %s", peer_name, exc)
            return None

    def peer_status(self, peer_name: str) -> PeerHeartbeat:
        """Check the liveness status of a single peer.

        Args:
            peer_name: Name of the peer.

        Returns:
            PeerHeartbeat with current status and timing.
        """
        payload = self.read_peer(peer_name)
        if payload is None:
            return PeerHeartbeat(name=peer_name, status=PeerLiveness.UNKNOWN)

        now = datetime.now(timezone.utc)
        age = (now - payload.timestamp).total_seconds()
        status = self._classify(age)

        return PeerHeartbeat(
            name=peer_name,
            status=status,
            last_heartbeat=payload.timestamp,
            age_seconds=round(age, 1),
            transports=payload.transports,
            fingerprint=payload.fingerprint,
        )

    def scan(self) -> list[PeerHeartbeat]:
        """Scan the heartbeat directory for all peer statuses.

        Returns:
            List of PeerHeartbeat for every peer with a heartbeat file,
            sorted by name. Excludes this agent's own heartbeat.
        """
        if not self._hb_dir.exists():
            return []

        results: list[PeerHeartbeat] = []
        now = datetime.now(timezone.utc)

        for path in sorted(self._hb_dir.glob(f"*{HEARTBEAT_SUFFIX}")):
            if path.name.startswith("."):
                continue
            peer_name = path.name.replace(HEARTBEAT_SUFFIX, "")
            if peer_name == self._name:
                continue

            try:
                payload = HeartbeatPayload.model_validate_json(path.read_text())
                age = (now - payload.timestamp).total_seconds()
                results.append(
                    PeerHeartbeat(
                        name=peer_name,
                        status=self._classify(age),
                        last_heartbeat=payload.timestamp,
                        age_seconds=round(age, 1),
                        transports=payload.transports,
                        fingerprint=payload.fingerprint,
                    )
                )
            except Exception as exc:
                logger.warning("Invalid heartbeat file %s: %s", path.name, exc)
                results.append(
                    PeerHeartbeat(
                        name=peer_name,
                        status=PeerLiveness.UNKNOWN,
                    )
                )

        return results

    def all_statuses(self, include_self: bool = False) -> list[PeerHeartbeat]:
        """Get statuses for all peers, optionally including self.

        Args:
            include_self: Whether to include this agent's own heartbeat.

        Returns:
            List of PeerHeartbeat sorted by name.
        """
        results = self.scan()
        if include_self:
            self_status = self.peer_status(self._name)
            if self_status.status != PeerLiveness.UNKNOWN:
                results.insert(0, self_status)
        return results

    def alive_peers(self) -> list[str]:
        """Return names of peers currently considered alive.

        Returns:
            List of peer names with ALIVE status.
        """
        return [p.name for p in self.scan() if p.status == PeerLiveness.ALIVE]

    def dead_peers(self) -> list[str]:
        """Return names of peers currently considered dead.

        Returns:
            List of peer names with DEAD status.
        """
        return [p.name for p in self.scan() if p.status == PeerLiveness.DEAD]

    def _classify(self, age_seconds: float) -> PeerLiveness:
        """Classify a peer's liveness based on heartbeat age.

        Args:
            age_seconds: Seconds since last heartbeat.

        Returns:
            PeerLiveness classification.
        """
        if age_seconds <= self._alive_timeout:
            return PeerLiveness.ALIVE
        elif age_seconds <= self._stale_timeout:
            return PeerLiveness.STALE
        else:
            return PeerLiveness.DEAD
