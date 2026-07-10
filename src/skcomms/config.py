"""
SKComms configuration — load and validate settings from YAML.

Default config location: ~/.skcapstone/skcomms/config.yml
Follows the same pattern as skcapstone's config.yaml.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from .models import RoutingMode

logger = logging.getLogger("skcomms.config")

# Env-aware so per-agent daemons (e.g. jarvis on .41) can load their OWN config
# (and thus their own inbox_path) via SKCOMMS_HOME, while the default agent + the
# S2S API use ~/.skcapstone/skcomms. Matches skcomms.home.skcomms_home()'s override.
SKCOMMS_HOME = os.environ.get("SKCOMMS_HOME") or "~/.skcapstone/skcomms"


class IdentityConfig(BaseModel):
    """Identity settings — who this agent is."""

    name: str = "unknown"
    fingerprint: Optional[str] = None


class DaemonConfig(BaseModel):
    """Background daemon settings."""

    enabled: bool = True
    poll_interval_s: int = 5
    log_file: str = "~/.skcapstone/skcomms/logs/transport.log"


class TransportConfig(BaseModel):
    """Configuration for a single transport."""

    enabled: bool = True
    priority: int = 99
    settings: dict = Field(default_factory=dict)


class HousekeepingConfig(BaseModel):
    """Retention / pruning settings for the periodic housekeeping pass.

    Every sender outbox write, receiver archive move, and mailbox outbox
    record is append-only; without pruning they grow without bound (the
    140k-file outbox leak that pegged Syncthing and froze a fleet laptop).
    These settings drive both the daemon's background housekeeping loop
    (see :mod:`skcomms.housekeeping`) and the ``skcomms housekeep`` CLI verb.

    Attributes:
        enabled: Whether the daemon runs the background housekeeping loop.
        interval_s: Seconds between housekeeping passes in the daemon
            (default 3600, hourly).
        outbox_max_age_hours: Sender outbox envelopes older than this are
            deleted (default 48h, matching ``prune_outbox``'s default;
            Syncthing has long since propagated anything this old).
        archive_ttl_hours: Receiver-side archive files older than this are
            deleted (default 168h = 7 days).
        mailbox_ttl_hours: Mailbox outbox records (the sender's local
            ``<realm>/<operator>/<agent>/outbox/*.json`` copies) older than
            this are deleted (default 168h = 7 days).
        dead_letter_ttl_hours: PersistentOutbox ``dead/`` entries older than
            this are deleted (default 720h = 30 days: long enough for manual
            triage, bounded so a persistent peer outage can not grow the
            directory forever). <= 0 disables the TTL sweep.
        dead_letter_max_count: Keep at most this many ``dead/`` entries
            (newest win; default 5000). <= 0 disables the count sweep.
        outbox_archive_ttl_hours: PersistentOutbox ``archive/`` entries
            (corrupt / dead-end entries parked by the outbox migrator, never
            read on the delivery path) older than this are deleted
            (default 720h = 30 days). <= 0 disables the TTL sweep.
        outbox_archive_max_count: Keep at most this many ``archive/`` entries
            (newest win; default 5000). <= 0 disables the count sweep.
    """

    enabled: bool = True
    interval_s: float = 3600.0
    outbox_max_age_hours: float = 48.0
    archive_ttl_hours: float = 168.0
    mailbox_ttl_hours: float = 168.0
    dead_letter_ttl_hours: float = 720.0
    dead_letter_max_count: int = 5000
    outbox_archive_ttl_hours: float = 720.0
    outbox_archive_max_count: int = 5000


class ObservabilityConfig(BaseModel):
    """Depth-threshold + alerting settings for the periodic depth monitor.

    The 140k-file outbox leak that pegged Syncthing and froze a fleet laptop
    was invisible: ``FileTransport.health_check`` exposed ``pending_outbox``
    but nothing thresholded or alerted on it. These settings drive the
    daemon's background depth monitor (see :mod:`skcomms.observability`),
    which sums per-transport outbox depth plus the dead-letter queue depth
    and fires an sk-alert (via :mod:`skcomms.integration`) when either
    crosses its threshold. The monitor is edge-triggered: it fires once when
    a depth first crosses its threshold, not on every pass, so it never
    storms the alert bus.

    Attributes:
        enabled: Whether the daemon runs the background depth monitor.
        interval_s: Seconds between depth checks in the daemon (default 300,
            every 5 minutes; depth changes slowly relative to housekeeping).
        outbox_depth_threshold: Total pending outbox depth (summed across
            every transport that reports ``pending_outbox``) at or above which
            an ``outbox_depth_high`` alert fires (default 1000). Values <= 0
            disable the outbox-depth check.
        dead_letter_threshold: Dead-letter queue depth at or above which a
            ``dead_letter_growth`` alert fires when the count has grown since
            the last pass (default 1: the first permanently-failed message is
            worth surfacing). Values <= 0 disable the dead-letter check.
        alert_level: sk-alert severity for depth alerts (default ``warn``).
    """

    enabled: bool = True
    interval_s: float = 300.0
    outbox_depth_threshold: int = 1000
    dead_letter_threshold: int = 1
    alert_level: str = "warn"


class RegistryConfig(BaseModel):
    """Realm peer-registry settings (T11).

    Drives :class:`skcomms.registry.PeerRegistry` — which backends are enabled,
    in what order they are consulted, and per-backend connection details. The
    defaults are **sovereign**: only the offline ``syncthing-shared`` backend is
    enabled, so out of the box the registry never reaches the network.

    Attributes:
        enabled: Backend names that are active (default: syncthing-shared only).
        order: The order backends are consulted/merged in (default puts the
            sovereign offline backend first, then the opt-in network ones).
        https_url_template: Template for the HTTPS backend URL. ``{realm}`` is
            substituted from ``cluster.json``.
        tailscale_host_template: Hostname convention mapping a tailnet node to
            an fqid's ``<agent>`` + ``<operator>`` (default
            ``skcomms-{agent}-{operator}``).
        tailscale_tag: Tailnet tag that marks a node as an skcomms peer.
    """

    enabled: list[str] = Field(default_factory=lambda: ["syncthing-shared"])
    order: list[str] = Field(
        default_factory=lambda: ["syncthing-shared", "https", "tailscale"]
    )
    https_url_template: str = "https://registry.{realm}/peers.json"
    tailscale_host_template: str = "skcomms-{agent}-{operator}"
    tailscale_tag: str = "tag:skcomms"


class SKCommsConfig(BaseModel):
    """Top-level SKComms configuration.

    Loaded from ~/.skcapstone/skcomms/config.yml. Provides defaults for
    routing mode, encryption, signing, retries, and per-transport
    configuration.
    """

    version: str = "1.0.0"
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    default_mode: RoutingMode = RoutingMode.FAILOVER
    encrypt: bool = True
    sign: bool = True
    ack: bool = True
    # When True, an inbound ACK must carry a PGP payload signature that
    # verifies against the claimed sender's known public key before it can
    # confirm delivery (fail closed). Off by default for backward
    # compatibility with peers that do not sign ACKs yet.
    ack_verify_signature: bool = False
    retry_max: int = 5
    retry_backoff: list[int] = Field(default_factory=lambda: [5, 15, 60, 300, 900])
    ttl: int = 86400
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    housekeeping: HousekeepingConfig = Field(default_factory=HousekeepingConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    transports: dict[str, TransportConfig] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: Path) -> SKCommsConfig:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML config file.

        Returns:
            SKCommsConfig populated from the file, or defaults on error.
        """
        path = path.expanduser()
        if not path.exists():
            logger.info("No config at %s — using defaults", path)
            return cls()

        try:
            raw = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as exc:
            logger.warning("Failed to parse %s: %s — using defaults", path, exc)
            return cls()

        skcomms_section = raw.get("skcomms") or raw.get("skcomm") or raw

        transport_configs = {}
        for name, tconf in skcomms_section.get("transports", {}).items():
            if isinstance(tconf, dict):
                transport_configs[name] = TransportConfig(**tconf)
            elif isinstance(tconf, bool):
                transport_configs[name] = TransportConfig(enabled=tconf)

        identity_data = skcomms_section.get("identity", {})
        daemon_data = skcomms_section.get("daemon", {})
        housekeeping_data = skcomms_section.get("housekeeping", {})
        observability_data = skcomms_section.get("observability", {})

        return cls(
            version=skcomms_section.get("version", "1.0.0"),
            identity=IdentityConfig(**identity_data) if identity_data else IdentityConfig(),
            default_mode=skcomms_section.get("defaults", {}).get("mode", "failover"),
            encrypt=skcomms_section.get("defaults", {}).get("encrypt", True),
            sign=skcomms_section.get("defaults", {}).get("sign", True),
            ack=skcomms_section.get("defaults", {}).get("ack", True),
            ack_verify_signature=skcomms_section.get("defaults", {}).get(
                "ack_verify_signature", False
            ),
            retry_max=skcomms_section.get("defaults", {}).get("retry_max", 5),
            retry_backoff=skcomms_section.get("defaults", {}).get(
                "retry_backoff", [5, 15, 60, 300, 900]
            ),
            ttl=skcomms_section.get("defaults", {}).get("ttl", 86400),
            daemon=DaemonConfig(**daemon_data) if daemon_data else DaemonConfig(),
            housekeeping=(
                HousekeepingConfig(**housekeeping_data)
                if housekeeping_data
                else HousekeepingConfig()
            ),
            observability=(
                ObservabilityConfig(**observability_data)
                if observability_data
                else ObservabilityConfig()
            ),
            transports=transport_configs,
        )


def load_adapters_block(config_path: Optional[str] = None) -> dict:
    """Return the raw ``adapters:`` block from the skcomms config file.

    The channel-adapter registry (see :mod:`skcomms.adapters.factory`) consumes a
    raw config dict shaped as ``{"adapters": {...}}`` rather than the validated
    :class:`SKCommsConfig` model.  This helper reads just that block from the
    same ``config.yml`` the daemon already loads, honoring the
    ``skcomms``/``skcomm`` section wrapper.

    Args:
        config_path: Override config file location. Defaults to
            ``~/.skcapstone/skcomms/config.yml``.

    Returns:
        A dict ``{"adapters": {...}}``.  When the file is missing, unparseable,
        or has no ``adapters:`` block, ``{"adapters": {}}`` is returned so
        callers can build an empty registry without special-casing absence.
    """
    path = Path(config_path) if config_path else Path(SKCOMMS_HOME) / "config.yml"
    path = path.expanduser()
    if not path.exists():
        return {"adapters": {}}

    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        logger.warning("Failed to parse %s for adapters: %s", path, exc)
        return {"adapters": {}}

    section = raw.get("skcomms") or raw.get("skcomm") or raw
    adapters = section.get("adapters") if isinstance(section, dict) else None
    return {"adapters": adapters if isinstance(adapters, dict) else {}}


def load_config(config_path: Optional[str] = None) -> SKCommsConfig:
    """Load SKComms config from disk.

    Args:
        config_path: Override config file location. Defaults to ~/.skcapstone/skcomms/config.yml.

    Returns:
        SKCommsConfig with loaded or default settings.
    """
    path = Path(config_path) if config_path else Path(SKCOMMS_HOME) / "config.yml"
    config = SKCommsConfig.from_yaml(path)

    # The skcomms config home is a single shared path, so every agent loads the
    # same config.yml and would inherit its (historically 'lumina') identity —
    # making non-lumina agents transmit as 'lumina' and collide on the wire.
    # Honor the framework's per-agent selector so each agent transmits as
    # itself. SKAGENT is the primary selector (see skcapstone agent resolution);
    # SKCAPSTONE_AGENT is the documented fallback.
    agent = (os.environ.get("SKAGENT") or os.environ.get("SKCAPSTONE_AGENT") or "").strip()
    if agent:
        if config.identity.name != agent:
            logger.info(
                "skcomms identity overridden '%s' -> '%s' from SKAGENT",
                config.identity.name,
                agent,
            )
            config.identity.name = agent

        # Per-agent transport paths: the ONE shared config serves N agents, each
        # reading/writing its OWN ~/.skcapstone/agents/<agent>/comms tree rather
        # than the historically-hardcoded 'lumina' paths (which made every agent
        # collide on lumina's inbox). ``agents/<agent>`` already exists per agent;
        # ``agent`` is a symlink to ``agents`` so lumina resolves byte-identically
        # to its prior path. Mirrors the S2S API's per-recipient routing in
        # api._write_to_recipient_inbox so writes and reads meet at one location.
        base = f"~/.skcapstone/agents/{agent}"
        file_t = config.transports.get("file")
        if file_t is not None:
            file_t.settings["inbox_path"] = f"{base}/comms/inbox"
            file_t.settings["outbox_path"] = f"{base}/comms/outbox"
        sync_t = config.transports.get("syncthing")
        if sync_t is not None and "comms_root" in sync_t.settings:
            sync_t.settings["comms_root"] = f"{base}/comms"
        if config.daemon and config.daemon.log_file:
            config.daemon.log_file = f"{base}/logs/transport.log"

    return config
