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

SKCOMMS_HOME = "~/.skcapstone/skcomms"


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
    retry_max: int = 5
    retry_backoff: list[int] = Field(default_factory=lambda: [5, 15, 60, 300, 900])
    ttl: int = 86400
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
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

        return cls(
            version=skcomms_section.get("version", "1.0.0"),
            identity=IdentityConfig(**identity_data) if identity_data else IdentityConfig(),
            default_mode=skcomms_section.get("defaults", {}).get("mode", "failover"),
            encrypt=skcomms_section.get("defaults", {}).get("encrypt", True),
            sign=skcomms_section.get("defaults", {}).get("sign", True),
            ack=skcomms_section.get("defaults", {}).get("ack", True),
            retry_max=skcomms_section.get("defaults", {}).get("retry_max", 5),
            retry_backoff=skcomms_section.get("defaults", {}).get(
                "retry_backoff", [5, 15, 60, 300, 900]
            ),
            ttl=skcomms_section.get("defaults", {}).get("ttl", 86400),
            daemon=DaemonConfig(**daemon_data) if daemon_data else DaemonConfig(),
            transports=transport_configs,
        )


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
    if agent and config.identity.name != agent:
        logger.info(
            "skcomms identity overridden '%s' -> '%s' from SKAGENT",
            config.identity.name,
            agent,
        )
        config.identity.name = agent

    return config
