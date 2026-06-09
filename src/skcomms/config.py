"""
SKComm configuration — load and validate settings from YAML.

Default config location: ~/.skcomm/config.yml
Follows the same pattern as skcapstone's config.yaml.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from .models import RoutingMode

logger = logging.getLogger("skcomm.config")

SKCOMM_HOME = "~/.skcomm"


class IdentityConfig(BaseModel):
    """Identity settings — who this agent is."""

    name: str = "unknown"
    fingerprint: Optional[str] = None


class DaemonConfig(BaseModel):
    """Background daemon settings."""

    enabled: bool = True
    poll_interval_s: int = 5
    log_file: str = "~/.skcomm/logs/transport.log"


class TransportConfig(BaseModel):
    """Configuration for a single transport."""

    enabled: bool = True
    priority: int = 99
    settings: dict = Field(default_factory=dict)


class SKCommConfig(BaseModel):
    """Top-level SKComm configuration.

    Loaded from ~/.skcomm/config.yml. Provides defaults for
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
    def from_yaml(cls, path: Path) -> SKCommConfig:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML config file.

        Returns:
            SKCommConfig populated from the file, or defaults on error.
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

        skcomm_section = raw.get("skcomm", raw)

        transport_configs = {}
        for name, tconf in skcomm_section.get("transports", {}).items():
            if isinstance(tconf, dict):
                transport_configs[name] = TransportConfig(**tconf)
            elif isinstance(tconf, bool):
                transport_configs[name] = TransportConfig(enabled=tconf)

        identity_data = skcomm_section.get("identity", {})
        daemon_data = skcomm_section.get("daemon", {})

        return cls(
            version=skcomm_section.get("version", "1.0.0"),
            identity=IdentityConfig(**identity_data) if identity_data else IdentityConfig(),
            default_mode=skcomm_section.get("defaults", {}).get("mode", "failover"),
            encrypt=skcomm_section.get("defaults", {}).get("encrypt", True),
            sign=skcomm_section.get("defaults", {}).get("sign", True),
            ack=skcomm_section.get("defaults", {}).get("ack", True),
            retry_max=skcomm_section.get("defaults", {}).get("retry_max", 5),
            retry_backoff=skcomm_section.get("defaults", {}).get(
                "retry_backoff", [5, 15, 60, 300, 900]
            ),
            ttl=skcomm_section.get("defaults", {}).get("ttl", 86400),
            daemon=DaemonConfig(**daemon_data) if daemon_data else DaemonConfig(),
            transports=transport_configs,
        )


def load_config(config_path: Optional[str] = None) -> SKCommConfig:
    """Load SKComm config from disk.

    Args:
        config_path: Override config file location. Defaults to ~/.skcomm/config.yml.

    Returns:
        SKCommConfig with loaded or default settings.
    """
    path = Path(config_path) if config_path else Path(SKCOMM_HOME) / "config.yml"
    return SKCommConfig.from_yaml(path)
