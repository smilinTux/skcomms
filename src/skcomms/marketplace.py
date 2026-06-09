"""
SKWorld marketplace — publish and discover sovereign agent skills via Nostr.

Skills are published as Nostr kind 30078 parameterized-replaceable events
(NIP-78 application-specific data). Each skill manifest is a JSON payload
with metadata, tags, and install instructions.

Local registry at ~/.skcomm/skills/ tracks installed skills as YAML files.

Usage:
    from skcomm.marketplace import SkillManifest, SkillRegistry
    from skcomm.marketplace import publish_skill, search_skills
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from .config import SKCOMM_HOME

logger = logging.getLogger("skcomm.marketplace")

SKILLS_DIR_NAME = "skills"
NOSTR_SKILL_KIND = 30078
NOSTR_SKILL_PREFIX = "skworld"
DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]


# ---------------------------------------------------------------------------
# Skill manifest model
# ---------------------------------------------------------------------------


class SkillManifest(BaseModel):
    """Metadata for a sovereign agent skill.

    Attributes:
        name: Machine-readable skill identifier (e.g. "email-prescreening").
        title: Human-readable title.
        version: Semantic version string.
        author: Author name or agent name.
        description: Brief description of what the skill does.
        tags: Searchable keywords (e.g. ["security", "email"]).
        license: SPDX license identifier.
        repo: Git repository URL, if available.
        install_cmd: Shell command to install the skill.
        requires: List of dependency skill names or package names.
        homepage: URL to documentation or website.
        nostr_event_id: Nostr event ID if published to relays.
        published_at: When the skill was published to the marketplace.
        publisher_pubkey: Nostr pubkey of the publisher.
    """

    name: str
    title: str
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    license: str = "Apache-2.0"
    repo: Optional[str] = None
    install_cmd: Optional[str] = None
    requires: list[str] = Field(default_factory=list)
    homepage: Optional[str] = None
    nostr_event_id: Optional[str] = None
    published_at: Optional[datetime] = None
    publisher_pubkey: Optional[str] = None

    @classmethod
    def from_yaml_file(cls, path: Path) -> SkillManifest:
        """Load a skill manifest from a YAML file.

        Args:
            path: Path to the YAML manifest file.

        Returns:
            Parsed SkillManifest.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            ValueError: If the YAML is invalid.
        """
        raw = yaml.safe_load(path.read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"Invalid manifest: {path}")
        return cls.model_validate(raw)

    def to_yaml(self) -> str:
        """Serialize the manifest to YAML string.

        Returns:
            YAML-formatted string.
        """
        data = self.model_dump(mode="json", exclude_none=True)
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Local skill registry
# ---------------------------------------------------------------------------


class SkillRegistry:
    """Local registry of installed skills at ~/.skcomm/skills/.

    Each installed skill is stored as a YAML manifest file.

    Args:
        skills_dir: Directory for skill manifest files.
    """

    def __init__(self, skills_dir: Optional[Path] = None):
        self._dir = skills_dir or Path(SKCOMM_HOME).expanduser() / SKILLS_DIR_NAME
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def skills_dir(self) -> Path:
        """Path to the skills directory."""
        return self._dir

    def install(self, manifest: SkillManifest) -> Path:
        """Add a skill manifest to the local registry.

        Args:
            manifest: Skill to register locally.

        Returns:
            Path to the saved manifest file.
        """
        path = self._skill_path(manifest.name)
        path.write_text(manifest.to_yaml())
        logger.info("Installed skill %s v%s", manifest.name, manifest.version)
        return path

    def get(self, name: str) -> Optional[SkillManifest]:
        """Retrieve an installed skill by name.

        Args:
            name: Skill identifier.

        Returns:
            SkillManifest or None if not installed.
        """
        path = self._skill_path(name)
        if not path.exists():
            return None
        try:
            return SkillManifest.from_yaml_file(path)
        except Exception as exc:
            logger.warning("Failed to load skill %s: %s", name, exc)
            return None

    def list_all(self) -> list[SkillManifest]:
        """List all installed skills.

        Returns:
            List of SkillManifest sorted by name.
        """
        skills: list[SkillManifest] = []
        for path in sorted(self._dir.glob("*.yml")):
            try:
                skills.append(SkillManifest.from_yaml_file(path))
            except Exception as exc:
                logger.warning("Skipping invalid skill %s: %s", path.name, exc)
        return skills

    def remove(self, name: str) -> bool:
        """Remove a skill from the local registry.

        Args:
            name: Skill identifier.

        Returns:
            True if the skill was found and removed.
        """
        path = self._skill_path(name)
        if path.exists():
            path.unlink()
            logger.info("Removed skill %s", name)
            return True
        return False

    def _skill_path(self, name: str) -> Path:
        """Sanitized path for a skill YAML file."""
        safe = "".join(c for c in name if c.isalnum() or c in "-_.")
        return self._dir / f"{safe}.yml"


# ---------------------------------------------------------------------------
# Nostr marketplace: publish
# ---------------------------------------------------------------------------


def publish_skill(
    manifest: SkillManifest,
    private_key_hex: str,
    relays: Optional[list[str]] = None,
    timeout: float = 5.0,
) -> Optional[str]:
    """Publish a skill manifest to the Nostr marketplace.

    Creates a kind 30078 parameterized-replaceable event (NIP-78).
    The skill can be updated by publishing again with the same name.

    Args:
        manifest: Skill manifest to publish.
        private_key_hex: 64-char hex Nostr private key.
        relays: Relay URLs to publish to (defaults to standard relays).
        timeout: Relay connection timeout in seconds.

    Returns:
        Nostr event ID on success, or None on failure.
    """
    try:
        from .transports.nostr import (
            NOSTR_AVAILABLE,
            _make_event,
            _pubkey_of,
            _publish_to_relay,
            _sign_event,
        )
    except ImportError:
        logger.error("Nostr transport not available — cannot publish")
        return None

    if not NOSTR_AVAILABLE:
        logger.error("Nostr crypto deps missing — install skcomm[nostr]")
        return None

    secret = bytes.fromhex(private_key_hex)
    pubkey_x, _ = _pubkey_of(secret)
    pubkey_hex = pubkey_x.hex()

    manifest.published_at = datetime.now(timezone.utc)
    manifest.publisher_pubkey = pubkey_hex
    content = manifest.model_dump_json(exclude_none=True)

    tags = [
        ["d", f"{NOSTR_SKILL_PREFIX}:{manifest.name}"],
        ["name", manifest.name],
        ["title", manifest.title],
        ["version", manifest.version],
    ]
    if manifest.author:
        tags.append(["author", manifest.author])
    for tag in manifest.tags:
        tags.append(["t", tag])

    event = _make_event(pubkey_hex, NOSTR_SKILL_KIND, content, tags)
    _sign_event(event, secret)

    target_relays = relays or list(DEFAULT_RELAYS)
    for relay_url in target_relays:
        if _publish_to_relay(relay_url, event, timeout=timeout):
            logger.info(
                "Published skill %s to %s (event %s)",
                manifest.name,
                relay_url,
                event["id"][:12],
            )
            return event["id"]

    logger.warning("Failed to publish skill %s to any relay", manifest.name)
    return None


# ---------------------------------------------------------------------------
# Nostr marketplace: search
# ---------------------------------------------------------------------------


def search_skills(
    query: Optional[str] = None,
    relays: Optional[list[str]] = None,
    limit: int = 50,
    timeout: float = 5.0,
) -> list[SkillManifest]:
    """Search the Nostr marketplace for skills.

    Queries relays for kind 30078 events with the skworld prefix.
    Optionally filters by a search term matching name, title, or tags.

    Args:
        query: Optional search string to filter results.
        relays: Relay URLs to query (defaults to standard relays).
        limit: Maximum number of results.
        timeout: Relay connection timeout in seconds.

    Returns:
        List of matching SkillManifest, newest first.
    """
    try:
        from .transports.nostr import NOSTR_AVAILABLE, _query_relay
    except ImportError:
        logger.error("Nostr transport not available — cannot search")
        return []

    if not NOSTR_AVAILABLE:
        logger.error("Nostr crypto deps missing — install skcomm[nostr]")
        return []

    filters: dict = {
        "kinds": [NOSTR_SKILL_KIND],
        "#d": [f"{NOSTR_SKILL_PREFIX}:"],
        "limit": limit,
    }
    if query:
        filters["search"] = query

    target_relays = relays or list(DEFAULT_RELAYS)
    seen_ids: set[str] = set()
    results: list[SkillManifest] = []

    for relay_url in target_relays:
        events = _query_relay(relay_url, filters, timeout=timeout)
        for event in events:
            eid = event.get("id", "")
            if eid in seen_ids:
                continue
            seen_ids.add(eid)

            d_tags = [t[1] for t in event.get("tags", []) if t[0] == "d"]
            if not any(t.startswith(f"{NOSTR_SKILL_PREFIX}:") for t in d_tags):
                continue

            try:
                manifest = SkillManifest.model_validate_json(event["content"])
                manifest.nostr_event_id = eid
                manifest.publisher_pubkey = event.get("pubkey")
                results.append(manifest)
            except Exception:
                logger.debug("Skipping invalid skill event %s", eid[:12])

    query_lower = (query or "").lower()
    if query_lower:
        results = [
            s
            for s in results
            if query_lower in s.name.lower()
            or query_lower in s.title.lower()
            or query_lower in s.description.lower()
            or any(query_lower in t.lower() for t in s.tags)
        ]

    results.sort(
        key=lambda s: s.published_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return results[:limit]
