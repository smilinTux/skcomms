"""
Household API — multi-agent roster and per-agent data access.

Scans ~/.skcapstone/agent/ for agent directories, cross-references
with heartbeat files for online/offline status, and serves per-agent
identity, memories, and soul data.

Mounted at /api/v1/household/* by api.py.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger("skcomm.household")

household_router = APIRouter(prefix="/api/v1/household", tags=["household"])

# Default skcapstone root — can be overridden by env
_SKCAPSTONE_ROOT = Path("~/.skcapstone").expanduser()

# Heartbeat is "online" if younger than this many seconds
_ONLINE_THRESHOLD_SECONDS = 300


def _get_root() -> Path:
    """Resolve the skcapstone shared root."""
    import os

    root = os.environ.get("SKCAPSTONE_ROOT", os.environ.get("SKCAPSTONE_HOME", "~/.skcapstone"))
    return Path(root).expanduser()


def _read_json(path: Path) -> Optional[dict]:
    """Safely read a JSON file."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _agent_dirs(root: Path) -> list[Path]:
    """List all agent directories under root/agents/."""
    agents_dir = root / "agents"
    if not agents_dir.exists():
        return []
    return sorted(d for d in agents_dir.iterdir() if d.is_dir() and not d.name.startswith("."))


def _heartbeat_status(root: Path, agent_name: str) -> dict[str, Any]:
    """Read heartbeat for an agent and determine online status."""
    hb_dir = root / "heartbeats"
    # Try exact match first, then case-insensitive (heartbeat files may use
    # display name casing e.g. "Opus.json" while agent dir is "opus").
    hb_path = hb_dir / f"{agent_name}.json"
    if not hb_path.exists() and hb_dir.exists():
        for candidate in hb_dir.iterdir():
            if candidate.stem.lower() == agent_name.lower() and candidate.suffix == ".json":
                hb_path = candidate
                break
    hb_data = _read_json(hb_path)
    if not hb_data:
        return {"online": False, "last_seen": None}

    try:
        ts = datetime.fromisoformat(hb_data.get("timestamp", ""))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - ts).total_seconds()
        online = age < _ONLINE_THRESHOLD_SECONDS
        return {
            "online": online,
            "last_seen": ts.isoformat(),
            "status": hb_data.get("status", "unknown"),
            "hostname": hb_data.get("hostname", ""),
            "soul_active": hb_data.get("soul_active", ""),
            "loaded_model": hb_data.get("loaded_model", ""),
        }
    except (ValueError, TypeError):
        return {"online": False, "last_seen": None}


def _agent_summary(root: Path, agent_dir: Path) -> dict[str, Any]:
    """Build a summary dict for a single agent."""
    name = agent_dir.name

    # Identity
    identity = _read_json(agent_dir / "identity" / "identity.json") or {}

    # Soul
    soul = _read_json(agent_dir / "soul" / "active.json") or {}

    # Manifest
    manifest = _read_json(agent_dir / "manifest.json") or {}

    # Heartbeat
    hb = _heartbeat_status(root, name)

    # Memory stats
    memory_stats = {"short_term": 0, "mid_term": 0, "long_term": 0}
    mem_dir = agent_dir / "memory"
    if mem_dir.exists():
        for tier, dirname in [
            ("short_term", "short-term"),
            ("mid_term", "mid-term"),
            ("long_term", "long-term"),
        ]:
            tier_dir = mem_dir / dirname
            if tier_dir.exists():
                memory_stats[tier] = sum(
                    1 for f in tier_dir.iterdir() if f.suffix in (".json", ".md", ".yaml")
                )

    return {
        "name": name,
        "fingerprint": identity.get("fingerprint", ""),
        "entity_type": manifest.get("entity_type", identity.get("entity_type", "ai-agent")),
        "soul": soul.get("active_soul", ""),
        "online": hb.get("online", False),
        "last_seen": hb.get("last_seen"),
        "status": hb.get("status", "unknown"),
        "hostname": hb.get("hostname", ""),
        "loaded_model": hb.get("loaded_model", ""),
        "memory_stats": memory_stats,
    }


@household_router.get("")
async def list_household():
    """List all agents in the household with online/offline status."""
    root = _get_root()
    agents = []
    for agent_dir in _agent_dirs(root):
        agents.append(_agent_summary(root, agent_dir))
    return {"agents": agents, "count": len(agents)}


@household_router.get("/{agent_name}")
async def get_agent_detail(agent_name: str):
    """Get detailed info for a single agent."""
    root = _get_root()
    agent_dir = root / "agents" / agent_name
    if not agent_dir.exists():
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
    return _agent_summary(root, agent_dir)


@household_router.get("/{agent_name}/memories")
async def get_agent_memories(
    agent_name: str,
    limit: int = Query(default=20, ge=1, le=200),
    layer: Optional[str] = Query(default=None),
):
    """Get memories for a specific agent."""
    root = _get_root()
    agent_dir = root / "agents" / agent_name
    if not agent_dir.exists():
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")

    mem_dir = agent_dir / "memory"
    if not mem_dir.exists():
        return {"agent": agent_name, "memories": [], "count": 0}

    memories = []
    tiers = [("short-term", "short_term"), ("mid-term", "mid_term"), ("long-term", "long_term")]

    if layer:
        tiers = [(t, l) for t, l in tiers if l == layer or t == layer]

    for dirname, tier_label in tiers:
        tier_dir = mem_dir / dirname
        if not tier_dir.exists():
            continue
        for f in sorted(tier_dir.glob("*.json"), reverse=True):
            if len(memories) >= limit:
                break
            data = _read_json(f)
            if data:
                data["layer"] = tier_label
                memories.append(data)
        if len(memories) >= limit:
            break

    return {"agent": agent_name, "memories": memories[:limit], "count": len(memories)}


@household_router.get("/{agent_name}/soul")
async def get_agent_soul(agent_name: str):
    """Get the soul blueprint for a specific agent."""
    root = _get_root()
    agent_dir = root / "agents" / agent_name
    if not agent_dir.exists():
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")

    active = _read_json(agent_dir / "soul" / "active.json")
    if not active:
        return {"agent": agent_name, "soul": None}

    # Try to load the full blueprint
    soul_name = active.get("active_soul", "")
    blueprint = None
    if soul_name:
        bp_path = agent_dir / "soul" / "installed" / f"{soul_name}.json"
        blueprint = _read_json(bp_path)

    return {
        "agent": agent_name,
        "active_soul": soul_name,
        "base_soul": active.get("base_soul", "default"),
        "activated_at": active.get("activated_at"),
        "blueprint": blueprint,
    }


@household_router.get("/{agent_name}/status")
async def get_agent_status(agent_name: str):
    """Get heartbeat/capacity status for a specific agent."""
    root = _get_root()
    hb_path = root / "heartbeats" / f"{agent_name}.json"
    hb_data = _read_json(hb_path)
    if not hb_data:
        raise HTTPException(
            status_code=404,
            detail=f"No heartbeat found for agent '{agent_name}'",
        )
    return hb_data
