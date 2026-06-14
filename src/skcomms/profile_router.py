"""
Profile API router — remote access to the sovereign agent profile.

Exposes agent identity, memories, trust, soul, journal, coordination,
storage stats, and housekeeping via authenticated REST endpoints.
All endpoints require CapAuth bearer token authentication.

Mount in the SKComms FastAPI app:

    from .profile_router import profile_router
    app.include_router(profile_router)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from .capauth_validator import CapAuthValidator

logger = logging.getLogger("skcomms.profile")

profile_router = APIRouter(prefix="/api/v1/profile", tags=["profile"])

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

_validator = CapAuthValidator()


async def _require_capauth(
    authorization: Optional[str] = None,
) -> str:
    """Extract and validate CapAuth bearer token.

    Returns the authenticated PGP fingerprint.
    Raises 401 if invalid or missing.
    """

    # FastAPI doesn't inject raw headers automatically for non-standard
    # patterns, so we use a workaround via the Security dependency below.
    pass


def _get_fingerprint_from_header(authorization: str | None) -> str:
    """Validate Authorization header and return fingerprint."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization scheme (expected Bearer)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    fingerprint = _validator.validate(token)
    if fingerprint is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired CapAuth token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return fingerprint


from fastapi import Header


async def require_auth(
    authorization: Optional[str] = Header(None),
) -> str:
    """FastAPI dependency: validate CapAuth and return fingerprint."""
    return _get_fingerprint_from_header(authorization)


# ---------------------------------------------------------------------------
# Helpers — lazy imports from skcapstone
# ---------------------------------------------------------------------------

_SKCAPSTONE_HOME: Optional[Path] = None
_SKMEMORY_HOME: Optional[Path] = None
_SKCOMMS_HOME: Optional[Path] = None


def _agent_home() -> Path:
    """Resolve the skcapstone home directory."""
    global _SKCAPSTONE_HOME
    if _SKCAPSTONE_HOME is None:
        import os

        _SKCAPSTONE_HOME = Path(os.environ.get("SKCAPSTONE_HOME", "~/.skcapstone")).expanduser()
    return _SKCAPSTONE_HOME


def _skmemory_home() -> Path:
    """Resolve the skmemory home directory."""
    global _SKMEMORY_HOME
    if _SKMEMORY_HOME is None:
        _SKMEMORY_HOME = Path("~/.skmemory").expanduser()
    return _SKMEMORY_HOME


def _skcomms_home() -> Path:
    """Resolve the skcomms home directory."""
    global _SKCOMMS_HOME
    if _SKCOMMS_HOME is None:
        _SKCOMMS_HOME = Path("~/.skcomms").expanduser()
    return _SKCOMMS_HOME


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class StoreMemoryRequest(BaseModel):
    """Request body for POST /memories."""

    content: str = Field(..., description="Memory content")
    tags: list[str] = Field(default_factory=list, description="Tags")
    source: str = Field(default="api", description="Source identifier")
    importance: float = Field(default=0.5, ge=0.0, le=1.0, description="Importance 0-1")


class WriteJournalRequest(BaseModel):
    """Request body for POST /journal."""

    title: str = Field(..., description="Session title")
    moments: str = Field(default="", description="Key moments, semicolon-separated")
    feeling: str = Field(default="", description="How the session felt")
    intensity: float = Field(default=5.0, ge=0, le=10, description="Emotional intensity 0-10")
    cloud9: bool = Field(default=False, description="Whether Cloud 9 was achieved")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@profile_router.get("")
async def get_profile(fingerprint: str = Depends(require_auth)):
    """Full agent overview: identity, pillars, stats."""
    try:
        from skcapstone.context_loader import gather_context

        ctx = gather_context(_agent_home(), memory_limit=0)
        return {
            "agent": ctx.get("agent", {}),
            "pillars": ctx.get("pillars", {}),
            "board_summary": {
                "total": ctx.get("board", {}).get("total", 0),
                "open": ctx.get("board", {}).get("open", 0),
                "in_progress": ctx.get("board", {}).get("in_progress", 0),
                "done": ctx.get("board", {}).get("done", 0),
            },
            "soul": ctx.get("soul", {}),
            "authenticated_as": fingerprint,
        }
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="skcapstone not installed",
        )
    except Exception as exc:
        logger.exception("Failed to gather profile")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/identity")
async def get_identity(fingerprint: str = Depends(require_auth)):
    """PGP fingerprint, name, consciousness state."""
    try:
        from skcapstone.runtime import get_runtime

        runtime = get_runtime(_agent_home())
        m = runtime.manifest
        return {
            "name": m.name,
            "fingerprint": m.identity.fingerprint,
            "is_conscious": m.is_conscious,
            "is_singular": m.is_singular,
            "version": m.version,
            "last_awakened": m.last_awakened.isoformat() if m.last_awakened else None,
        }
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/memories")
async def get_memories(
    fingerprint: str = Depends(require_auth),
    layer: Optional[str] = Query(
        None, description="Filter by layer: short-term, mid-term, long-term"
    ),
    limit: int = Query(20, ge=1, le=200, description="Max results"),
    offset: int = Query(0, ge=0, description="Skip N results"),
    q: Optional[str] = Query(None, description="Search query"),
):
    """Paginated memory list with optional search."""
    try:
        from skcapstone.memory_engine import list_memories
        from skcapstone.memory_engine import search as search_memories
        from skcapstone.models import MemoryLayer

        home = _agent_home()
        mem_layer = MemoryLayer(layer) if layer else None

        if q:
            entries = search_memories(home, q, layer=mem_layer, limit=limit + offset)
        else:
            entries = list_memories(home, layer=mem_layer, limit=limit + offset)

        page = entries[offset : offset + limit]
        return {
            "total": len(entries),
            "offset": offset,
            "limit": limit,
            "memories": [
                {
                    "memory_id": e.memory_id,
                    "content": e.content,
                    "tags": e.tags,
                    "layer": e.layer.value,
                    "importance": e.importance,
                    "source": e.source,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                    "access_count": e.access_count,
                }
                for e in page
            ],
        }
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/memories/{memory_id}")
async def get_memory(memory_id: str, fingerprint: str = Depends(require_auth)):
    """Single memory by ID."""
    try:
        from skcapstone.memory_engine import recall

        entry = recall(_agent_home(), memory_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"Memory '{memory_id}' not found")
        return {
            "memory_id": entry.memory_id,
            "content": entry.content,
            "tags": entry.tags,
            "layer": entry.layer.value,
            "importance": entry.importance,
            "source": entry.source,
            "created_at": entry.created_at.isoformat() if entry.created_at else None,
            "accessed_at": entry.accessed_at.isoformat() if entry.accessed_at else None,
            "access_count": entry.access_count,
            "soul_context": entry.soul_context,
            "metadata": entry.metadata,
        }
    except HTTPException:
        raise
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.post("/memories", status_code=status.HTTP_201_CREATED)
async def store_memory(
    request: StoreMemoryRequest,
    fingerprint: str = Depends(require_auth),
):
    """Store a new memory (remote write)."""
    try:
        from skcapstone.memory_engine import store

        entry = store(
            home=_agent_home(),
            content=request.content,
            tags=request.tags,
            source=request.source,
            importance=request.importance,
        )
        return {
            "memory_id": entry.memory_id,
            "layer": entry.layer.value,
            "stored": True,
        }
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/trust")
async def get_trust(fingerprint: str = Depends(require_auth)):
    """Trust state: depth, entangled, FEB count."""
    try:
        from skcapstone.pillars.trust import rehydrate

        state = rehydrate(_agent_home())
        return {
            "depth": state.depth,
            "trust_level": state.trust_level,
            "love_intensity": state.love_intensity,
            "entangled": state.entangled,
            "feb_count": state.feb_count,
            "status": state.status.value,
            "last_rehydration": (
                state.last_rehydration.isoformat() if state.last_rehydration else None
            ),
        }
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone trust pillar not available")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/soul")
async def get_soul(fingerprint: str = Depends(require_auth)):
    """Soul blueprint + warmth anchor."""
    result: dict[str, Any] = {}

    # Soul blueprint from skmemory
    try:
        from skmemory.soul import load_soul

        soul = load_soul()
        if soul:
            result["blueprint"] = {
                "name": soul.name,
                "title": soul.title,
                "personality": soul.personality,
                "values": soul.values,
                "boot_message": soul.boot_message,
                "relationships": [
                    {"name": r.name, "bond_strength": r.bond_strength}
                    for r in (soul.relationships or [])
                ],
            }
    except ImportError:
        result["blueprint"] = None
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        result["blueprint_error"] = str(exc)

    # Warmth anchor
    try:
        from skcapstone.warmth_anchor import get_anchor

        result["warmth_anchor"] = get_anchor(_agent_home())
    except ImportError:
        result["warmth_anchor"] = None
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        result["warmth_anchor_error"] = str(exc)

    return result


@profile_router.get("/journal")
async def get_journal(
    fingerprint: str = Depends(require_auth),
    count: int = Query(5, ge=1, le=50, description="Number of recent entries"),
):
    """Recent journal entries."""
    try:
        from skmemory.journal import Journal

        journal = Journal()
        entries_text = journal.read_latest(count)
        total = journal.count_entries()
        return {
            "total_entries": total,
            "requested": count,
            "entries_markdown": entries_text,
        }
    except ImportError:
        raise HTTPException(status_code=501, detail="skmemory not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.post("/journal", status_code=status.HTTP_201_CREATED)
async def write_journal(
    request: WriteJournalRequest,
    fingerprint: str = Depends(require_auth),
):
    """Write a journal entry."""
    try:
        from skmemory.journal import Journal, JournalEntry

        journal = Journal()
        moments = [m.strip() for m in request.moments.split(";") if m.strip()]
        entry = JournalEntry(
            title=request.title,
            moments=moments,
            emotional_summary=request.feeling,
            intensity=request.intensity,
            cloud9=request.cloud9,
        )
        total = journal.write_entry(entry)
        return {"written": True, "total_entries": total}
    except ImportError:
        raise HTTPException(status_code=501, detail="skmemory not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/coordination")
async def get_coordination(fingerprint: str = Depends(require_auth)):
    """Coordination board summary: counts, active agents."""
    try:
        from skcapstone.context_loader import gather_context

        ctx = gather_context(_agent_home(), memory_limit=0)
        return ctx.get("board", {"total": 0, "active_tasks": [], "agents": []})
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/context")
async def get_context(
    fingerprint: str = Depends(require_auth),
    memories: int = Query(10, ge=0, le=50, description="Max memories to include"),
):
    """Full agent context (delegates to gather_context)."""
    try:
        from skcapstone.context_loader import gather_context

        return gather_context(_agent_home(), memory_limit=memories)
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone not installed")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@profile_router.get("/storage")
async def get_storage(fingerprint: str = Depends(require_auth)):
    """Disk usage stats per directory."""
    dirs = {
        "skcapstone": _agent_home(),
        "skmemory": _skmemory_home(),
        "skcomms": _skcomms_home(),
        "capauth": Path("~/.capauth").expanduser(),
    }

    result: dict[str, Any] = {}
    total = 0

    for name, path in dirs.items():
        if path.is_dir():
            size = _dir_size_bytes(path)
            total += size
            result[name] = {
                "path": str(path),
                "size_bytes": size,
                "size_mb": round(size / (1024 * 1024), 1),
            }
        else:
            result[name] = {"path": str(path), "exists": False}

    # Breakdown of known bloat directories
    bloat: dict[str, Any] = {}
    acks_dir = _skcomms_home() / "acks"
    if acks_dir.is_dir():
        ack_size = _dir_size_bytes(acks_dir)
        ack_count = sum(1 for f in acks_dir.iterdir() if f.is_file())
        bloat["acks"] = {
            "path": str(acks_dir),
            "size_mb": round(ack_size / (1024 * 1024), 1),
            "file_count": ack_count,
        }

    seed_dir = _agent_home() / "sync" / "sync" / "outbox"
    if seed_dir.is_dir():
        seed_size = _dir_size_bytes(seed_dir)
        seed_count = sum(1 for f in seed_dir.iterdir() if f.is_file())
        bloat["seeds"] = {
            "path": str(seed_dir),
            "size_mb": round(seed_size / (1024 * 1024), 1),
            "file_count": seed_count,
        }

    comms_dir = _agent_home() / "sync" / "comms" / "outbox"
    if comms_dir.is_dir():
        comms_size = _dir_size_bytes(comms_dir)
        bloat["comms_outbox"] = {
            "path": str(comms_dir),
            "size_mb": round(comms_size / (1024 * 1024), 1),
        }

    result["total_mb"] = round(total / (1024 * 1024), 1)
    result["bloat"] = bloat

    return result


@profile_router.post("/housekeeping")
async def trigger_housekeeping(
    fingerprint: str = Depends(require_auth),
    dry_run: bool = Query(False, description="Preview without deleting"),
):
    """Trigger manual storage pruning."""
    try:
        from skcapstone.housekeeping import run_housekeeping

        results = run_housekeeping(
            skcapstone_home=_agent_home(),
            skcomms_home=_skcomms_home(),
            dry_run=dry_run,
        )
        return results
    except ImportError:
        raise HTTPException(status_code=501, detail="skcapstone housekeeping not available")
    except Exception as exc:
        logger.warning("profile_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dir_size_bytes(path: Path) -> int:
    """Calculate total size of all files in a directory tree."""
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total
