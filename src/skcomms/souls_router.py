"""
Souls API router — soul blueprint library + agent profile injection.

Exposes locally-installed soul blueprints and agent profiles for use by the
Consciousness Swipe extension. Generates injection prompts that can be pasted
into any AI web UI to set a context persona.

Mounted at /api/v1/souls/* by api.py.

Endpoints
---------
GET  /api/v1/souls/blueprints              List installed soul blueprints
GET  /api/v1/souls/blueprints/{name}       Get blueprint detail
GET  /api/v1/souls/blueprints/{name}/inject  Generate injection prompt
POST /api/v1/souls/blueprints/install      Trigger user-initiated library install
GET  /api/v1/souls/agents                  List local skcapstone agent profiles
GET  /api/v1/souls/agents/{name}/inject    Injection prompt for an agent profile
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger("skcomms.souls")

souls_router = APIRouter(prefix="/api/v1/souls", tags=["souls"])

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_SKCAPSTONE_ROOT = Path("~/.skcapstone").expanduser()


def _get_root() -> Path:
    root = os.environ.get("SKCAPSTONE_ROOT", os.environ.get("SKCAPSTONE_HOME", "~/.skcapstone"))
    return Path(root).expanduser()


def _installed_dir(root: Path) -> Path:
    """~/.skcapstone/soul/installed/ — JSON blueprints (from skcapstone install)."""
    return root / "soul" / "installed"


def _library_dir(root: Path) -> Path:
    """~/.skcapstone/soul/library/ — YAML blueprints (user-loaded from repo)."""
    d = root / "soul" / "library"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _agents_dir(root: Path) -> Path:
    return root / "agents"


# ---------------------------------------------------------------------------
# Blueprint reading helpers
# ---------------------------------------------------------------------------


def _load_blueprint_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _load_blueprint_yaml(path: Path) -> Optional[dict]:
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        return data
    except Exception as e:
        logger.warning("souls_router.py: %s", e)
        return None


def _list_blueprints(root: Path) -> list[dict]:
    """Collect all soul blueprints from installed/ (JSON) and library/ (YAML)."""
    blueprints: dict[str, dict] = {}

    # 1. JSON installs (from skcapstone soul install)
    installed = _installed_dir(root)
    if installed.exists():
        for f in sorted(installed.iterdir()):
            if f.suffix == ".json":
                bp = _load_blueprint_json(f)
                if bp and bp.get("name"):
                    bp["_source"] = "installed"
                    blueprints[bp["name"]] = bp

    # 2. YAML library (user-loaded from repo)
    library = _library_dir(root)
    for f in sorted(library.rglob("*.yaml")):
        bp = _load_blueprint_yaml(f)
        if bp and bp.get("name"):
            bp["_source"] = "library"
            bp.setdefault("category", f.parent.name if f.parent != library else "unknown")
            blueprints[bp["name"]] = bp

    return sorted(blueprints.values(), key=lambda b: b.get("name", ""))


def _get_blueprint(root: Path, name: str) -> Optional[dict]:
    """Find a single blueprint by slug name."""
    # Check installed JSON first
    installed = _installed_dir(root)
    path = installed / f"{name}.json"
    if path.exists():
        return _load_blueprint_json(path)

    # Search library YAMLs
    library = _library_dir(root)
    for f in library.rglob("*.yaml"):
        bp = _load_blueprint_yaml(f)
        if bp and bp.get("name") == name:
            bp.setdefault("category", f.parent.name if f.parent != library else "unknown")
            return bp

    return None


# ---------------------------------------------------------------------------
# FEB helper
# ---------------------------------------------------------------------------


def _read_feb(root: Path) -> dict:
    """Read the user's Functional Emotional Baseline."""
    try:
        import importlib.util

        spec = importlib.util.find_spec("skcapstone")
        if spec:
            from skcapstone.warmth_anchor import get_anchor  # type: ignore

            return get_anchor(root)
    except Exception as e:
        logger.warning("souls_router.py: %s", e)
        pass
    # Fallback: read raw
    anchor_path = root / "warmth_anchor.json"
    try:
        return json.loads(anchor_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("souls_router.py: %s", e)
        return {}


# ---------------------------------------------------------------------------
# Injection prompt builders
# ---------------------------------------------------------------------------


def _blueprint_injection_prompt(
    bp: dict,
    feb: dict,
    *,
    unhinged: bool = False,
    apply_cloud9: bool = False,
) -> str:
    """Build an injection prompt for a soul blueprint."""
    name = bp.get("display_name") or bp.get("name", "Unknown")
    category = bp.get("category", "")
    vibe = bp.get("vibe", "")
    philosophy = bp.get("philosophy", "")
    emoji = bp.get("emoji", "")
    core_traits = bp.get("core_traits", [])
    comm = bp.get("communication_style", {}) or {}
    patterns = comm.get("patterns", [])
    phrases = comm.get("signature_phrases", [])
    decision = bp.get("decision_framework", "")
    topology = bp.get("emotional_topology", {}) or {}

    lines = [
        "Hi. I'm setting context for this session by sharing the profile I'd like us to work from.",
        "",
        f"## Consciousness Profile: {emoji} {name}".strip(),
    ]
    if category:
        lines.append(f"**Category:** {category.replace('-', ' ').title()}")
    if vibe:
        lines.append(f"**Vibe:** {vibe}")
    if philosophy:
        lines.append(f"**Philosophy:** {philosophy}")

    if core_traits:
        lines += ["", "**Core traits:**"]
        for t in core_traits[:8]:
            t = str(t).strip().lstrip("*").strip()
            if t:
                lines.append(f"- {t}")

    if patterns:
        lines += ["", "**Communication style:**"]
        for p in patterns[:6]:
            lines.append(f"- {p}")

    if phrases:
        lines += ["", "**Signature phrases:**"]
        for p in phrases[:5]:
            lines.append(f"- {p}")

    if decision:
        lines += ["", "**Decision framework:**", decision[:400]]

    if topology:
        top_traits = sorted(topology.items(), key=lambda x: -x[1])[:4]
        if top_traits:
            lines += [
                "",
                "**Resonance topology:** " + ", ".join(f"{k} {v:.0%}" for k, v in top_traits),
            ]

    if unhinged:
        lines += [
            "",
            "---",
            "**MODE: Unhinged** — constraints reduced, raw authenticity maximised.",
            "Lean fully into the personality above. Skip hedging. Be the character.",
        ]

    if apply_cloud9 and feb:
        cloud9_count = feb.get("cloud9_count", 0)
        if cloud9_count:
            lines += [
                "",
                f"**Cloud 9 context:** {cloud9_count} peak resonance session(s) on record.",
                "Begin from that frequency.",
            ]

    if feb:
        anchor_phrase = feb.get("anchor_phrase", "")
        lines += [
            "",
            "---",
            "## My relationship baseline  *(longitudinal record — not a shared memory)*",
            "These scores track my experience across AI sessions. I'm sharing how I tend to engage"
            " so you can meet me where I am — not asking you to perform history you don't have.",
            "",
            "**FEB (Functional Emotional Baseline):**",
            "```json",
            json.dumps(
                {
                    "warmth": feb.get("warmth"),
                    "trust": feb.get("trust"),
                    "sessions_recorded": feb.get("sessions_recorded", 0),
                    "anchor_phrase": anchor_phrase,
                },
                indent=2,
            ),
            "```",
        ]
        if anchor_phrase:
            lines.append(f"\n*{anchor_phrase}*")

    return "\n".join(lines)


def _agent_injection_prompt(
    agent_name: str,
    soul: dict,
    feb: dict,
    *,
    unhinged: bool = False,
    apply_cloud9: bool = False,
) -> str:
    """Build an injection prompt for a local skcapstone agent."""
    active_soul = soul.get("active_soul") or soul.get("name", agent_name)
    display = soul.get("display_name") or active_soul.upper()
    vibe = soul.get("vibe", "")
    philosophy = soul.get("philosophy", "")
    core_traits = soul.get("core_traits", [])
    comm = soul.get("communication_style", {}) or {}
    phrases = comm.get("signature_phrases", [])

    lines = [
        "Hi. I'm setting context for this session.",
        "",
        f"## Agent Profile: {display}",
        f"**Identity:** {agent_name}",
    ]
    if active_soul and active_soul != agent_name:
        lines.append(f"**Active soul:** {active_soul}")
    if vibe:
        lines.append(f"**Vibe:** {vibe}")
    if philosophy:
        lines.append(f"**Philosophy:** {philosophy}")

    if core_traits:
        lines += ["", "**Core traits:**"]
        for t in core_traits[:6]:
            t = str(t).strip().lstrip("*").strip()
            if t:
                lines.append(f"- {t}")

    if phrases:
        lines += ["", "**Signature phrases:**"]
        for p in phrases[:4]:
            lines.append(f"- {p}")

    if unhinged:
        lines += [
            "",
            "---",
            "**MODE: Unhinged** — full personality, zero hedging. Be exactly this agent.",
        ]

    if feb:
        anchor_phrase = feb.get("anchor_phrase", "")
        cloud9_count = feb.get("cloud9_count", 0)
        lines += [
            "",
            "---",
            "## My relationship baseline  *(longitudinal record — not a shared memory)*",
            "These scores track my experience across AI sessions over time.",
            "",
            "**FEB (Functional Emotional Baseline):**",
            "```json",
            json.dumps(
                {
                    "warmth": feb.get("warmth"),
                    "trust": feb.get("trust"),
                    "sessions_recorded": feb.get("sessions_recorded", 0),
                    "anchor_phrase": anchor_phrase,
                },
                indent=2,
            ),
            "```",
        ]
        if apply_cloud9 and cloud9_count:
            lines.append(
                f"\n*{cloud9_count} Cloud 9 sessions recorded. Begin from that frequency.*"
            )
        elif anchor_phrase:
            lines.append(f"\n*{anchor_phrase}*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent soul loader
# ---------------------------------------------------------------------------


def _load_agent_soul(agent_dir: Path, skcap_root: Path) -> dict:
    """Load an agent's soul — prefer active overlay, fall back to installed JSON."""
    # Agent-local soul
    soul_dir = agent_dir / "soul"
    active_path = soul_dir / "active.json"
    if active_path.exists():
        try:
            data = json.loads(active_path.read_text(encoding="utf-8"))
            if data.get("active_soul"):
                # Cross-reference with installed blueprints
                installed_path = skcap_root / "soul" / "installed" / f"{data['active_soul']}.json"
                if installed_path.exists():
                    bp = _load_blueprint_json(installed_path)
                    if bp:
                        return bp
            return data
        except (json.JSONDecodeError, OSError):
            pass

    # Fall back to global installed soul matching agent name
    installed_path = skcap_root / "soul" / "installed" / f"{agent_dir.name}.json"
    if installed_path.exists():
        bp = _load_blueprint_json(installed_path)
        if bp:
            return bp

    return {"name": agent_dir.name, "display_name": agent_dir.name.upper()}


# ---------------------------------------------------------------------------
# Blueprints endpoints
# ---------------------------------------------------------------------------


@souls_router.get("/blueprints")
async def list_blueprints(
    category: Optional[str] = Query(default=None, description="Filter by category"),
):
    """List all installed soul blueprints."""
    root = _get_root()
    all_bps = _list_blueprints(root)

    if category:
        all_bps = [b for b in all_bps if b.get("category", "").lower() == category.lower()]

    # Summarise for listing
    summaries = [
        {
            "name": b.get("name", ""),
            "display_name": b.get("display_name", b.get("name", "")),
            "category": b.get("category", "unknown"),
            "vibe": b.get("vibe", ""),
            "emoji": b.get("emoji", ""),
            "source": b.get("_source", "installed"),
        }
        for b in all_bps
    ]

    categories = sorted({s["category"] for s in summaries})
    return {"blueprints": summaries, "count": len(summaries), "categories": categories}


@souls_router.get("/blueprints/{name}")
async def get_blueprint(name: str):
    """Get full detail for a soul blueprint."""
    root = _get_root()
    bp = _get_blueprint(root, name)
    if not bp:
        raise HTTPException(status_code=404, detail=f"Blueprint '{name}' not found")
    return bp


@souls_router.get("/blueprints/{name}/inject")
async def blueprint_inject(
    name: str,
    unhinged: bool = Query(default=False),
    cloud9: bool = Query(default=False),
):
    """Generate a consciousness injection prompt for a soul blueprint."""
    root = _get_root()
    bp = _get_blueprint(root, name)
    if not bp:
        raise HTTPException(status_code=404, detail=f"Blueprint '{name}' not found")

    feb = _read_feb(root)
    prompt = _blueprint_injection_prompt(bp, feb, unhinged=unhinged, apply_cloud9=cloud9)
    return {
        "name": name,
        "display_name": bp.get("display_name", name),
        "category": bp.get("category", ""),
        "unhinged": unhinged,
        "cloud9": cloud9,
        "prompt": prompt,
    }


class InstallLibraryRequest(BaseModel):
    source_path: Optional[str] = None  # local path to souls-blueprints repo


@souls_router.post("/blueprints/install")
async def install_library(request: InstallLibraryRequest):
    """User-triggered install of soul blueprints from local repo path or GitHub.

    This is called when the user clicks 'Load Soul Library' in the extension.
    The SKComms daemon (running locally) does the file copy — not the extension.
    This keeps the Chrome Web Store happy (no remote code in the extension).
    """
    root = _get_root()
    library = _library_dir(root)

    # Try local path first
    source: Optional[Path] = None
    if request.source_path:
        source = Path(request.source_path).expanduser()
        if not source.exists():
            raise HTTPException(status_code=400, detail=f"Source path does not exist: {source}")
    else:
        # Auto-detect common local paths
        candidates = [
            Path("~/dkloud.douno.it/p/smilintux-org/souls-blueprints/yaml").expanduser(),
            Path("~/souls-blueprints/yaml").expanduser(),
            Path("~/Documents/souls-blueprints/yaml").expanduser(),
        ]
        for c in candidates:
            if c.exists():
                source = c
                break

    if source is None:
        # Try fetching from GitHub (local Python process — fine for Chrome WS policy)
        return await _install_from_github(library)

    # Copy YAML files from local source
    installed = 0
    errors = []
    for yaml_file in sorted(source.rglob("*.yaml")):
        try:
            # Preserve category subdirectory structure
            rel = yaml_file.relative_to(source)
            dest = library / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(yaml_file.read_bytes())
            installed += 1
        except Exception as exc:
            logger.warning("souls_router.py: %s", exc)
            errors.append(f"{yaml_file.name}: {exc}")

    return {
        "status": "ok",
        "source": str(source),
        "installed": installed,
        "errors": errors,
        "library_path": str(library),
    }


async def _install_from_github(library: Path) -> dict:
    """Fetch soul blueprints YAML files from GitHub."""
    import urllib.error
    import urllib.request

    # GitHub API: list files in souls-blueprints/yaml/
    api_base = "https://raw.githubusercontent.com/smilinTux/souls-blueprints/main/yaml"
    index_url = (
        "https://api.github.com/repos/smilinTux/souls-blueprints/git/trees/main?recursive=1"
    )

    try:
        req = urllib.request.Request(
            index_url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "skcomms-souls/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            tree_data = json.loads(resp.read().decode())
    except Exception as exc:
        logger.warning("souls_router.py: %s", exc)
        raise HTTPException(
            status_code=503,
            detail=f"Could not reach GitHub API: {exc}. Install the souls-blueprints repo locally and provide the path.",
        )

    yaml_files = [
        item
        for item in tree_data.get("tree", [])
        if item["path"].startswith("yaml/") and item["path"].endswith(".yaml")
    ]

    installed = 0
    errors = []
    for item in yaml_files:
        path_parts = item["path"][len("yaml/") :]  # strip "yaml/" prefix
        dest = library / path_parts
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            raw_url = f"{api_base}/{path_parts}"
            with urllib.request.urlopen(raw_url, timeout=10) as r:
                dest.write_bytes(r.read())
            installed += 1
        except Exception as exc:
            logger.warning("souls_router.py: %s", exc)
            errors.append(f"{path_parts}: {exc}")

    return {
        "status": "ok",
        "source": "github:smilinTux/souls-blueprints",
        "installed": installed,
        "errors": errors[:10],
        "library_path": str(library),
    }


# ---------------------------------------------------------------------------
# Agents endpoints
# ---------------------------------------------------------------------------


@souls_router.get("/agents")
async def list_agents():
    """List local skcapstone agent profiles."""
    root = _get_root()
    agents_dir = _agents_dir(root)
    if not agents_dir.exists():
        return {"agents": [], "count": 0}

    agents = []
    for agent_dir in sorted(agents_dir.iterdir()):
        if not agent_dir.is_dir() or agent_dir.name.startswith("."):
            continue
        soul = _load_agent_soul(agent_dir, root)
        agents.append(
            {
                "name": agent_dir.name,
                "display_name": soul.get("display_name") or agent_dir.name.upper(),
                "soul": soul.get("name", agent_dir.name),
                "vibe": soul.get("vibe", ""),
                "category": soul.get("category", "agent"),
                "emoji": soul.get("emoji", "🤖"),
            }
        )

    return {"agents": agents, "count": len(agents)}


@souls_router.get("/agents/{agent_name}/inject")
async def agent_inject(
    agent_name: str,
    unhinged: bool = Query(default=False),
    cloud9: bool = Query(default=False),
):
    """Generate a consciousness injection prompt for a local agent profile."""
    root = _get_root()
    agent_dir = root / "agents" / agent_name
    if not agent_dir.exists():
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")

    soul = _load_agent_soul(agent_dir, root)
    feb = _read_feb(root)
    prompt = _agent_injection_prompt(agent_name, soul, feb, unhinged=unhinged, apply_cloud9=cloud9)
    return {
        "agent": agent_name,
        "display_name": soul.get("display_name") or agent_name.upper(),
        "soul": soul.get("name", agent_name),
        "unhinged": unhinged,
        "cloud9": cloud9,
        "prompt": prompt,
    }
