"""Single per-agent path resolver for skcomms storage (coord 119b49f1).

Storage historically mixed three scoping conventions:

* transfers lived at the per-user ``~/.skcapstone/transfers`` (shared by every
  agent on the node),
* the federation inbox write used a hardcoded
  ``~/.skcapstone/agents/<recipient>/comms/inbox`` template that bypassed
  ``SKCOMMS_HOME`` entirely, while ``api._fed_inbox_dir`` computed a different
  base that the code then overrode,
* the message queue and retry outbox defaulted to node-shared directories that
  multiple agent daemons would drain out from under each other.

On a multi-agent node that only worked by convention: a ``SKCOMMS_HOME``
override or a differently named agent tree silently split reads from writes.

This module is now the ONE place these paths are derived. Every reader and
writer (config transport paths, the S2S inbox writer, transfer state, message
queue, retry outbox) resolves through it, so they always agree:

* ``SKCOMMS_HOME`` unset: the legacy skcapstone layout is preserved byte for
  byte (``~/.skcapstone/agents/<agent>/...``, ``~/.skcapstone/transfers``).
* ``SKCOMMS_HOME`` set: ALL per-agent state lives inside that home
  (``$SKCOMMS_HOME/agents/<agent>/...``), so a custom home keeps reader and
  writer paths in a single tree.

Agent names are validated fail-closed before ever touching a path: any
component containing a separator, traversal token, or NUL raises ``ValueError``
(the recipient of a federation envelope is peer-controlled input).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from .home import skcomms_home

logger = logging.getLogger("skcomms.paths")

# Agent selector env vars, in precedence order (matches skcapstone agent
# resolution: SKAGENT primary, SKCAPSTONE_AGENT documented fallback).
AGENT_ENV_VARS = ("SKAGENT", "SKCAPSTONE_AGENT")


def safe_component(name: str, *, what: str = "agent") -> str:
    """Validate a single path component, failing closed on anything unsafe.

    Recipient/agent names are formatted into filesystem paths; some of them
    (the ``to_fqid`` of a federation envelope) are peer-controlled. A value
    like ``../../evil`` must never resolve outside the storage tree.

    Args:
        name: The candidate component.
        what: Label used in the error message.

    Returns:
        The validated component (stripped).

    Raises:
        ValueError: If the component is empty, is a traversal token, or
            contains a path separator or NUL byte.
    """
    candidate = (name or "").strip()
    if (
        not candidate
        or candidate in (".", "..")
        or "/" in candidate
        or "\\" in candidate
        or "\x00" in candidate
    ):
        raise ValueError(f"invalid {what} name for path scoping: {name!r}")
    return candidate


def resolve_agent(agent: Optional[str] = None) -> Optional[str]:
    """Resolve the acting agent name: explicit arg, then SKAGENT, then fallback.

    Args:
        agent: Explicit agent name; wins when non-empty.

    Returns:
        The validated agent name, or ``None`` when no selector is set (a
        per-user, agentless invocation).

    Raises:
        ValueError: If the selected name is path-unsafe (fail closed rather
            than scoping storage into an attacker- or typo-chosen tree).
    """
    if agent and agent.strip():
        return safe_component(agent)
    for var in AGENT_ENV_VARS:
        value = (os.environ.get(var) or "").strip()
        if value:
            return safe_component(value, what=f"agent ({var})")
    return None


def agents_root() -> Path:
    """Root directory under which per-agent storage trees live.

    With ``SKCOMMS_HOME`` set, per-agent state lives INSIDE that home
    (``$SKCOMMS_HOME/agents``) so reads and writes stay in one tree under a
    custom home. Unset, the legacy skcapstone layout
    (``~/.skcapstone/agents``) is preserved byte for byte.
    """
    if os.environ.get("SKCOMMS_HOME"):
        return skcomms_home() / "agents"
    return Path.home() / ".skcapstone" / "agents"


def agent_dir(agent: Optional[str] = None) -> Path:
    """The storage root for one agent: ``agents_root()/<agent>``.

    Raises:
        ValueError: If no agent can be resolved or the name is path-unsafe.
    """
    name = resolve_agent(agent)
    if not name:
        raise ValueError("no agent resolvable (pass one or set SKAGENT)")
    return agents_root() / name


def agent_comms_dir(agent: Optional[str] = None) -> Path:
    """The agent's comms tree: ``agents_root()/<agent>/comms``."""
    return agent_dir(agent) / "comms"


def agent_comms_inbox(agent: Optional[str] = None) -> Path:
    """The agent's file-transport inbox (the dir its daemon polls)."""
    return agent_comms_dir(agent) / "inbox"


def agent_comms_outbox(agent: Optional[str] = None) -> Path:
    """The agent's file-transport outbox."""
    return agent_comms_dir(agent) / "outbox"


def agent_log_file(agent: Optional[str] = None) -> Path:
    """The agent's transport log file."""
    return agent_dir(agent) / "logs" / "transport.log"


def fed_inbox_base() -> Path:
    """The recipient-less federation landing zone: ``skcomms_home()/inbox``.

    Used when an inbound envelope carries no derivable recipient agent (or a
    path-unsafe one, which fails closed to here). Fixed relative to the home
    so the API write location is deterministic.
    """
    return skcomms_home() / "inbox"


def fed_inbox_dir(recipient: Optional[str] = None) -> Path:
    """The federation inbox directory for an inbound envelope.

    THE single source for where the S2S gate writes and where the recipient
    daemon reads: ``agent_comms_inbox(recipient)`` when a recipient agent is
    known, else :func:`fed_inbox_base`. ``config.load_config`` derives the
    daemon's file-transport ``inbox_path`` from the same helper, so writer and
    reader can never diverge (the historical bug this module removes).

    Args:
        recipient: The recipient agent short name (peer-controlled input).

    Returns:
        The inbox directory (not necessarily created).

    Raises:
        ValueError: If *recipient* is non-empty but path-unsafe.
    """
    if recipient is None or not str(recipient).strip():
        return fed_inbox_base()
    return agent_comms_inbox(safe_component(str(recipient), what="recipient"))


def file_transport_inbox(agent: Optional[str] = None) -> Path:
    """Default FileTransport inbox: the agent's comms inbox when an agent is
    resolvable, else the recipient-less :func:`fed_inbox_base`. Keeps an
    unconfigured transport reading exactly where the S2S gate writes."""
    name = resolve_agent(agent)
    if name:
        return agent_comms_inbox(name)
    return fed_inbox_base()


def file_transport_outbox(agent: Optional[str] = None) -> Path:
    """Default FileTransport outbox: the agent's comms outbox when an agent is
    resolvable, else the legacy node-shared ``skcomms_home()/outbox``."""
    name = resolve_agent(agent)
    if name:
        return agent_comms_outbox(name)
    return skcomms_home() / "outbox"


def transfers_dir(agent: Optional[str] = None) -> Path:
    """Chunked file-transfer state directory, per-agent scoped.

    Per-agent (``agents_root()/<agent>/transfers``) when an agent is
    resolvable, so two agents on one node never share resume state. Falls
    back to the legacy per-user ``~/.skcapstone/transfers`` (or
    ``$SKCOMMS_HOME/transfers`` under a custom home) for agentless callers.
    """
    name = resolve_agent(agent)
    if name:
        return agents_root() / name / "transfers"
    if os.environ.get("SKCOMMS_HOME"):
        return skcomms_home() / "transfers"
    return Path.home() / ".skcapstone" / "transfers"


def queue_dir(agent: Optional[str] = None) -> Path:
    """Persistent message-queue directory, per-agent scoped.

    Per-agent (``agents_root()/<agent>/comms/queue``) when an agent is
    resolvable, so two daemons never drain each other's queue. Falls back to
    the legacy node-shared ``skcomms_home()/queue`` for agentless callers.
    """
    name = resolve_agent(agent)
    if name:
        return agents_root() / name / "comms" / "queue"
    return skcomms_home() / "queue"


def retry_outbox_dir(agent: Optional[str] = None) -> Path:
    """PersistentOutbox (retry store) root.

    Precedence:

    1. ``SKCOMMS_OUTBOX_DIR`` (explicit env override) wins over per-agent
       scoping: an operator or test that pins it relocates the retry store
       there verbatim, regardless of the acting agent. This keeps
       :func:`skcomms.outbox.default_outbox_dir` and a default-constructed
       ``PersistentOutbox`` in agreement (both resolve there when it is set).
    2. Per-agent (``agents_root()/<agent>/comms/outbox-retry``) when an agent is
       resolvable; named distinctly from the file-transport ``comms/outbox`` so
       the retry store's ``pending/dead/archive`` subdirs never mingle with
       envelope files awaiting pickup.
    3. The legacy node-shared ``skcomms_home()/outbox`` for agentless callers.
    """
    env = os.environ.get("SKCOMMS_OUTBOX_DIR")
    if env:
        return Path(env).expanduser()
    name = resolve_agent(agent)
    if name:
        return agents_root() / name / "comms" / "outbox-retry"
    return skcomms_home() / "outbox"


def adopt_legacy_tree(legacy: Path, new: Path, subdirs: tuple[str, ...] = ("",)) -> int:
    """Best-effort one-time move of legacy store entries into a per-agent tree.

    When a store's default location moves from a node-shared directory to a
    per-agent one, entries queued before the upgrade must not be stranded
    (never drained, never retried). This moves the regular files found in
    *legacy* (or its listed *subdirs*) into the same spot under *new* via
    atomic rename. Races between two upgrading daemons are safe: a losing
    rename raises and is skipped, and every entry is pre-signed so whichever
    daemon adopted it can still deliver it.

    Only ever call this with a *legacy* path inside the current
    ``skcomms_home()`` so a custom/temporary home never reaches into real
    production state.

    Args:
        legacy: The old shared directory.
        new: The new per-agent directory.
        subdirs: Relative subdirectories to sweep; ``""`` means the directory
            itself.

    Returns:
        The number of files moved.
    """
    moved = 0
    try:
        if legacy.resolve() == new.resolve() or not legacy.is_dir():
            return 0
    except OSError:
        return 0
    for sub in subdirs:
        src = legacy / sub if sub else legacy
        dst = new / sub if sub else new
        if not src.is_dir():
            continue
        try:
            entries = list(src.iterdir())
        except OSError:
            continue
        for item in entries:
            if not item.is_file():
                continue
            try:
                dst.mkdir(parents=True, exist_ok=True)
                target = dst / item.name
                if target.exists():
                    continue
                item.rename(target)
                moved += 1
            except OSError:
                continue
    if moved:
        logger.info("adopted %d legacy entrie(s) from %s into %s", moved, legacy, new)
    return moved
