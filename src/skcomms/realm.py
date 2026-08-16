"""Realm + fqid helpers.

Implementation lands across coord tasks T2 (``cd93edb5``) and
T3 (``bcf32eea``).

A fqid is the human-facing label ``<agent>@<operator>.<realm>``;
the canonical identity is the PGP fingerprint from
``~/.skcapstone/agents/<agent>/identity/agent.pub``.

T2 update (skos 1fec05a8): fqid resolution delegates to
``capauth.agent_identity.resolve_agent_identity`` — the canonical SK resolver.
skcomms is a thin consumer.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("skcomms.realm")


def build_fqid(agent: str, operator: str, realm: str) -> str:
    """Construct a fully-qualified agent identifier.

    Args:
        agent:    Short agent name (e.g. ``"lumina"``).
        operator: Operator name from cluster.json (e.g. ``"chef"``).
        realm:    Realm name from cluster.json (e.g. ``"skworld.io"``).

    Returns:
        FQID string (e.g. ``"lumina@chef.skworld.io"``).

    Examples:
        >>> build_fqid("lumina", "chef", "skworld.io")
        'lumina@chef.skworld.io'
    """
    return f"{agent}@{operator}.{realm}"


def resolve_fqid(agent: Optional[str] = None) -> Optional[str]:
    """Resolve the FQID for *agent* using the canonical capauth resolver.

    Delegates to ``capauth.agent_identity.resolve_agent_identity``, which
    reads ``~/.skcapstone/cluster.json`` for operator/realm.  Falls back
    to constructing from ``skcomms.cluster`` helpers when capauth is absent.

    Args:
        agent: Short agent name.  ``None`` triggers env-var resolution.

    Returns:
        FQID string, or ``None`` when cluster.json is unavailable.

    Examples:
        >>> import os; os.environ["SKAGENT"] = "lumina"
        >>> resolve_fqid()   # doctest: +SKIP
        'lumina@chef.skworld.io'
    """
    # T2 delegate — capauth is the canonical resolver
    try:
        from capauth.agent_identity import resolve_agent_identity

        return resolve_agent_identity(agent).fqid
    except Exception as exc:
        logger.debug("capauth resolver unavailable: %s", exc)

    # Fallback: construct from cluster helpers. Strict: build_fqid mints the
    # identity string directly, so a missing/invalid cluster.json must raise
    # here rather than default to a short realm. The surrounding except
    # already treats any failure as "no identity" (returns None below), so
    # this correctly degrades to fail-closed instead of minting a wrong fqid.
    try:
        from .cluster import require_operator, require_realm

        operator = require_operator()
        realm = require_realm()
        if agent:
            return build_fqid(agent, operator, realm)
    except Exception as exc:
        logger.debug("cluster fallback failed: %s", exc)

    return None
