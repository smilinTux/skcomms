"""Three-tier identity — ``<agent>@<operator>.<realm>``.

Implementation lands across coord tasks T2 (``cd93edb5`` — extend
``identity.json`` with ``realm`` / ``operator`` / ``fqid``) and T3
(``bcf32eea`` — PGP fingerprint as canonical id, TOFU on first contact).

T2 update (skos 1fec05a8): resolution delegates to
``capauth.agent_identity.resolve_agent_identity``.  skcomms is a thin
consumer of the capauth resolver.

Tiers
-----
1. ``realm``    — federation/network (``skworld``, ``douno``)
2. ``operator`` — human running this instance (``chef``, ``casey``)
3. ``agent``    — AI persona (``jarvis``, ``lumina``, ``opus``)

Display fqid: ``<agent>@<operator>.<realm>`` (e.g. ``lumina@chef.skworld``).

Canonical identity is the PGP fingerprint at
``~/.skcapstone/agents/<agent>/identity/agent.pub`` — fqid is the
human-readable label, fingerprint is truth. First-message fingerprint
mismatch -> reject (SSH host-key style TOFU).

See also: ``skcomms.cluster`` (cluster.json reader, T1) for the
realm/operator part, sourced from ``~/.skcapstone/cluster.json``.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("skcomms.identity")


def resolve_self_identity(agent: Optional[str] = None) -> dict:
    """Resolve the running agent's full identity (capauth_uri + fqid + fingerprint).

    Delegates to ``capauth.agent_identity.resolve_agent_identity`` — the
    canonical SK resolver (T2).

    Args:
        agent: Short agent name.  ``None`` triggers env-var resolution.

    Returns:
        Dict with keys ``agent``, ``capauth_uri``, ``fqid``, ``fingerprint``.
        ``fqid`` is ``None`` when ``cluster.json`` is absent.

    Examples:
        >>> import os; os.environ["SKAGENT"] = "lumina"
        >>> d = resolve_self_identity()
        >>> d["capauth_uri"]
        'capauth:lumina@skworld.io'
    """
    try:
        from capauth.agent_identity import resolve_agent_identity

        ident = resolve_agent_identity(agent)
        return ident.to_dict()
    except Exception as exc:
        logger.debug("capauth resolver unavailable: %s", exc)

    # Minimal fallback (capauth not installed)
    import os

    name = agent or os.environ.get("SKAGENT") or "local"
    return {
        "agent": name,
        "capauth_uri": f"capauth:{name}@skworld.io",
        "fqid": None,
        "fingerprint": None,
    }
