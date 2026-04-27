"""Three-tier identity — ``<agent>@<operator>.<realm>``.

Implementation lands across coord tasks T2 (``cd93edb5`` — extend
``identity.json`` with ``realm`` / ``operator`` / ``fqid``) and T3
(``bcf32eea`` — PGP fingerprint as canonical id, TOFU on first contact).

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
