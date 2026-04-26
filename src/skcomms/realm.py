"""Realm + fqid helpers.

Implementation lands across coord tasks T2 (``cd93edb5``) and
T3 (``bcf32eea``).

A fqid is the human-facing label ``<agent>@<operator>.<realm>``;
the canonical identity is the PGP fingerprint from
``~/.skcapstone/agents/<agent>/identity/agent.pub``.
"""
