"""
Adapter factory + config→registry builder (Tier 3 runtime plumbing).

Mirrors the ``BUILTIN_TRANSPORTS`` pattern in ``core.py``: a registry of
``adapter_type → constructor`` plus a builder that reads the ``adapters:`` block
of ``~/.skcomms/config.yml``, expands ``${ENV_VAR}`` placeholders, and constructs
each *enabled* adapter — gracefully skipping any whose required token is missing
(the GATED-friendly path, so the daemon never crashes without creds).

Constructor shapes (discovered, NOT assumed):
  - ``TelegramAdapter(config: dict, ...)``
  - ``DiscordAdapter(config: dict, ...)``   # config-dict, NOT a bare token
  - ``SlackAdapter(config: dict, ...)``
  - ``MatrixAdapter(config: dict, ...)``
  - ``FakeAdapter(config: dict)``

All four real adapters take a config dict as their first positional arg, so the
factory uses the uniform ``Class(config)`` path for every type.

Spec: docs/superpowers/plans/2026-06-13-tier3-adapter-runtime.md (Task 2)
"""

from __future__ import annotations

import os
import re
from typing import Optional

from .base import ChannelAdapter
from .discord import DiscordAdapter
from .fake import FakeAdapter
from .matrix import MatrixAdapter
from .registry import AdapterRegistry
from .slack import SlackAdapter
from .telegram import TelegramAdapter

# adapter_type → constructor (callable taking a single config dict).
BUILTIN_ADAPTERS: dict[str, type[ChannelAdapter]] = {
    "telegram": TelegramAdapter,
    "discord": DiscordAdapter,
    "slack": SlackAdapter,
    "matrix": MatrixAdapter,
    "fake": FakeAdapter,
}

# adapter_type → the config field that must be non-empty for the adapter to be
# usable.  ``None`` means "no credential required" (e.g. the fake adapter).
REQUIRED_TOKEN_FIELD: dict[str, Optional[str]] = {
    "telegram": "bot_token",
    "discord": "bot_token",
    "slack": "bot_token",
    "matrix": "access_token",
    "fake": None,
}

_ENV_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def expand_env(config: dict) -> dict:
    """Return a copy of *config* with ``${VAR}`` string values substituted.

    A string value that exactly matches ``${VAR}`` is replaced with
    ``os.environ.get(VAR, "")``.  Nested dicts are recursed one level deep.
    All other values are left untouched.
    """
    out: dict = {}
    for key, value in config.items():
        if isinstance(value, str):
            m = _ENV_PLACEHOLDER.match(value)
            out[key] = os.environ.get(m.group(1), "") if m else value
        elif isinstance(value, dict):
            out[key] = {
                k: (
                    os.environ.get(_ENV_PLACEHOLDER.match(v).group(1), "")
                    if isinstance(v, str) and _ENV_PLACEHOLDER.match(v)
                    else v
                )
                for k, v in value.items()
            }
        else:
            out[key] = value
    return out


def build_adapter(adapter_type: str, config: dict) -> ChannelAdapter:
    """Construct a single adapter of *adapter_type* from *config*.

    Expands ``${ENV_VAR}`` placeholders first, then constructs the class.  All
    built-in adapters share the ``Class(config)`` constructor shape.

    Raises:
        ValueError: If *adapter_type* is not a known adapter.
    """
    cls = BUILTIN_ADAPTERS.get(adapter_type)
    if cls is None:
        raise ValueError(f"unknown adapter type {adapter_type!r}")
    return cls(expand_env(config))


def build_registry_from_config(
    cfg: dict,
    *,
    registry: Optional[AdapterRegistry] = None,
) -> tuple[AdapterRegistry, list[str], list[str]]:
    """Build an :class:`AdapterRegistry` from the ``adapters:`` config block.

    For each entry under ``cfg["adapters"]``:
      - Skip if ``enabled is False``.
      - Skip (token-gated) if the type's required token field is empty after
        env-expansion — this is the GATED path and never raises.
      - Otherwise build the adapter and register it.

    The registry is created with no hub/handler (lightweight mode); callers that
    need dispatch can pass their own pre-constructed *registry*.

    Returns:
        ``(registry, built_adapter_names, skipped_types)``.
    """
    if registry is None:
        registry = AdapterRegistry()

    built: list[str] = []
    skipped: list[str] = []

    for adapter_type, raw in cfg.get("adapters", {}).items():
        entry = raw or {}
        if entry.get("enabled") is False:
            skipped.append(adapter_type)
            continue

        if adapter_type not in BUILTIN_ADAPTERS:
            skipped.append(adapter_type)
            continue

        expanded = expand_env(entry)
        token_field = REQUIRED_TOKEN_FIELD.get(adapter_type, "bot_token")
        if token_field is not None and not expanded.get(token_field):
            skipped.append(adapter_type)
            continue

        adapter = build_adapter(adapter_type, entry)
        registry.register(adapter)
        built.append(adapter.adapter_name)

    return registry, built, skipped
