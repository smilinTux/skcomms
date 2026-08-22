"""cluster.json schema + reader helper (coord task T1, ``76d9b519``).

``cluster.json`` defines the sovereign realm topology: the operator name,
the realm name, and the operator's PGP fingerprint. It is the source for the
``<operator>.<realm>`` portion of every fqid (``<agent>@<operator>.<realm>``).

Real-world example (``~/.skcapstone/cluster.json``)::

    {
      "realm": "skworld.io",
      "operator": "chef",
      "operator_pubkey_fingerprint": "D8920EA86742260161A220C30355DE4AA63CCD69",
      "created_at": "2026-06-10T00:00:00+00:00"
    }

Lookup order (first match wins):

1. explicit ``path=`` argument
2. ``$SKCOMMS_CLUSTER_JSON`` environment override
3. ``/etc/skcapstone/cluster.json``
4. ``~/.skcapstone/cluster.json``

Two readers are provided:

* :func:`load_cluster` returns the raw parsed ``dict`` (or ``None`` when
  absent). It is lenient and never raises on a missing file, preserving the
  behaviour the ``get_realm`` / ``get_operator`` helpers rely on.
* :func:`load_cluster_config` returns a validated :class:`ClusterConfig`
  typed object and raises :class:`ClusterConfigError` with a clear message on
  a missing file, malformed JSON, or a schema violation.

Four convenience accessors sit on top of these two readers:

* :func:`get_realm` / :func:`get_operator` are lenient (default on failure).
  Use them only for display, logging, or network-target selection, where a
  wrong value degrades to a failed lookup.
* :func:`require_realm` / :func:`require_operator` are strict (raise
  :class:`ClusterConfigError` on failure). Use them at every call site that
  mints or persists an identity: fqid construction, capauth pairing,
  on-disk identity paths, signed federation directories.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

logger = logging.getLogger("skcomms.cluster")

#: Environment variable that overrides the cluster.json search path.
CLUSTER_ENV_VAR = "SKCOMMS_CLUSTER_JSON"

#: Default cluster.json search path, first match wins. Public so error
#: messages at every call site name the exact paths that were searched.
CLUSTER_LOOKUP_PATHS = [
    Path("/etc/skcapstone/cluster.json"),
    Path.home() / ".skcapstone" / "cluster.json",
]

#: Backwards-compatible private alias for CLUSTER_LOOKUP_PATHS.
_CLUSTER_LOOKUP = CLUSTER_LOOKUP_PATHS

_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


class ClusterConfigError(ValueError):
    """Raised when cluster.json is missing, unreadable, or fails validation."""


class ClusterConfig(BaseModel):
    """Schema for ``cluster.json``.

    Only ``realm`` and ``operator`` are required; the fingerprint and
    creation timestamp are optional (older cluster files omit them).

    Attributes:
        realm:    Realm name, e.g. ``"skworld.io"``.
        operator: Operator name, e.g. ``"chef"``.
        operator_pubkey_fingerprint: 40-hex PGP fingerprint of the operator
            key, when present.
        created_at: ISO-8601 creation timestamp, when present.
    """

    model_config = ConfigDict(extra="allow")

    realm: str = Field(min_length=1)
    operator: str = Field(min_length=1)
    operator_pubkey_fingerprint: Optional[str] = None
    created_at: Optional[str] = None

    @field_validator("realm", "operator")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    @field_validator("operator_pubkey_fingerprint")
    @classmethod
    def _valid_fingerprint(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not _FINGERPRINT_RE.match(value):
            raise ValueError("operator_pubkey_fingerprint must be a 40-char hex string")
        return value


def _resolve_path(path: Optional[Union[Path, str]] = None) -> Optional[Path]:
    """Resolve the cluster.json path to use, honouring env override + defaults.

    An explicit ``path`` is authoritative: it is used exactly as given and
    never falls back to the env override or default list (so a caller that
    names a file does not silently get a different one). Only when ``path`` is
    ``None`` do the ``$SKCOMMS_CLUSTER_JSON`` override and default list apply.

    Args:
        path: Explicit path (authoritative). ``None`` consults the
            ``$SKCOMMS_CLUSTER_JSON`` env override, then the default list.

    Returns:
        The resolved existing ``Path``, or ``None`` when none exist.
    """
    if path is not None:
        candidate = Path(path)
        return candidate if candidate.exists() else None

    candidates: list[Path] = []
    env_override = os.environ.get(CLUSTER_ENV_VAR)
    if env_override:
        candidates.append(Path(env_override))
    candidates.extend(_CLUSTER_LOOKUP)

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def load_cluster(path: Optional[Union[Path, str]] = None) -> Optional[dict]:
    """Load cluster.json as a raw dict from the standard search path.

    Lenient reader: returns ``None`` when no file exists and swallows parse
    errors (logged at debug). Use :func:`load_cluster_config` when you want a
    validated, typed object with clear errors.

    Args:
        path: Optional explicit path. Falls back to ``$SKCOMMS_CLUSTER_JSON``
            then the default lookup list.

    Returns:
        Parsed cluster dict, or ``None`` if no cluster.json is found or it is
        unparseable.

    Examples:
        >>> data = load_cluster()
        >>> data["realm"] if data else "skworld"
        'skworld'
    """
    resolved = _resolve_path(path)
    if resolved is None:
        return None
    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("cluster.json parse error at %s: %s", resolved, exc)
        return None


def load_cluster_config(path: Optional[Union[Path, str]] = None) -> ClusterConfig:
    """Load and validate cluster.json into a typed :class:`ClusterConfig`.

    Strict reader: resolves the canonical path (explicit ``path`` >
    ``$SKCOMMS_CLUSTER_JSON`` > default lookup), parses, and validates against
    the schema. Raises :class:`ClusterConfigError` with a clear message on a
    missing file, malformed JSON, or a schema violation.

    Args:
        path: Optional explicit path. Falls back to ``$SKCOMMS_CLUSTER_JSON``
            then the default lookup list.

    Returns:
        A validated :class:`ClusterConfig`.

    Raises:
        ClusterConfigError: No cluster.json found, unreadable file, invalid
            JSON, or the contents fail schema validation.

    Examples:
        >>> cfg = load_cluster_config()   # doctest: +SKIP
        >>> cfg.realm                     # doctest: +SKIP
        'skworld.io'
    """
    resolved = _resolve_path(path)
    if resolved is None:
        searched = path or os.environ.get(CLUSTER_ENV_VAR) or _CLUSTER_LOOKUP
        raise ClusterConfigError(f"cluster.json not found (searched: {searched})")
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ClusterConfigError(f"cluster.json at {resolved} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ClusterConfigError(f"cluster.json at {resolved} could not be read: {exc}") from exc
    try:
        return ClusterConfig.model_validate(raw)
    except ValidationError as exc:
        raise ClusterConfigError(f"cluster.json at {resolved} failed validation: {exc}") from exc


def get_realm() -> str:
    """Return the realm name (default: ``"skworld"``).

    Lenient: never raises, even when cluster.json is missing or malformed.
    This is safe only for display/logging/network-target-selection callers,
    where a wrong-but-plausible value degrades to a failed lookup rather than
    a wrongly minted identity. Any call site that constructs or persists an
    identity (an fqid, a capauth pairing record, an on-disk identity path, a
    signed federation directory) must use :func:`require_realm` instead, so a
    missing config fails loudly rather than silently minting a short realm.
    """
    data = load_cluster()
    if data:
        return str(data.get("realm", "skworld"))
    return "skworld"


def get_operator() -> str:
    """Return the operator name (default: ``"chef"``).

    Lenient: see :func:`get_realm` for the strict/lenient split rationale.
    Any call site that constructs or persists an identity must use
    :func:`require_operator` instead.
    """
    data = load_cluster()
    if data:
        return str(data.get("operator", "chef"))
    return "chef"


def require_realm() -> str:
    """Return the realm name, refusing to default on a missing/invalid config.

    Strict counterpart to :func:`get_realm`. Every identity-minting call site
    (fqid construction, capauth pairing, on-disk identity paths, signed
    federation directories) must call this instead of :func:`get_realm`: a
    missing or unreadable cluster.json must fail loudly, never silently mint
    an identity under the wrong realm. (Coord card 076d49cd: a missing
    cluster.json minted ``chef.skworld`` in place of the real
    ``chef.skworld.io``, landing 58 wrong fqids in the live capauth pairing
    store before this was caught.)

    Returns:
        The realm name from a validated cluster.json.

    Raises:
        ClusterConfigError: cluster.json is missing, unreadable, malformed,
            or fails schema validation. The message names the searched
            paths.
    """
    return load_cluster_config().realm


def require_operator() -> str:
    """Return the operator name, refusing to default on a missing/invalid config.

    Strict counterpart to :func:`get_operator`. See :func:`require_realm` for
    the rationale; use this at every identity-minting call site.

    Returns:
        The operator name from a validated cluster.json.

    Raises:
        ClusterConfigError: cluster.json is missing, unreadable, malformed,
            or fails schema validation. The message names the searched
            paths.
    """
    return load_cluster_config().operator
