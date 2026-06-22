"""Configuration for the sk-access MCP server (P7 / A2).

Carries the **security-critical knobs**: the tailnet bind address, the
exposed-root allowlist + hard-denied secret paths, the per-identity scope
grants, and the dev-bypass flag (OFF by default).

Sources, in order of precedence:
    1. explicit kwargs to :meth:`AccessConfig.load`
    2. environment (``SK_ACCESS_*``)
    3. ``~/.skcapstone/skcomms/access.yml`` (``access:`` block)
    4. built-in sovereign defaults

The bind address defaults to this node's tailscale 100.x IP. If tailscale is
unavailable the fallback is loopback ``127.0.0.1`` — **never** ``0.0.0.0`` or a
routable public interface, which is refused outright (see
:func:`assert_not_public`).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .registry import Scope

logger = logging.getLogger("skcomms.access.config")

_ACCESS_CONFIG_PATH = Path("~/.skcapstone/skcomms/access.yml")
_DEFAULT_PORT = 9386  # next to skcomms api (9384) / tailscale transport (9385)

# Directories that are HARD-DENIED even if nested under an exposed root.
# (The A4 file tools enforce this; declared here so config is the single
# source of truth.)
DEFAULT_DENY_SUBPATHS: tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    ".skcapstone/agents",  # contains soul / capauth keys / identity
    "identity",
    "cot-pki",
    "capauth",
    ".aws",
    ".config/gcloud",
)

# Default exposed roots — conservative; the operator widens these in access.yml.
DEFAULT_EXPOSED_ROOTS: tuple[str, ...] = ("~/clawd",)


def _detect_tailnet_ip() -> Optional[str]:
    """Return this node's tailscale 100.x IPv4, or ``None`` if unavailable.

    Mirrors :meth:`skcomms.transports.tailscale.TailscaleTransport._detect_local_ip`.
    """
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=3.0,
        )
        if result.returncode == 0:
            ip = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ""
            if ip.startswith("100."):
                return ip
    except FileNotFoundError:
        logger.debug("tailscale binary not found — falling back to loopback bind")
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.debug("tailscale ip -4 failed: %s", exc)
    return None


def is_public_bind(host: str) -> bool:
    """True if ``host`` would expose the server beyond the tailnet/loopback.

    Public = ``0.0.0.0`` / ``::`` (all interfaces) or any globally-routable,
    non-loopback, non-tailnet (non-CGNAT-100.64/10) address. Loopback and
    tailnet (100.64.0.0/10) addresses are allowed.
    """
    h = (host or "").strip()
    if not h or h in ("0.0.0.0", "::", "*"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # A hostname — can't statically prove it's tailnet-only; treat unknown
        # non-loopback names as public to be safe.
        return h not in ("localhost",)
    if ip.is_loopback:
        return False
    # Tailscale/Headscale use the CGNAT range 100.64.0.0/10.
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def assert_not_public(host: str, *, allow_public: bool = False) -> None:
    """Raise unless ``host`` is a safe (tailnet/loopback) bind.

    Args:
        host: The bind address.
        allow_public: Explicit override (operator opt-in only).

    Raises:
        ValueError: If ``host`` is public and ``allow_public`` is False.
    """
    if allow_public:
        logger.warning("sk-access bound to PUBLIC host %s (allow_public override)", host)
        return
    if is_public_bind(host):
        raise ValueError(
            f"refusing to bind sk-access to public host {host!r}: tailnet-only "
            "(set allow_public / SK_ACCESS_ALLOW_PUBLIC=1 to override — not recommended)"
        )


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class AccessConfig:
    """Resolved sk-access server configuration.

    Attributes:
        host: Bind address. Default = tailnet 100.x IP, else ``127.0.0.1``.
            Never ``0.0.0.0`` unless ``allow_public`` is set.
        port: TCP port (default 9386).
        allow_public: Operator override to permit a public bind (default False).
        dev_bypass: Skip capauth verification (LOCAL DEV ONLY, default False).
        exposed_roots: Absolute, expanded directories agents may touch.
        deny_subpaths: Path fragments hard-denied even under an exposed root.
        scope_grants: Map of identity (fqid/name/fingerprint) -> granted scopes.
            ``"*"`` is a wildcard default grant. A verified identity not listed
            falls back to the ``"*"`` grant, else ``{READ}``.
        node_name: This node's short name (for ``node_info`` / skos advert).
        node_fqid: This node's FQID, if resolvable.
    """

    host: str = "127.0.0.1"
    port: int = _DEFAULT_PORT
    allow_public: bool = False
    dev_bypass: bool = False
    exposed_roots: list[Path] = field(default_factory=list)
    deny_subpaths: list[str] = field(default_factory=lambda: list(DEFAULT_DENY_SUBPATHS))
    scope_grants: dict[str, set[Scope]] = field(default_factory=dict)
    node_name: str = "local"
    node_fqid: Optional[str] = None

    # -- construction -------------------------------------------------------

    @classmethod
    def load(
        cls,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        allow_public: Optional[bool] = None,
        dev_bypass: Optional[bool] = None,
        config_path: Optional[Path] = None,
    ) -> "AccessConfig":
        """Build config from kwargs > env > yaml > defaults.

        Args:
            host: Explicit bind host (overrides everything).
            port: Explicit port.
            allow_public: Explicit public-bind override.
            dev_bypass: Explicit dev-bypass override.
            config_path: Alternate ``access.yml`` path (testing).

        Returns:
            A resolved :class:`AccessConfig`. Does NOT itself bind — the server
            calls :meth:`validate` (which refuses public binds) at startup.
        """
        raw = cls._read_yaml(config_path)

        eff_allow_public = (
            allow_public
            if allow_public is not None
            else _env_bool("SK_ACCESS_ALLOW_PUBLIC", bool(raw.get("allow_public", False)))
        )
        eff_dev_bypass = (
            dev_bypass
            if dev_bypass is not None
            else _env_bool("SK_ACCESS_DEV_BYPASS", bool(raw.get("dev_bypass", False)))
        )

        eff_host = (
            host
            or os.environ.get("SK_ACCESS_HOST")
            or raw.get("host")
            or _detect_tailnet_ip()
            or "127.0.0.1"
        )
        eff_port = int(
            port if port is not None else os.environ.get("SK_ACCESS_PORT", raw.get("port", _DEFAULT_PORT))
        )

        roots_src = raw.get("exposed_roots") or list(DEFAULT_EXPOSED_ROOTS)
        exposed_roots = [Path(str(r)).expanduser().resolve() for r in roots_src]

        deny = list(raw.get("deny_subpaths") or DEFAULT_DENY_SUBPATHS)

        scope_grants = cls._parse_grants(raw.get("scope_grants") or {})

        node_name, node_fqid = cls._resolve_node()

        return cls(
            host=eff_host,
            port=eff_port,
            allow_public=eff_allow_public,
            dev_bypass=eff_dev_bypass,
            exposed_roots=exposed_roots,
            deny_subpaths=deny,
            scope_grants=scope_grants,
            node_name=node_name,
            node_fqid=node_fqid,
        )

    @staticmethod
    def _read_yaml(config_path: Optional[Path]) -> dict:
        path = (config_path or _ACCESS_CONFIG_PATH).expanduser()
        if not path.exists():
            return {}
        try:
            doc = yaml.safe_load(path.read_text()) or {}
            return doc.get("access", doc) or {}
        except Exception as exc:
            logger.warning("access.yml parse failed (%s) — using defaults", exc)
            return {}

    @staticmethod
    def _parse_grants(raw: dict) -> dict[str, set[Scope]]:
        grants: dict[str, set[Scope]] = {}
        for ident, scopes in raw.items():
            if isinstance(scopes, str):
                scopes = [scopes]
            grants[ident] = {Scope(str(s)) for s in scopes}
        return grants

    @staticmethod
    def _resolve_node() -> tuple[str, Optional[str]]:
        try:
            from ..identity import resolve_self_identity

            ident = resolve_self_identity()
            return ident.get("agent", "local"), ident.get("fqid")
        except Exception:
            return os.environ.get("SKAGENT", "local"), None

    # -- runtime helpers ----------------------------------------------------

    def validate(self) -> None:
        """Enforce the no-public-bind rule. Called at server startup.

        Raises:
            ValueError: If the bind host is public and not explicitly allowed.
        """
        assert_not_public(self.host, allow_public=self.allow_public)

    def granted_scopes(self, identity: Optional[str]) -> set[Scope]:
        """Return the scope set granted to a verified identity.

        Falls back to the ``"*"`` wildcard grant, then to ``{READ}``.
        """
        if identity and identity in self.scope_grants:
            return self.scope_grants[identity]
        if "*" in self.scope_grants:
            return self.scope_grants["*"]
        return {Scope.READ}

    def to_dict(self) -> dict:
        """JSON-safe summary (no secrets)."""
        return {
            "host": self.host,
            "port": self.port,
            "allow_public": self.allow_public,
            "dev_bypass": self.dev_bypass,
            "exposed_roots": [str(p) for p in self.exposed_roots],
            "deny_subpaths": list(self.deny_subpaths),
            "node_name": self.node_name,
            "node_fqid": self.node_fqid,
            "scope_grants": {k: sorted(s.value for s in v) for k, v in self.scope_grants.items()},
        }
