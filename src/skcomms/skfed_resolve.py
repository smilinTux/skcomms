"""SKFed realm resolver — resolve ``<agent>@<operator>.<realm>`` with NO local config.

Two layers:

* :func:`resolve_realm_directory` — *where* a realm's signed directory lives.
  Resolution order: DNS ``_skfed._tcp.<realm>`` **SRV**, then ``_skfed.<realm>``
  **TXT** (``url=...``), then a config bootstrap
  (``skcomms_home()/realms.yml`` mapping ``realm -> directory_url``), then
  ``None``. DNS is done with ``dnspython`` when installed, but the resolver is
  injectable (``dns=...``) so the whole path is testable offline.

* :func:`resolve_agent` — fetch that realm's directory, **verify** its operator
  signature, find the agent's entry, and return its live endpoints. Verified
  directories are cached per-realm with a TTL (:class:`DirectoryCache`).

This is the sender side of the sovereign directory: given just a FQID and an
``http_get`` (the existing :443 funnel client), a node resolves a peer to live
endpoints with no pre-shared peer record. Fails **closed** — an unverifiable or
unreachable directory yields ``None`` (delivery falls back to other rails).
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional, Protocol

from .home import skcomms_home
from .skfed_directory import SignedDirectory

logger = logging.getLogger("skcomms.skfed_resolve")

# Default per-realm directory cache TTL (seconds).
DEFAULT_CACHE_TTL_S = 300

#: Type of the injected HTTP getter: ``url -> response bytes``.
HttpGet = Callable[[str], bytes]


class DnsResolver(Protocol):
    """Minimal DNS surface the resolver needs (injectable for tests)."""

    def srv(self, name: str) -> list[tuple[str, int]]:
        """Return ``[(host, port), ...]`` for an SRV name (most-preferred first)."""
        ...

    def txt(self, name: str) -> list[str]:
        """Return the decoded TXT strings for a name."""
        ...


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


class _DnspythonResolver:
    """Real DNS resolver backed by ``dnspython`` (used when installed)."""

    def srv(self, name: str) -> list[tuple[str, int]]:
        import dns.resolver  # type: ignore[import]

        try:
            answers = dns.resolver.resolve(name, "SRV")
        except Exception:
            return []
        records = sorted(answers, key=lambda r: (r.priority, -r.weight))
        return [(str(r.target).rstrip("."), int(r.port)) for r in records]

    def txt(self, name: str) -> list[str]:
        import dns.resolver  # type: ignore[import]

        try:
            answers = dns.resolver.resolve(name, "TXT")
        except Exception:
            return []
        out: list[str] = []
        for r in answers:
            # dnspython TXT strings are bytes chunks; join them.
            parts = getattr(r, "strings", None) or []
            out.append(b"".join(parts).decode("utf-8", "replace"))
        return out


def _default_dns() -> Optional[DnsResolver]:
    """Return a dnspython-backed resolver, or ``None`` if dnspython is absent."""
    try:
        import dns.resolver  # noqa: F401  type: ignore[import]
    except Exception:
        return None
    return _DnspythonResolver()


def _base_url_from_srv(host: str, port: int) -> str:
    """Build an ``https`` base URL from an SRV ``(host, port)``."""
    if port in (0, 443):
        return f"https://{host}"
    return f"https://{host}:{port}"


def resolve_realm_directory(
    realm: str,
    *,
    dns: Optional[DnsResolver] = None,
) -> Optional[str]:
    """Resolve a realm's directory **base URL** (no trailing slash).

    Order: DNS SRV (``_skfed._tcp.<realm>``) -> DNS TXT (``_skfed.<realm>``,
    ``url=...``) -> config bootstrap (``realms.yml``) -> ``None``.

    Args:
        realm: The realm to resolve (e.g. ``skworld``).
        dns: Injected DNS resolver. ``None`` uses dnspython when available;
            if dnspython is absent, DNS is skipped and only the config
            bootstrap is consulted.

    Returns:
        The directory base URL, or ``None`` if the realm is unresolvable.
    """
    resolver = dns if dns is not None else _default_dns()

    if resolver is not None:
        # 1. SRV.
        try:
            srv = resolver.srv(f"_skfed._tcp.{realm}")
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("SRV lookup failed for %s: %s", realm, exc)
            srv = []
        if srv:
            host, port = srv[0]
            return _base_url_from_srv(host, port)

        # 2. TXT (url=...).
        try:
            txt = resolver.txt(f"_skfed.{realm}")
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("TXT lookup failed for %s: %s", realm, exc)
            txt = []
        for rec in txt:
            rec = rec.strip().strip('"')
            if rec.startswith("url="):
                return rec[len("url="):].strip().rstrip("/")

    # 3. Config bootstrap (realms.yml).
    url = _realms_config().get(realm)
    if url:
        return str(url).rstrip("/")

    return None


def _realms_config() -> dict:
    """Load ``skcomms_home()/realms.yml`` (``realm -> directory_url``)."""
    path = skcomms_home() / "realms.yml"
    if not path.exists():
        return {}
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("realms.yml parse error: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Verified-directory cache (per realm, TTL)
# ---------------------------------------------------------------------------


class DirectoryCache:
    """Per-realm TTL cache of *verified* :class:`SignedDirectory` objects.

    Only directories that already passed signature verification are cached, so
    a cache hit is always trustworthy. The clock is injectable for tests.
    """

    def __init__(self, ttl_s: int = DEFAULT_CACHE_TTL_S, clock: Callable[[], float] = time.time):
        self._ttl = ttl_s
        self._clock = clock
        self._d: dict[str, tuple[float, SignedDirectory]] = {}

    def get(self, realm: str) -> Optional[SignedDirectory]:
        item = self._d.get(realm)
        if item is None:
            return None
        expires_at, directory = item
        if self._clock() >= expires_at:
            del self._d[realm]
            return None
        return directory

    def put(self, realm: str, directory: SignedDirectory) -> None:
        self._d[realm] = (self._clock() + self._ttl, directory)


#: Process-wide default cache (used when a caller doesn't inject one).
_DEFAULT_CACHE = DirectoryCache()


# ---------------------------------------------------------------------------
# resolve_agent
# ---------------------------------------------------------------------------


def _realm_of(fqid: str) -> Optional[str]:
    """Extract the realm from ``<agent>@<operator>.<realm>``."""
    if "@" not in fqid:
        return None
    rest = fqid.split("@", 1)[1]
    if "." not in rest:
        return None
    return rest.split(".", 1)[1]


def _fetch_verified_directory(
    realm: str,
    *,
    http_get: HttpGet,
    dns: Optional[DnsResolver],
    verifier,
    cache: DirectoryCache,
) -> Optional[SignedDirectory]:
    """Return a verified directory for *realm* — from cache or freshly fetched."""
    cached = cache.get(realm)
    if cached is not None:
        return cached

    base = resolve_realm_directory(realm, dns=dns)
    if not base:
        logger.debug("realm %s has no resolvable directory", realm)
        return None

    url = base.rstrip("/") + "/.well-known/skfed/directory"
    try:
        raw = http_get(url)
        sd = SignedDirectory.from_bytes(raw)
    except Exception as exc:
        logger.debug("failed to fetch/parse directory for %s at %s: %s", realm, url, exc)
        return None

    if verifier is None or not sd.verify(verifier):
        logger.warning("directory for realm %s failed signature verification", realm)
        return None

    cache.put(realm, sd)
    return sd


def resolve_agent(
    fqid: str,
    *,
    http_get: HttpGet,
    dns: Optional[DnsResolver] = None,
    verifier=None,
    cache: Optional[DirectoryCache] = None,
    now: Optional[float] = None,  # reserved; cache clock is injected at construction
) -> Optional[dict]:
    """Resolve a FQID to its live endpoints via the realm's signed directory.

    Steps: parse the realm from *fqid* -> resolve the realm directory base ->
    fetch + **verify** the signed directory (cached per realm) -> return the
    matching entry as a plain dict. Fails **closed** (returns ``None``) on any
    unresolvable / unfetchable / unverifiable / missing-entry condition.

    Args:
        fqid: ``<agent>@<operator>.<realm>`` to resolve.
        http_get: ``url -> bytes`` HTTP getter (the :443 funnel client).
        dns: Injected DNS resolver (defaults to dnspython when available).
        verifier: An :class:`~skcomms.signing.EnvelopeVerifier` preloaded with
            the realm operator's public key. Required — verification is
            mandatory; ``None`` means *fail closed*.
        cache: Per-realm :class:`DirectoryCache` (a process default is used
            otherwise).

    Returns:
        ``{"fqid", "inbox_url", "prekey_url", "did", "caps", "updated_at"}`` for
        the agent, or ``None``.
    """
    realm = _realm_of(fqid)
    if not realm:
        logger.debug("cannot extract realm from fqid %r", fqid)
        return None

    cache = cache if cache is not None else _DEFAULT_CACHE
    sd = _fetch_verified_directory(
        realm, http_get=http_get, dns=dns, verifier=verifier, cache=cache
    )
    if sd is None:
        return None

    entry = sd.get(fqid)
    if entry is None:
        logger.debug("agent %s not found in realm %s directory", fqid, realm)
        return None

    return {
        "fqid": entry.fqid,
        "inbox_url": entry.inbox_url,
        "prekey_url": entry.prekey_url,
        "did": entry.did,
        "caps": list(entry.caps),
        "updated_at": entry.updated_at,
    }
