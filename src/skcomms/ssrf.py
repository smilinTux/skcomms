"""Central SSRF guard for skcomms outbound directory/discovery fetches.

Threat model:
    Several skcomms fetch paths connect to hosts derived from
    **attacker-controllable input** before anything is verified:

    * SKFed realm-directory resolution (:mod:`skcomms.skfed_resolve`): the
      directory URL comes from the attacker realm's own DNS SRV/TXT records
      and is fetched *before* the directory signature check.
    * The registry ``HttpsBackend`` (:mod:`skcomms.registry`): the URL is
      templated from a realm name.
    * DID-based key exchange (:mod:`skcomms.key_exchange`): the DID document
      URL can be supplied verbatim.
    * The ``https-s2s`` transport (:mod:`skcomms.transports.http_s2s`): an
      ``inbox_url`` resolved from a *remote* realm directory points wherever
      that realm's operator wants, including this node's internal network.

    Without a guard, any of those can be pointed at ``127.0.0.1``,
    ``169.254.169.254`` (cloud metadata), or an internal host: classic SSRF.
    A check-then-fetch guard alone still leaves a DNS-rebind window (vet the
    name, then the second resolution inside the HTTP client returns a private
    address). This module closes both:

    * :func:`vet_url` validates the scheme, resolves the host, and requires
      every resolved address to pass policy. It returns a **pinned** address.
    * :func:`guarded_urlopen` performs the request over a connection that
      connects to that exact vetted address (Host header and TLS SNI still
      carry the original hostname), so a post-vet rebind cannot redirect the
      socket. Redirects are re-vetted hop by hop; redirected non-GET requests
      are refused outright.

Policy (fail closed by default, config-gated escape hatches):
    * ``SKCOMMS_SSRF_ALLOW_PRIVATE=1`` disables the private-address block
      entirely (dev/lab escape hatch, logged loudly once).
    * ``SKCOMMS_SSRF_ALLOW_CIDRS=100.64.0.0/10,192.168.0.0/24`` additionally
      allows specific ranges (e.g. a tailnet) without opening everything.
"""

from __future__ import annotations

import functools
import http.client
import ipaddress
import logging
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Optional, Union
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger("skcomms.ssrf")

#: Env var: set to 1/true/yes/on to allow private/loopback destinations (dev only).
ALLOW_PRIVATE_ENV = "SKCOMMS_SSRF_ALLOW_PRIVATE"

#: Env var: comma-separated CIDRs additionally allowed (e.g. a tailnet range).
ALLOW_CIDRS_ENV = "SKCOMMS_SSRF_ALLOW_CIDRS"

#: URL schemes an outbound discovery fetch is ever allowed to use.
ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Redirect statuses that are followed (with re-vetting) for GET/HEAD.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

#: Default cap on re-vetted redirect hops.
DEFAULT_MAX_REDIRECTS = 3

_warned_allow_private = False


class SSRFBlockedError(ValueError):
    """A fetch was refused by the SSRF guard.

    Subclasses ``ValueError`` so existing callers (and tests) that treat guard
    rejections as ``ValueError`` keep working unchanged.
    """


def _ip_is_public(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """True only for globally-routable unicast addresses.

    Rejects loopback, private (RFC1918 / ULA), link-local (incl. the
    169.254.169.254 metadata range), reserved, multicast, unspecified
    (``0.0.0.0`` / ``::``), and shared address space (CGNAT ``100.64.0.0/10``,
    which is ``is_global == False`` but not ``is_private``).
    """
    return (
        ip.is_global
        and not ip.is_multicast
        and not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )
    )


@dataclass(frozen=True)
class SSRFPolicy:
    """What the guard allows. Immutable; build once and pass around.

    Attributes:
        allow_private: When True the private/loopback block is disabled
            (dev/lab escape hatch; scheme and resolvability checks remain).
        allow_cidrs: Extra networks allowed even though they are not public
            (e.g. the tailnet ``100.64.0.0/10``).
        max_redirects: Redirect hops :func:`guarded_urlopen` will re-vet and
            follow for GET/HEAD before failing closed.
    """

    allow_private: bool = False
    allow_cidrs: tuple = ()
    max_redirects: int = DEFAULT_MAX_REDIRECTS

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "SSRFPolicy":
        """Build a policy from the environment (the default for all callers)."""
        global _warned_allow_private
        env = os.environ if environ is None else environ

        allow_private = env.get(ALLOW_PRIVATE_ENV, "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        if allow_private and not _warned_allow_private:
            logger.warning(
                "%s is set: the SSRF private-address block is DISABLED. "
                "Use %s with specific CIDRs instead where possible.",
                ALLOW_PRIVATE_ENV,
                ALLOW_CIDRS_ENV,
            )
            _warned_allow_private = True

        cidrs = []
        for token in env.get(ALLOW_CIDRS_ENV, "").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                cidrs.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                logger.warning(
                    "ignoring invalid CIDR %r in %s", token, ALLOW_CIDRS_ENV
                )

        return cls(allow_private=allow_private, allow_cidrs=tuple(cidrs))

    def ip_allowed(self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """True when *ip* is an acceptable connect target under this policy."""
        if self.allow_private:
            return True
        if _ip_is_public(ip):
            return True
        return any(ip in net for net in self.allow_cidrs)


@dataclass(frozen=True)
class VettedTarget:
    """The outcome of :func:`vet_url`: a scheme/host/port plus a pinned address.

    Attributes:
        scheme: ``http`` or ``https``.
        host: The original hostname (kept for the Host header and TLS SNI).
        port: The effective port.
        pinned_ip: The vetted address the socket MUST connect to.
    """

    scheme: str
    host: str
    port: int
    pinned_ip: str


def vet_url(url: str, policy: Optional[SSRFPolicy] = None) -> VettedTarget:
    """Validate *url* and resolve+vet its host, returning a pinned target.

    Every address the host resolves to must pass policy (a single blocked
    answer refuses the whole fetch, so an attacker cannot mix one public
    A record in with private ones). The first vetted address becomes the
    pinned connect target.

    Raises:
        SSRFBlockedError: For a disallowed scheme, a missing host, an
            unresolvable host, or any resolved address the policy blocks.
    """
    policy = policy if policy is not None else SSRFPolicy.from_env()

    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(
            f"SSRF guard: scheme {scheme!r} not allowed (http/https only)"
        )

    host = parts.hostname
    if not host:
        raise SSRFBlockedError("SSRF guard: URL has no host")

    port = parts.port or (443 if scheme == "https" else 80)

    # A literal IP is checked directly; a name is resolved and every returned
    # address must pass policy.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if not policy.ip_allowed(literal):
            raise SSRFBlockedError(f"SSRF guard: blocked non-public address {host}")
        return VettedTarget(scheme, host, port, str(literal))

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFBlockedError(
            f"SSRF guard: host {host!r} did not resolve: {exc}"
        ) from exc

    if not infos:
        raise SSRFBlockedError(f"SSRF guard: host {host!r} did not resolve")

    pinned: Optional[str] = None
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise SSRFBlockedError(
                f"SSRF guard: could not parse resolved address {addr!r}"
            ) from exc
        if not policy.ip_allowed(ip):
            raise SSRFBlockedError(
                f"SSRF guard: host {host!r} resolves to non-public address {addr}"
            )
        if pinned is None:
            pinned = str(ip)

    assert pinned is not None  # infos was non-empty and every entry was vetted
    return VettedTarget(scheme, host, port, pinned)


# ---------------------------------------------------------------------------
# Pinned connections: connect to the vetted address, present the hostname
# ---------------------------------------------------------------------------


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose socket connects to a pre-vetted address."""

    def __init__(self, host, pinned_ip=None, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection pinned to a vetted address; SNI + cert check keep the hostname."""

    def __init__(self, host, pinned_ip=None, **kwargs):
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # TLS is established against the ORIGINAL hostname (SNI + certificate
        # hostname verification), only the TCP connect target is pinned.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pinned_ip: str):
        super().__init__()
        self._pinned_ip = pinned_ip

    def http_open(self, req):
        return self.do_open(
            functools.partial(_PinnedHTTPConnection, pinned_ip=self._pinned_ip), req
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_ip: str):
        super().__init__()
        self._pinned_ip = pinned_ip

    def https_open(self, req):
        return self.do_open(
            functools.partial(_PinnedHTTPSConnection, pinned_ip=self._pinned_ip),
            req,
            context=self._context,
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn every 3xx into an HTTPError so guarded_urlopen can re-vet the hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener(pinned_ip: str) -> urllib.request.OpenerDirector:
    """Build a urllib opener whose connections are pinned to *pinned_ip*.

    Kept as a module-level seam so tests can substitute a fake opener and
    assert which vetted address the guard pinned.
    """
    return urllib.request.build_opener(
        _PinnedHTTPHandler(pinned_ip),
        _PinnedHTTPSHandler(pinned_ip),
        _NoRedirectHandler(),
    )


def guarded_urlopen(
    url: str,
    *,
    data: Optional[bytes] = None,
    headers: Optional[Mapping[str, str]] = None,
    method: Optional[str] = None,
    timeout: float = 10.0,
    policy: Optional[SSRFPolicy] = None,
):
    """SSRF-guarded, rebind-safe replacement for ``urllib.request.urlopen``.

    Vets the URL (:func:`vet_url`), then performs the request over a
    connection pinned to the vetted address. Redirects are intercepted and
    re-vetted hop by hop (GET/HEAD only, capped at ``policy.max_redirects``);
    a redirected request that carries a body or a non-GET method is refused
    fail-closed.

    Returns the open HTTP response (context-manager, ``.read()``,
    ``.status``), exactly like ``urlopen``. Non-2xx responses raise
    ``urllib.error.HTTPError`` as usual.

    Raises:
        SSRFBlockedError: When the URL, any resolved address, or any redirect
            hop is refused by policy.
    """
    policy = policy if policy is not None else SSRFPolicy.from_env()

    current_url = url
    hops = 0
    while True:
        target = vet_url(current_url, policy)
        opener = _build_opener(target.pinned_ip)
        req = urllib.request.Request(
            current_url, data=data, headers=dict(headers or {}), method=method
        )
        try:
            return opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code not in _REDIRECT_STATUSES:
                raise
            location = exc.headers.get("Location") if exc.headers else None
            exc.close()
            if not location:
                raise
            effective_method = (method or ("POST" if data is not None else "GET")).upper()
            if data is not None or effective_method not in ("GET", "HEAD"):
                raise SSRFBlockedError(
                    "SSRF guard: refusing to follow a redirect of a "
                    f"{effective_method} request (to {location!r})"
                )
            hops += 1
            if hops > policy.max_redirects:
                raise SSRFBlockedError(
                    f"SSRF guard: too many redirects (> {policy.max_redirects})"
                )
            next_url = urljoin(current_url, location)
            logger.debug(
                "guarded fetch following redirect %s -> %s (hop %d)",
                current_url,
                next_url,
                hops,
            )
            current_url = next_url


def guarded_get(
    url: str,
    *,
    timeout: float = 10.0,
    policy: Optional[SSRFPolicy] = None,
) -> bytes:
    """Guarded GET returning the response body bytes (see :func:`guarded_urlopen`)."""
    with guarded_urlopen(url, timeout=timeout, policy=policy) as resp:
        return resp.read()
