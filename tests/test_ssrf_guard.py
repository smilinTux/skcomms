"""Central SSRF guard (skcomms.ssrf): policy, vetting, pinning, redirects, wiring.

Security regression tests for coordination task e58e200f. The guard protects
every outbound directory/discovery fetch whose target derives from
attacker-controllable input:

* :mod:`skcomms.skfed_resolve` (realm directory, attacker DNS SRV/TXT)
* :mod:`skcomms.registry` ``HttpsBackend`` (realm-templated URL)
* :mod:`skcomms.key_exchange` DID fetch (caller-supplied URL)
* :mod:`skcomms.transports.http_s2s` (inbox_url from a REMOTE realm directory)

Beyond the plain private-address block (already covered by
``test_skfed_ssrf.py``), these tests prove the two harder properties:

* **DNS-rebind immunity**: the socket connects to the exact address that was
  vetted, even if the name re-resolves to something private afterwards.
* **Redirect re-vetting**: a public/allowed host cannot 302 the client into
  private address space, redirect loops are capped, and a redirected POST is
  refused outright.
"""

from __future__ import annotations

import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from skcomms.ssrf import (
    ALLOW_CIDRS_ENV,
    ALLOW_PRIVATE_ENV,
    SSRFBlockedError,
    SSRFPolicy,
    guarded_get,
    guarded_urlopen,
    vet_url,
)

#: Policy used by the local-server integration tests: loopback is explicitly
#: allowed via the CIDR allowlist (the strict default would block 127.0.0.1).
LOOPBACK_OK = SSRFPolicy(allow_cidrs=(ipaddress.ip_network("127.0.0.0/8"),))


@pytest.fixture(autouse=True)
def _clean_ssrf_env(monkeypatch):
    """Tests here reason about the default policy: start from a clean env."""
    monkeypatch.delenv(ALLOW_PRIVATE_ENV, raising=False)
    monkeypatch.delenv(ALLOW_CIDRS_ENV, raising=False)


# ---------------------------------------------------------------------------
# SSRFPolicy
# ---------------------------------------------------------------------------


class TestSSRFPolicy:
    def test_default_env_is_strict(self):
        policy = SSRFPolicy.from_env({})
        assert policy.allow_private is False
        assert policy.allow_cidrs == ()
        assert not policy.ip_allowed(ipaddress.ip_address("127.0.0.1"))
        assert not policy.ip_allowed(ipaddress.ip_address("192.168.0.41"))
        assert not policy.ip_allowed(ipaddress.ip_address("169.254.169.254"))
        assert not policy.ip_allowed(ipaddress.ip_address("100.100.1.1"))
        assert policy.ip_allowed(ipaddress.ip_address("93.184.216.34"))

    @pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
    def test_allow_private_env_gate(self, value):
        policy = SSRFPolicy.from_env({ALLOW_PRIVATE_ENV: value})
        assert policy.allow_private is True
        assert policy.ip_allowed(ipaddress.ip_address("127.0.0.1"))

    def test_allow_cidrs_env_scopes_the_exception(self):
        policy = SSRFPolicy.from_env({ALLOW_CIDRS_ENV: "100.64.0.0/10, 192.168.0.0/24"})
        # The listed ranges are allowed...
        assert policy.ip_allowed(ipaddress.ip_address("100.100.1.1"))
        assert policy.ip_allowed(ipaddress.ip_address("192.168.0.41"))
        # ...but everything else non-public stays blocked.
        assert not policy.ip_allowed(ipaddress.ip_address("192.168.1.41"))
        assert not policy.ip_allowed(ipaddress.ip_address("127.0.0.1"))
        assert not policy.ip_allowed(ipaddress.ip_address("169.254.169.254"))

    def test_invalid_cidr_tokens_are_ignored(self):
        policy = SSRFPolicy.from_env({ALLOW_CIDRS_ENV: "not-a-cidr,10.0.0.0/8"})
        assert len(policy.allow_cidrs) == 1
        assert policy.ip_allowed(ipaddress.ip_address("10.1.2.3"))


# ---------------------------------------------------------------------------
# vet_url
# ---------------------------------------------------------------------------


def _fake_getaddrinfo(*answers: str):
    """Build a getaddrinfo fake returning the given IPv4 answers for any host."""
    import socket as _socket

    def _gai(host, port, *a, **k):
        return [
            (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, port or 443))
            for ip in answers
        ]

    return _gai


class TestVetUrl:
    def test_one_private_answer_blocks_a_mixed_resolution(self, monkeypatch):
        """An attacker cannot smuggle a private A record in among public ones."""
        import skcomms.ssrf as ssrf

        monkeypatch.setattr(
            ssrf.socket,
            "getaddrinfo",
            _fake_getaddrinfo("93.184.216.34", "10.0.0.5"),
        )
        with pytest.raises(SSRFBlockedError, match="non-public"):
            vet_url("https://mixed.example.com/x")

    def test_pins_the_first_vetted_address(self, monkeypatch):
        import skcomms.ssrf as ssrf

        monkeypatch.setattr(
            ssrf.socket,
            "getaddrinfo",
            _fake_getaddrinfo("93.184.216.34", "203.0.114.7"),
        )
        target = vet_url("https://multi.example.com/x")
        assert target.pinned_ip == "93.184.216.34"
        assert target.host == "multi.example.com"
        assert target.port == 443

    def test_allow_cidrs_permits_a_matching_literal(self):
        policy = SSRFPolicy(allow_cidrs=(ipaddress.ip_network("100.64.0.0/10"),))
        target = vet_url("https://100.100.1.1:9384/api/v1/inbox", policy)
        assert target.pinned_ip == "100.100.1.1"

    def test_strict_policy_blocks_the_same_literal(self):
        with pytest.raises(SSRFBlockedError):
            vet_url("https://100.100.1.1:9384/api/v1/inbox", SSRFPolicy())

    def test_unresolvable_host_is_blocked(self, monkeypatch):
        import socket as _socket

        import skcomms.ssrf as ssrf

        def _gai(host, port, *a, **k):
            raise _socket.gaierror("NXDOMAIN")

        monkeypatch.setattr(ssrf.socket, "getaddrinfo", _gai)
        with pytest.raises(SSRFBlockedError, match="did not resolve"):
            vet_url("https://nxdomain.example.com/x")


# ---------------------------------------------------------------------------
# Local HTTP server: pinning + redirect behaviour, end to end
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _respond(self, status: int, body: bytes = b"", location: str | None = None):
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Seen-Host", self.headers.get("Host", ""))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ok":
            self._respond(200, b"hello")
        elif self.path == "/redirect-ok":
            self._respond(302, location="/ok")
        elif self.path == "/redirect-meta":
            self._respond(302, location="http://169.254.169.254/latest/meta-data/")
        elif self.path == "/redirect-loop":
            self._respond(302, location="/redirect-loop")
        else:
            self._respond(404, b"nope")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._respond(302, location="/ok")


@pytest.fixture
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _base(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


class TestGuardedFetch:
    def test_default_policy_blocks_a_reachable_loopback_server(self, http_server):
        """The strict default refuses loopback even when something listens there."""
        with pytest.raises(SSRFBlockedError):
            guarded_get(f"{_base(http_server)}/ok")

    def test_allow_cidrs_policy_fetches(self, http_server):
        assert guarded_get(f"{_base(http_server)}/ok", policy=LOOPBACK_OK) == b"hello"

    def test_env_cidr_gate_fetches_without_explicit_policy(self, http_server, monkeypatch):
        monkeypatch.setenv(ALLOW_CIDRS_ENV, "127.0.0.0/8")
        assert guarded_get(f"{_base(http_server)}/ok") == b"hello"

    def test_env_allow_private_gate_fetches(self, http_server, monkeypatch):
        monkeypatch.setenv(ALLOW_PRIVATE_ENV, "1")
        assert guarded_get(f"{_base(http_server)}/ok") == b"hello"

    def test_dns_rebind_cannot_move_the_connection(self, http_server, monkeypatch):
        """The fetch connects to the address that was vetted, not a re-resolution.

        ``rebind.example`` resolves to 127.0.0.1 exactly once (the vetting
        pass) and to the cloud-metadata address on every later lookup. With
        the pinned connection the fetch still lands on the vetted 127.0.0.1
        server, carrying the original Host header. Pre-fix behavior (urllib
        re-resolving the name at connect time) would have chased the rebind.
        """
        import skcomms.ssrf as ssrf

        port = http_server.server_address[1]
        calls = {"rebind.example": 0}
        real_gai = ssrf.socket.getaddrinfo

        def _gai(host, gai_port, *a, **k):
            if host == "rebind.example":
                calls[host] += 1
                ip = "127.0.0.1" if calls[host] == 1 else "169.254.169.254"
                return [
                    (
                        ssrf.socket.AF_INET,
                        ssrf.socket.SOCK_STREAM,
                        6,
                        "",
                        (ip, gai_port),
                    )
                ]
            return real_gai(host, gai_port, *a, **k)

        monkeypatch.setattr(ssrf.socket, "getaddrinfo", _gai)

        with guarded_urlopen(
            f"http://rebind.example:{port}/ok", policy=LOOPBACK_OK
        ) as resp:
            assert resp.read() == b"hello"
            # The request carried the ORIGINAL hostname to the pinned socket.
            assert resp.headers["X-Seen-Host"] == f"rebind.example:{port}"

        # Sanity: the name really does rebind on a later lookup.
        assert _gai("rebind.example", port)[0][4][0] == "169.254.169.254"

    def test_redirect_to_metadata_is_blocked(self, http_server):
        """An allowed host cannot 302 the client into private address space."""
        with pytest.raises(SSRFBlockedError, match="non-public|blocked"):
            guarded_get(f"{_base(http_server)}/redirect-meta", policy=LOOPBACK_OK)

    def test_redirect_to_an_allowed_target_is_followed(self, http_server):
        assert (
            guarded_get(f"{_base(http_server)}/redirect-ok", policy=LOOPBACK_OK)
            == b"hello"
        )

    def test_redirect_loops_are_capped(self, http_server):
        with pytest.raises(SSRFBlockedError, match="too many redirects"):
            guarded_get(f"{_base(http_server)}/redirect-loop", policy=LOOPBACK_OK)

    def test_redirected_post_is_refused(self, http_server):
        with pytest.raises(SSRFBlockedError, match="refusing to follow"):
            guarded_urlopen(
                f"{_base(http_server)}/anything",
                data=b"payload",
                method="POST",
                policy=LOOPBACK_OK,
            )


# ---------------------------------------------------------------------------
# Wiring: registry HttpsBackend
# ---------------------------------------------------------------------------


def test_registry_default_https_fetcher_is_guarded():
    from skcomms.registry import _default_https_fetcher

    with pytest.raises(ValueError, match="(?i)ssrf"):
        _default_https_fetcher("https://169.254.169.254/peers.json")

    with pytest.raises(ValueError, match="(?i)ssrf"):
        _default_https_fetcher("https://127.0.0.1:8443/peers.json")


# ---------------------------------------------------------------------------
# Wiring: DID key exchange
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/did.json",
        "http://127.0.0.1/agents/x/.well-known/did.json",
        "https://10.0.0.5/agents/x/.well-known/did.json",
    ],
)
def test_fetch_peer_from_did_blocks_private_urls(url, tmp_path):
    from skcomms.key_exchange import KeyExchangeError, fetch_peer_from_did

    with pytest.raises(KeyExchangeError, match="(?i)ssrf|failed to fetch"):
        fetch_peer_from_did(url, peers_dir=tmp_path, save=False)


# ---------------------------------------------------------------------------
# Wiring: https-s2s transport (directory-derived inbox URLs)
# ---------------------------------------------------------------------------

# SignedEnvelope shape: passes the structural gate so the send reaches the
# HTTP layer (mirrors tests/test_http_s2s_transport.py).
SIGNED_ENVELOPE = (
    b'{"envelope": {"id": "env-ssrf", "from_fqid": "opus@chef.skworld", '
    b'"to_fqid": "evil@boss.evilrealm", "body": "hi"}, "signature": "sig"}'
)


class TestHttpS2SDirectorySSRF:
    def test_directory_resolution_drops_a_private_inbox_url(self, monkeypatch):
        """An inbox_url from a remote directory pointing inside is discarded."""
        import skcomms.discovery as discovery
        import skcomms.skfed_resolve as skfed_resolve
        from skcomms.transports.http_s2s import HttpS2STransport

        monkeypatch.setattr(skfed_resolve, "realm_verifier", lambda realm: object())
        monkeypatch.setattr(
            discovery,
            "inbox_url_for",
            lambda fqid, **kw: "http://192.168.0.41:9384/api/v1/inbox",
        )

        t = HttpS2STransport()
        assert t._inbox_url_from_directory("evil@boss.evilrealm") is None

    def test_directory_resolution_keeps_a_public_inbox_url(self, monkeypatch):
        import skcomms.discovery as discovery
        import skcomms.skfed_resolve as skfed_resolve
        import skcomms.ssrf as ssrf
        from skcomms.transports.http_s2s import HttpS2STransport

        monkeypatch.setattr(skfed_resolve, "realm_verifier", lambda realm: object())
        monkeypatch.setattr(
            discovery,
            "inbox_url_for",
            lambda fqid, **kw: "https://inbox.evilrealm.example/api/v1/inbox",
        )
        monkeypatch.setattr(
            ssrf.socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34")
        )

        t = HttpS2STransport()
        url = t._inbox_url_from_directory("evil@boss.evilrealm")
        assert url == "https://inbox.evilrealm.example/api/v1/inbox"

    def test_send_to_directory_url_is_guarded_and_permanent(self):
        """A directory-derived URL that turns private is refused at send time.

        This closes the rebind window between resolution-time vetting and the
        actual POST: the send path re-vets (and pins) directory-derived URLs.
        No network call is made; the guard raises before any socket opens and
        the failure is permanent (retrying a blocked URL can never succeed).
        """
        from skcomms.transports.http_s2s import HttpS2STransport

        t = HttpS2STransport()
        evil_url = "http://127.0.0.1:9384/api/v1/inbox"
        t._peer_urls["evil@boss.evilrealm"] = evil_url
        t._directory_urls.add(evil_url)

        result = t.send(SIGNED_ENVELOPE, "evil@boss.evilrealm")
        assert result.success is False
        assert result.error.startswith("perm:")
        assert "SSRF" in result.error

    def test_store_configured_private_url_is_untouched(self, monkeypatch):
        """Operator-configured (manual/store) URLs keep working on the LAN/tailnet."""
        import urllib.request

        from skcomms.transports.http_s2s import HttpS2STransport

        captured = {}

        class _Resp:
            status = 200

            def read(self):
                return b'{"ok": true, "id": "env-ssrf"}'

            def getcode(self):
                return self.status

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def _urlopen(req, timeout=None):
            captured["url"] = req.full_url
            return _Resp()

        monkeypatch.setattr(urllib.request, "urlopen", _urlopen)

        t = HttpS2STransport()
        t.register_peer_url("jarvis", "http://192.168.0.41:9384/api/v1/inbox")
        result = t.send(SIGNED_ENVELOPE, "jarvis")
        assert result.success is True
        assert captured["url"] == "http://192.168.0.41:9384/api/v1/inbox"
