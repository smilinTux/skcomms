"""SSRF guard for the SKFed directory/discovery outbound fetch.

Security regression tests for the finding: ``resolve_agent`` resolves a realm
directory URL from **attacker-controllable DNS** (SRV/TXT for the attacker's
own realm) and then ``http_get(url)`` **connects before** the directory's
signature is verified. With no guard, an attacker points
``_skfed._tcp.<realm>`` / ``_skfed.<realm>`` at ``127.0.0.1``,
``169.254.169.254`` (cloud metadata), or an internal host and the node fetches
it — classic SSRF, plus a DNS-rebind window.

``default_http_get`` must resolve the host and refuse to connect to
private / loopback / link-local / reserved / multicast addresses, and refuse
non-http(s) schemes, *before* opening the socket.
"""

from __future__ import annotations

import pytest

from skcomms.skfed_resolve import default_http_get


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/.well-known/skfed/directory",
        "http://127.0.0.1:6379/",
        "http://localhost/x",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://10.0.0.5/x",
        "http://192.168.1.10/x",
        "http://172.16.0.9/x",
        "http://[::1]/x",  # ipv6 loopback
        "http://0.0.0.0/x",
    ],
)
def test_default_http_get_blocks_private_and_loopback(url):
    with pytest.raises(ValueError, match="(?i)ssrf|private|loopback|blocked|not allowed"):
        default_http_get(url)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_",
        "ftp://example.com/x",
    ],
)
def test_default_http_get_blocks_bad_schemes(url):
    with pytest.raises(ValueError, match="(?i)scheme|ssrf|not allowed|blocked"):
        default_http_get(url)


def test_default_http_get_allows_public_host(monkeypatch):
    """A public host passes the guard and the fetch is pinned to the vetted IP.

    We stub name resolution to a public IP and stub the pinned-opener factory
    so no real network call is made; the point is the guard does NOT reject a
    legitimate public directory URL, and the connection it builds is pinned to
    the address that passed vetting (DNS-rebind hardening).
    """
    import skcomms.ssrf as ssrf

    # Force resolution to a public address.
    monkeypatch.setattr(
        ssrf.socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [
            (ssrf.socket.AF_INET, ssrf.socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))
        ],
    )

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"OK"

    pinned = {}

    class _Opener:
        def open(self, req, timeout=None):
            return _Resp()

    def _fake_build_opener(pinned_ip):
        pinned["ip"] = pinned_ip
        return _Opener()

    monkeypatch.setattr(ssrf, "_build_opener", _fake_build_opener)

    assert default_http_get("https://directory.example.com/.well-known/skfed/directory") == b"OK"
    # The connection was pinned to the exact address that passed vetting.
    assert pinned["ip"] == "93.184.216.34"
