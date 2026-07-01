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
    """A public host passes the guard and reaches the real fetch path.

    We stub name resolution to a public IP and stub urlopen so no real network
    call is made; the point is the guard does NOT reject a legitimate public
    directory URL.
    """
    import skcomms.skfed_resolve as mod

    # Force resolution to a public address.
    monkeypatch.setattr(
        mod.socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [
            (mod.socket.AF_INET, mod.socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))
        ],
    )

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"OK"

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())

    assert default_http_get("https://directory.example.com/.well-known/skfed/directory") == b"OK"
