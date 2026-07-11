"""Workstream B3 (http_s2s side): '*'/'' recipients never hit the peer store.

RC3: resolving an inbox URL for the literal broadcast recipient ``"*"`` (or an
empty recipient) drove a peer-store lookup that raised
``Peer name '*' is empty after sanitization`` and logged a WARNING. The router
fix (B3) stops offering https-s2s for ``*`` at all, but the transport is
hardened independently: ``_resolve_inbox_url`` / ``_inbox_url_from_store``
early-return ``None`` for a ``*``/``''`` recipient BEFORE the peer-store call,
so no sanitizer ever runs and no WARNING is emitted.
"""

from __future__ import annotations

import logging

import pytest

from skcomms.transports.http_s2s import HttpS2STransport


@pytest.mark.parametrize("recipient", ["*", ""])
def test_resolve_inbox_url_short_circuits_star_and_empty(recipient, caplog):
    t = HttpS2STransport()
    with caplog.at_level(logging.DEBUG, logger="skcomms.transports.http_s2s"):
        assert t._resolve_inbox_url(recipient) is None
        assert t._inbox_url_from_store(recipient) is None
    # No WARNING (the peer-store sanitizer was never reached).
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.parametrize("recipient", ["*", ""])
def test_send_to_star_is_permanent_without_network(recipient):
    t = HttpS2STransport()
    # A signed-looking payload passes the structural gate; resolution then
    # fails closed to a perm: no-inbox result, never touching the network.
    signed = b'{"envelope": {"id": "x"}, "signature": "sig", "public_key": "pk"}'
    res = t.send(signed, recipient)
    assert res.success is False
    assert res.error.startswith("perm:")
