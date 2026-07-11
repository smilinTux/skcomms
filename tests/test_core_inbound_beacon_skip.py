"""Workstream B6: a leading-'<' inbound payload is a non-chat beacon (DEBUG).

RC (F4): the inbound decode runs ``MessageEnvelope.model_validate_json`` on
every raw payload a rail hands up. A non-chat beacon (an XML / CoT ``<event>``
frame that shares a file rail) is not a chat envelope and will never parse, but
it was logged at WARNING on every poll — steady log noise. B6 treats a payload
whose first non-space byte is ``<`` as a non-chat beacon and skips it at DEBUG,
while a genuinely malformed *chat* payload still WARNs.
"""

from __future__ import annotations

import logging

import pytest

from skcomms.core import SKComms
from skcomms.config import SKCommsConfig, IdentityConfig
from skcomms.router import Router


class _StubRouter(Router):
    """Router whose receive_all yields a fixed list of raw payloads once."""

    def __init__(self, payloads):
        super().__init__(transports=[])
        self._payloads = list(payloads)

    def receive_all(self):
        out, self._payloads = self._payloads, []
        return out


def _make_comms(payloads, tmp_path, monkeypatch):
    # Isolate ack/outbox state away from the real home; disable the ACK tracker
    # so receive()'s ack-timeout sweep does not emit unrelated skcomms.ack noise.
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    cfg = SKCommsConfig(identity=IdentityConfig(name="lumina"), ack=False)
    return SKComms(config=cfg, router=_StubRouter(payloads))


def _core_warnings(caplog):
    return [
        r for r in caplog.records
        if r.levelno == logging.WARNING and r.name == "skcomms.core"
    ]


def test_leading_lt_payload_skipped_at_debug_not_warning(tmp_path, monkeypatch, caplog):
    comms = _make_comms([b"<event><detail/></event>"], tmp_path, monkeypatch)

    with caplog.at_level(logging.DEBUG, logger="skcomms.core"):
        got = comms.receive()

    assert got == []
    debugs = [
        r for r in caplog.records
        if r.levelno == logging.DEBUG and r.name == "skcomms.core"
    ]
    assert _core_warnings(caplog) == []
    assert any("beacon" in r.getMessage().lower() for r in debugs)


def test_leading_whitespace_then_lt_still_treated_as_beacon(tmp_path, monkeypatch, caplog):
    comms = _make_comms([b"  \n<event/>"], tmp_path, monkeypatch)
    with caplog.at_level(logging.DEBUG, logger="skcomms.core"):
        got = comms.receive()
    assert got == []
    assert _core_warnings(caplog) == []


def test_malformed_chat_payload_still_warns(tmp_path, monkeypatch, caplog):
    comms = _make_comms([b"{not valid json at all"], tmp_path, monkeypatch)
    with caplog.at_level(logging.DEBUG, logger="skcomms.core"):
        got = comms.receive()
    assert got == []
    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "deserialize" in r.getMessage()
    ]
    assert len(warnings) == 1
