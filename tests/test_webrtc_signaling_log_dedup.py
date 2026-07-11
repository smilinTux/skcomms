"""Workstream B4: WebRTC signaling-failure log-once-per-state-change.

RC4: when the signaling broker (``ws://127.0.0.1:9390``) is simply down, the
WebRTC ``_main_loop`` re-logged the connect failure at WARNING on every
reconnect attempt (~every few seconds, growing to 60s). B4 logs the failure at
WARNING once on the transition INTO the failing state, DEBUG while it persists,
and one INFO line on recovery. (The startup health-gate in B5 is the real fix
when the broker is absent; this just stops the noise.)
"""

from __future__ import annotations

import logging

from skcomms.transports.webrtc import WebRTCTransport

LOGGER = "skcomms.transports.webrtc"


def _levels(caplog, needle):
    return [r.levelno for r in caplog.records if needle in r.getMessage()]


def test_first_failure_warns_then_debug(caplog):
    t = WebRTCTransport(agent_fingerprint="DEADBEEFCAFE1234")
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        t._log_signaling_failure(ConnectionRefusedError("broker down"), 2.0)
        t._log_signaling_failure(ConnectionRefusedError("broker down"), 4.0)
        t._log_signaling_failure(ConnectionRefusedError("broker down"), 8.0)

    levels = _levels(caplog, "Signaling connection error")
    assert levels[0] == logging.WARNING
    assert levels[1:] == [logging.DEBUG, logging.DEBUG]


def test_recovery_logs_once_and_rearms(caplog):
    t = WebRTCTransport(agent_fingerprint="DEADBEEFCAFE1234")
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        t._log_signaling_failure(ConnectionRefusedError("down"), 2.0)   # WARN
        t._note_signaling_recovered()                                    # INFO
        t._log_signaling_failure(ConnectionRefusedError("down"), 2.0)   # WARN again

    warns = _levels(caplog, "Signaling connection error")
    recovered = [r for r in caplog.records if "recover" in r.getMessage().lower()]
    assert warns.count(logging.WARNING) == 2
    assert len(recovered) == 1
    assert recovered[0].levelno == logging.INFO


def test_recovery_without_prior_failure_is_silent(caplog):
    t = WebRTCTransport(agent_fingerprint="DEADBEEFCAFE1234")
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        t._note_signaling_recovered()
    assert [r for r in caplog.records if "recover" in r.getMessage().lower()] == []
