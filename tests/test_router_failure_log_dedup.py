"""Workstream B1: log-once-per-state-change dedup for transport failures.

RC2 (the transport storm): ``router.py`` logged ``Transport '%s' send failed``
at WARNING on EVERY failing cycle — a structurally-undeliverable rail (bad
``perm:`` target, a ``*`` broadcast on a point-to-point rail) re-logged every
~5s, filling the daemon log. The fix is a per-(transport, error-signature)
state map: WARN only on the transition INTO a failing state, DEBUG while the
same failure repeats, and one recovery line when the rail sends successfully
again. The receive-side WARNING is deduped the same way.
"""

from __future__ import annotations

import logging

from skcomms.models import (
    MessageEnvelope,
    MessagePayload,
    RoutingConfig,
    RoutingMode,
)
from skcomms.router import Router
from skcomms.transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportError,
    TransportStatus,
)


class ScriptedTransport(Transport):
    """A transport whose send outcome is driven by a mutable script list."""

    def __init__(self, name="file", category=TransportCategory.FILE_BASED):
        self.name = name
        self.priority = 1
        self.category = category
        # each entry: SendResult | Exception to raise
        self.script: list = []
        self._recv_script: list = []

    def configure(self, config: dict) -> None:  # pragma: no cover - trivial
        pass

    def is_available(self) -> bool:
        return True

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        outcome = self.script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def receive(self) -> list[bytes]:
        if self._recv_script:
            outcome = self._recv_script.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
        return []

    def health_check(self) -> HealthStatus:  # pragma: no cover - unused
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


def _fail(name, error):
    return SendResult(success=False, transport_name=name, envelope_id="", latency_ms=0.0, error=error)


def _ok(name):
    return SendResult(success=True, transport_name=name, envelope_id="", latency_ms=0.0)


def _dm_env(recipient="jarvis"):
    return MessageEnvelope(
        sender="lumina",
        recipient=recipient,
        payload=MessagePayload(content="hi"),
        routing=RoutingConfig(mode=RoutingMode.FAILOVER),
    )


def _count(caplog, level):
    return len([r for r in caplog.records if r.levelno == level and r.name == "skcomms.router"])


def test_same_failure_warns_once_then_debug(caplog):
    t = ScriptedTransport()
    r = Router(transports=[t])
    err = "perm: no https-s2s inbox_url known for 'jarvis'"

    with caplog.at_level(logging.DEBUG, logger="skcomms.router"):
        for _ in range(5):
            t.script.append(_fail(t.name, err))
            r._try_send(t, b"{}", "jarvis")

    send_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "send failed" in r.getMessage()
    ]
    send_debug = [
        r for r in caplog.records
        if r.levelno == logging.DEBUG and "send failed" in r.getMessage()
    ]
    # First failure WARNs once; the four identical repeats drop to DEBUG.
    assert len(send_warnings) == 1
    assert len(send_debug) == 4


def test_recovery_logs_once_and_rearms(caplog):
    t = ScriptedTransport()
    r = Router(transports=[t])
    err = "perm: no https-s2s inbox_url known for 'jarvis'"

    with caplog.at_level(logging.DEBUG, logger="skcomms.router"):
        t.script.append(_fail(t.name, err))
        r._try_send(t, b"{}", "jarvis")           # WARN (into failing)
        t.script.append(_fail(t.name, err))
        r._try_send(t, b"{}", "jarvis")           # DEBUG (same)
        t.script.append(_ok(t.name))
        r._try_send(t, b"{}", "jarvis")           # recovery INFO, clears state
        t.script.append(_fail(t.name, err))
        r._try_send(t, b"{}", "jarvis")           # WARN again (re-armed)

    send_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "send failed" in r.getMessage()
    ]
    recovery = [
        r for r in caplog.records
        if r.levelno == logging.INFO and "recover" in r.getMessage().lower()
    ]
    assert len(send_warnings) == 2          # once before, once after recovery
    assert len(recovery) == 1


def test_distinct_failure_signatures_each_warn_once(caplog):
    t = ScriptedTransport()
    r = Router(transports=[t])

    with caplog.at_level(logging.DEBUG, logger="skcomms.router"):
        t.script.append(_fail(t.name, "perm: no inbox_url for 'jarvis'"))
        r._try_send(t, b"{}", "jarvis")
        t.script.append(_fail(t.name, "retry: connection refused"))
        r._try_send(t, b"{}", "jarvis")

    send_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "send failed" in r.getMessage()
    ]
    # Two genuinely different failure modes each get a single WARN.
    assert len(send_warnings) == 2


def test_receive_side_warning_is_deduped(caplog):
    t = ScriptedTransport()
    r = Router(transports=[t])

    with caplog.at_level(logging.DEBUG, logger="skcomms.router"):
        for _ in range(4):
            t._recv_script.append(RuntimeError("boom"))
            r.receive_all()

    recv_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "Error receiving" in r.getMessage()
    ]
    recv_debug = [
        r for r in caplog.records
        if r.levelno == logging.DEBUG and "Error receiving" in r.getMessage()
    ]
    assert len(recv_warnings) == 1
    assert len(recv_debug) == 3
