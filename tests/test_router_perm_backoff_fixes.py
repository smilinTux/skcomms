"""Regressions for the perm-backoff / log-dedup hardening.

Covers:
  * Finding 3 (PERM_BACKOFF WEDGES ON TRANSIENT): a send to a not-yet-discovered
    peer (https-s2s has no inbox_url for it) is TRANSIENT, not structural. It must
    NOT arm the growing per-recipient _perm_backoff (which would divert directed
    traffic off the only direct rail for up to 1h and could never self-clear).
  * Finding 4 (PERM_BACKOFF UNBOUNDED): the _perm_backoff dict is size-capped +
    TTL-evicted, mirroring _seen_ids, so never-succeeding recipients don't leak.
  * Finding 5 (LOG-DEDUP SIGNATURE COLLAPSE): the dedup key includes the
    recipient, so a genuinely-new failing recipient still warns once even when
    the error signature matches an already-warned recipient on the same rail.
  * Finding 6 (STORE-FORWARD IGNORES QUARANTINE): _try_store_forward honors
    _quarantined like _select_transports.
"""

from __future__ import annotations

import logging

import skcomms.router as router_mod
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
    TransportStatus,
)
from skcomms.transports.http_s2s import HttpS2STransport


class ScriptedTransport(Transport):
    def __init__(self, name="file", category=TransportCategory.FILE_BASED):
        self.name = name
        self.priority = 1
        self.category = category
        self.script: list = []

    def configure(self, config: dict) -> None:
        pass

    def is_available(self) -> bool:
        return True

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        if self.script:
            return self.script.pop(0)
        return SendResult(success=True, transport_name=self.name, envelope_id="", latency_ms=0.0)

    def receive(self) -> list[bytes]:
        return []

    def health_check(self) -> HealthStatus:
        return HealthStatus(transport_name=self.name, status=TransportStatus.AVAILABLE)


def _fail(name, error):
    return SendResult(success=False, transport_name=name, envelope_id="", latency_ms=0.0, error=error)


# --------------------------------------------------------------------------
# Finding 3: undiscovered-peer failure is transient, does NOT perm-backoff.
# --------------------------------------------------------------------------
def test_undiscovered_peer_does_not_perm_backoff_direct_rail(monkeypatch):
    """A real https-s2s send to a peer with no known inbox_url is transient."""
    t = HttpS2STransport()
    # Bypass the local signed-payload structural gate — we want to reach the
    # inbox_url resolution step (the not-yet-discovered class of failure).
    monkeypatch.setattr(
        "skcomms.transports.http_s2s.classify_envelope_json",
        lambda s: "signed",
    )
    # Peer is undiscovered → no inbox_url.
    monkeypatch.setattr(t, "_resolve_inbox_url", lambda recipient: None)

    r = Router(transports=[t])
    result = r._try_send(t, b"{}", "R")

    assert result.success is False
    # The failure must NOT be classified structural/permanent.
    assert not (result.error or "").startswith("perm:")
    # The only direct rail must remain usable for this recipient.
    assert ("https-s2s", "R") not in r._perm_backoff


def test_genuinely_structural_perm_still_backs_off():
    """A structural perm (e.g. 4xx / non-signed refusal) still arms backoff."""
    t = ScriptedTransport(name="https-s2s")
    t.script.append(_fail(t.name, "perm: refusing non-SignedEnvelope payload on https-s2s"))
    r = Router(transports=[t])
    r._try_send(t, b"{}", "ghost")
    assert ("https-s2s", "ghost") in r._perm_backoff


# --------------------------------------------------------------------------
# Finding 4: _perm_backoff is bounded under many distinct failing recipients.
# --------------------------------------------------------------------------
def test_perm_backoff_bounded_under_many_recipients(monkeypatch):
    monkeypatch.setattr(router_mod, "PERM_BACKOFF_MAX_ENTRIES", 100)
    t = ScriptedTransport(name="https-s2s")
    r = Router(transports=[t])
    for i in range(500):
        t.script.append(_fail(t.name, f"perm: no route for 'ghost-{i}'"))
        r._try_send(t, b"{}", f"ghost-{i}")
    assert len(r._perm_backoff) <= 100


# --------------------------------------------------------------------------
# Finding 5: a new failing recipient warns once even on a warned rail.
# --------------------------------------------------------------------------
def test_new_recipient_warns_once_despite_matching_signature(caplog):
    t = ScriptedTransport(name="https-s2s")
    r = Router(transports=[t])
    with caplog.at_level(logging.DEBUG, logger="skcomms.router"):
        # Recipient A: same structural error → first WARN.
        t.script.append(_fail(t.name, "perm: no https-s2s inbox_url known for 'alice'"))
        r._try_send(t, b"{}", "alice")
        # Recipient B: signature normalizes identically, but it's a NEW recipient
        # → must still WARN once (was silently DEBUG-suppressed before the fix).
        t.script.append(_fail(t.name, "perm: no https-s2s inbox_url known for 'bob'"))
        r._try_send(t, b"{}", "bob")

    warnings = [
        rec for rec in caplog.records
        if rec.levelno == logging.WARNING and "send failed" in rec.getMessage()
    ]
    assert len(warnings) == 2


# --------------------------------------------------------------------------
# Finding 6: store-and-forward honors quarantine.
# --------------------------------------------------------------------------
def test_store_forward_skips_quarantined_rail():
    sf = ScriptedTransport(name="nostr-sf")
    r = Router(transports=[sf], store_forward_transport="nostr-sf")
    r.quarantine_transport("nostr-sf")

    env = MessageEnvelope(
        sender="lumina", recipient="ghost",
        payload=MessagePayload(content="x"),
        routing=RoutingConfig(mode=RoutingMode.FAILOVER),
    )
    from skcomms.transport import DeliveryReport

    report = DeliveryReport(envelope_id="e", delivered=False, attempts=[])
    out = r._try_store_forward(b"{}", env, candidates=[], report=report)
    # Quarantined S&F rail must not have been attempted.
    assert out.attempts == []
    assert sf.script == []  # send never called
