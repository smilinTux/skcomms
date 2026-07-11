"""Regression: ephemeral CoT beacons must PRESERVE delivery by default.

Finding 1 (FAIL-CLOSED BREAKS TAK): ``federation_ingest`` is wired from
``cot_service`` with NO providers, so its default beacon peer set was the
fail-closed :func:`_cot_peer_fqids` gate — which returns ``[]`` unless a peer
advertises a cot/tak capability or ``SKCOMMS_COT_PEERS`` is set. On any existing
deployment (capabilities unset, env unset) that silently federates every ``a-*``
PLI beacon to ZERO peers after upgrade.

The fix: default beacon fan-out PRESERVES delivery — beacons go to the full
federation peer set (same as durable events), still short-TTL + no-ack +
supersede_key. The CoT-capability restriction is OPT-IN, engaging only when
``SKCOMMS_COT_STRICT=1``, a peer advertises a cot/tak capability, or
``SKCOMMS_COT_PEERS`` is set.
"""

from __future__ import annotations

import skcomms.discovery as discovery_mod
from skcomms.cot import parse_cot
from skcomms.cot_server import (
    _default_beacon_peer_fqids,
    federation_ingest,
)
from skcomms.discovery import PeerInfo, PeerTransport

PLI = (  # a CoT atom -> ephemeral position beacon (PLI). stale = time + 5 min.
    '<event version="2.0" uid="ANDROID-1" type="a-f-G-U-C" how="m-g"'
    ' time="2026-06-22T03:00:00.000Z" start="2026-06-22T03:00:00.000Z"'
    ' stale="2026-06-22T03:05:00.000Z">'
    '<point lat="38.8895" lon="-77.0353" hae="50.0" ce="9.0" le="9.0"/>'
    '<detail><contact callsign="JARVIS-1"/></detail></event>'
)


class _RecordingSk:
    def __init__(self):
        self.calls = []

    def send_federated(self, to_fqid, message, *, content_type="text/plain",
                       supersede_key=None, ttl=None, ack_requested=None, **kw):
        self.calls.append({
            "to_fqid": to_fqid, "supersede_key": supersede_key,
            "ttl": ttl, "ack_requested": ack_requested,
        })


def _peer(name, fqid, caps=None):
    return PeerInfo(
        name=name, fqid=fqid,
        capabilities=list(caps or []),
        transports=[PeerTransport(
            transport="https-s2s",
            settings={"inbox_url": f"https://{name}.example/api/v1/inbox"},
        )],
    )


def _patch_peers(monkeypatch, peers):
    class _FakeStore:
        def __init__(self, *a, **kw):
            pass

        def list_all(self):
            return peers

    monkeypatch.setattr(discovery_mod, "PeerStore", _FakeStore)


def _clear_env(monkeypatch):
    monkeypatch.delenv("SKCOMMS_COT_PEERS", raising=False)
    monkeypatch.delenv("SKCOMMS_COT_STRICT", raising=False)


# --------------------------------------------------------------------------
# Default (nothing configured) → full federation peer set, short-ttl/no-ack.
# --------------------------------------------------------------------------
def test_default_beacon_peers_is_full_federation_set(monkeypatch):
    _clear_env(monkeypatch)
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),
        _peer("lumina", "lumina@chef.skworld"),
    ])
    assert set(_default_beacon_peer_fqids()) == {
        "chef@chef.skworld", "lumina@chef.skworld",
    }


def test_default_hook_fans_beacon_to_full_set_with_short_ttl_no_ack(monkeypatch):
    """No providers supplied (the cot_service wiring) → full set, ephemeral wire."""
    _clear_env(monkeypatch)
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),
        _peer("lumina", "lumina@chef.skworld"),
    ])
    sk = _RecordingSk()
    hook = federation_ingest(sk, from_fqid="jarvis@chef.skworld")  # NO providers
    hook(parse_cot(PLI))
    recipients = {c["to_fqid"] for c in sk.calls}
    assert recipients == {"chef@chef.skworld", "lumina@chef.skworld"}
    for c in sk.calls:
        assert c["ack_requested"] is False
        assert isinstance(c["ttl"], int) and 0 < c["ttl"] <= 300
        assert c["supersede_key"] is not None


# --------------------------------------------------------------------------
# Opt-in restriction: strict env / advertised capability / env allowlist.
# --------------------------------------------------------------------------
def test_strict_mode_restricts_to_cot_capable_peers(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("SKCOMMS_COT_STRICT", "1")
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),                    # human, no CoT
        _peer("atak", "atak@chef.skworld", caps=["cot"]),      # advertises CoT
    ])
    assert set(_default_beacon_peer_fqids()) == {"atak@chef.skworld"}


def test_advertised_capability_engages_gate(monkeypatch):
    """A peer advertising cot/tak opts the whole node into the restriction."""
    _clear_env(monkeypatch)
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),                    # human, no CoT
        _peer("wintak", "wintak@chef.skworld", caps=["TAK"]),  # advertises TAK
    ])
    assert set(_default_beacon_peer_fqids()) == {"wintak@chef.skworld"}


def test_env_allowlist_engages_gate(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("SKCOMMS_COT_PEERS", "lumina@chef.skworld")
    _patch_peers(monkeypatch, [
        _peer("chef", "chef@chef.skworld"),
        _peer("lumina", "lumina@chef.skworld"),
    ])
    assert _default_beacon_peer_fqids() == ["lumina@chef.skworld"]
