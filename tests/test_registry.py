"""Tests for the realm peer registry (T11, ``e1dea61f``).

The registry is the **realm-discovery layer above** the T8 ``peers.json``
connectivity store. It answers "given an fqid, how do I reach + trust this
peer?" by consulting one or more *pluggable backends* and merging their
connectivity hints into a single :class:`~skcomms.registry.PeerRecord`.

Three backends ship:

    - ``SyncthingSharedBackend`` (DEFAULT, sovereign): reads a steward-maintained
      shared ``${SKCOMMS_HOME}/_realm/peers.json`` (a Syncthing Receive-Only
      folder). Offline, no network.
    - ``HttpsBackend`` (opt-in): GETs ``https://registry.<realm>/peers.json``.
      The HTTP fetcher is **injected** — tests pass a fake; nothing touches the
      network.
    - ``TailscaleBackend`` (opt-in): resolves via a ``tailscale status --json``
      dict supplied by an **injected** ``status_runner`` — tests pass a fixture;
      nothing shells out to real ``tailscale``.

``PeerRegistry.resolve(fqid)`` tries the ENABLED backends in configured order,
merging hints. ``PeerRegistry.from_config()`` reads the ``registry`` config.

Standalone: tmp SKCOMMS_HOME + a tmp ``_realm/peers.json`` + injected HTTP and
tailscale fixtures. Never hits the network or real tailscale.
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


# A typical steward-maintained shared realm file.
REALM_PEERS = {
    "peers": {
        "opus@casey.douno": {
            "fqid": "opus@casey.douno",
            "operator": "casey",
            "pgp_fingerprint": "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
            "syncthing_device_id": "ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678",
        },
        "jarvis@chef.skworld": {
            "fqid": "jarvis@chef.skworld",
            "pgp_fingerprint": "1111222233334444555566667777888899990000",
        },
    }
}


def _write_realm(home, data=None):
    realm_dir = home / "_realm"
    realm_dir.mkdir(parents=True, exist_ok=True)
    (realm_dir / "peers.json").write_text(
        json.dumps(data if data is not None else REALM_PEERS), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# PeerRecord schema + merge semantics
# ---------------------------------------------------------------------------


class TestPeerRecord:
    def test_minimal_record(self):
        from skcomms.registry import PeerRecord

        rec = PeerRecord(fqid="opus@casey.douno")
        assert rec.fqid == "opus@casey.douno"
        # operator is auto-derived from the fqid when not given
        assert rec.operator == "casey"
        assert rec.syncthing_device_id is None
        assert rec.tailscale is None
        assert rec.https is None

    def test_invalid_fqid_rejected(self):
        from skcomms.registry import PeerRecord

        with pytest.raises(ValueError):
            PeerRecord(fqid="not-an-fqid")

    def test_merge_enriches_missing_hints(self):
        from skcomms.registry import PeerRecord

        base = PeerRecord(
            fqid="opus@casey.douno",
            pgp_fingerprint="AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
            syncthing_device_id="DEV-1",
            source="syncthing-shared",
        )
        enrich = PeerRecord(
            fqid="opus@casey.douno",
            tailscale={"magicdns": "opus-casey.tailnet.ts.net", "ip": "100.64.0.2"},
            source="tailscale",
        )
        merged = base.merge(enrich)
        # base keeps its hints, gains the tailscale hint
        assert merged.syncthing_device_id == "DEV-1"
        assert merged.tailscale == {
            "magicdns": "opus-casey.tailnet.ts.net",
            "ip": "100.64.0.2",
        }
        assert merged.pgp_fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        # both sources are recorded
        assert "syncthing-shared" in merged.sources
        assert "tailscale" in merged.sources

    def test_merge_does_not_overwrite_existing_hint(self):
        from skcomms.registry import PeerRecord

        base = PeerRecord(fqid="opus@casey.douno", syncthing_device_id="DEV-FIRST")
        other = PeerRecord(fqid="opus@casey.douno", syncthing_device_id="DEV-SECOND")
        merged = base.merge(other)
        # first-writer wins for an already-populated hint
        assert merged.syncthing_device_id == "DEV-FIRST"

    def test_merge_requires_same_fqid(self):
        from skcomms.registry import PeerRecord

        a = PeerRecord(fqid="opus@casey.douno")
        b = PeerRecord(fqid="jarvis@chef.skworld")
        with pytest.raises(ValueError):
            a.merge(b)


# ---------------------------------------------------------------------------
# SyncthingSharedBackend (DEFAULT)
# ---------------------------------------------------------------------------


class TestSyncthingSharedBackend:
    def test_lookup_hit(self, home):
        _write_realm(home)
        from skcomms.registry import SyncthingSharedBackend

        be = SyncthingSharedBackend()
        rec = be.lookup("opus@casey.douno")
        assert rec is not None
        assert rec.fqid == "opus@casey.douno"
        assert rec.syncthing_device_id.startswith("ABCDEF1")
        assert rec.pgp_fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        assert rec.source == "syncthing-shared"

    def test_lookup_miss(self, home):
        _write_realm(home)
        from skcomms.registry import SyncthingSharedBackend

        assert SyncthingSharedBackend().lookup("nobody@nowhere.void") is None

    def test_lookup_no_realm_file(self, home):
        # _realm/peers.json absent -> no crash, just a miss
        from skcomms.registry import SyncthingSharedBackend

        assert SyncthingSharedBackend().lookup("opus@casey.douno") is None

    def test_list(self, home):
        _write_realm(home)
        from skcomms.registry import SyncthingSharedBackend

        recs = SyncthingSharedBackend().list()
        fqids = {r.fqid for r in recs}
        assert fqids == {"opus@casey.douno", "jarvis@chef.skworld"}


# ---------------------------------------------------------------------------
# HttpsBackend (opt-in) — injected fetcher, never hits network
# ---------------------------------------------------------------------------


class TestHttpsBackend:
    def _fetcher(self, payload):
        seen = {}

        def fetch(url: str) -> str:
            seen["url"] = url
            return json.dumps(payload)

        fetch.seen = seen  # type: ignore[attr-defined]
        return fetch

    def test_lookup_hit_via_injected_fetcher(self):
        from skcomms.registry import HttpsBackend

        fetch = self._fetcher(REALM_PEERS)
        be = HttpsBackend(
            url_template="https://registry.{realm}/peers.json",
            realm="douno",
            fetcher=fetch,
        )
        rec = be.lookup("opus@casey.douno")
        assert rec is not None
        assert rec.source == "https"
        assert rec.syncthing_device_id.startswith("ABCDEF1")
        # URL templated with the realm — never hardcoded
        assert fetch.seen["url"] == "https://registry.douno/peers.json"

    def test_lookup_miss(self):
        from skcomms.registry import HttpsBackend

        be = HttpsBackend(
            url_template="https://registry.{realm}/peers.json",
            realm="douno",
            fetcher=self._fetcher(REALM_PEERS),
        )
        assert be.lookup("ghost@nowhere.void") is None

    def test_fetch_error_is_a_miss_not_a_crash(self):
        from skcomms.registry import HttpsBackend

        def boom(url):
            raise OSError("network down")

        be = HttpsBackend(
            url_template="https://registry.{realm}/peers.json",
            realm="douno",
            fetcher=boom,
        )
        assert be.lookup("opus@casey.douno") is None
        assert be.list() == []

    def test_list(self):
        from skcomms.registry import HttpsBackend

        be = HttpsBackend(
            url_template="https://registry.{realm}/peers.json",
            realm="douno",
            fetcher=self._fetcher(REALM_PEERS),
        )
        assert {r.fqid for r in be.list()} == {
            "opus@casey.douno",
            "jarvis@chef.skworld",
        }


# ---------------------------------------------------------------------------
# TailscaleBackend (opt-in) — injected status_runner, never shells out
# ---------------------------------------------------------------------------


# A fixture mimicking `tailscale status --json`. Hostname convention:
#   skcomms-<agent>-<operator>   (DNSName/HostName)
# A node tagged tag:skcomms whose host matches the fqid's agent+operator maps.
TS_STATUS = {
    "Self": {
        "HostName": "skcomms-lumina-chef",
        "DNSName": "skcomms-lumina-chef.tailnet.ts.net.",
        "TailscaleIPs": ["100.64.0.1"],
    },
    "Peer": {
        "nodekey:aaa": {
            "HostName": "skcomms-opus-casey",
            "DNSName": "skcomms-opus-casey.tailnet.ts.net.",
            "TailscaleIPs": ["100.64.0.2", "fd7a::2"],
            "Tags": ["tag:skcomms"],
            "Online": True,
        },
        "nodekey:bbb": {
            "HostName": "some-laptop",
            "DNSName": "some-laptop.tailnet.ts.net.",
            "TailscaleIPs": ["100.64.0.3"],
            "Online": False,
        },
    },
}


class TestTailscaleBackend:
    def _runner(self, status=None):
        def run():
            return status if status is not None else TS_STATUS

        return run

    def test_lookup_maps_host_to_fqid(self):
        from skcomms.registry import TailscaleBackend

        be = TailscaleBackend(status_runner=self._runner())
        rec = be.lookup("opus@casey.douno")
        assert rec is not None
        assert rec.source == "tailscale"
        assert rec.tailscale["magicdns"] == "skcomms-opus-casey.tailnet.ts.net"
        assert rec.tailscale["ip"] == "100.64.0.2"
        assert rec.tailscale["node"] == "skcomms-opus-casey"

    def test_lookup_miss_for_unknown_agent(self):
        from skcomms.registry import TailscaleBackend

        be = TailscaleBackend(status_runner=self._runner())
        assert be.lookup("nobody@nowhere.void") is None

    def test_untagged_nonmatching_host_ignored(self):
        from skcomms.registry import TailscaleBackend

        be = TailscaleBackend(status_runner=self._runner())
        # some-laptop has no skcomms- prefix and no tag -> not discoverable
        assert be.list() and all(
            r.fqid != "@some-laptop" for r in be.list()
        )

    def test_runner_error_is_a_miss(self):
        from skcomms.registry import TailscaleBackend

        def boom():
            raise OSError("tailscale not installed")

        be = TailscaleBackend(status_runner=boom)
        assert be.lookup("opus@casey.douno") is None
        assert be.list() == []

    def test_list_includes_self_and_peers(self):
        from skcomms.registry import TailscaleBackend

        be = TailscaleBackend(status_runner=self._runner())
        hosts = {r.tailscale["node"] for r in be.list()}
        assert "skcomms-opus-casey" in hosts
        assert "skcomms-lumina-chef" in hosts


# ---------------------------------------------------------------------------
# PeerRegistry — order + merge
# ---------------------------------------------------------------------------


class TestPeerRegistryResolve:
    def test_default_enabled_is_syncthing_only(self, home):
        _write_realm(home)
        from skcomms.registry import PeerRegistry, SyncthingSharedBackend

        reg = PeerRegistry(backends=[SyncthingSharedBackend()])
        rec = reg.resolve("opus@casey.douno")
        assert rec is not None
        assert rec.syncthing_device_id.startswith("ABCDEF1")
        assert rec.sources == ["syncthing-shared"]

    def test_resolve_miss_returns_none(self, home):
        _write_realm(home)
        from skcomms.registry import PeerRegistry, SyncthingSharedBackend

        reg = PeerRegistry(backends=[SyncthingSharedBackend()])
        assert reg.resolve("ghost@nowhere.void") is None

    def test_resolve_merges_across_backends_in_order(self, home):
        # syncthing has the device id; tailscale adds the magicdns hint.
        _write_realm(
            home,
            {
                "peers": {
                    "opus@casey.douno": {
                        "fqid": "opus@casey.douno",
                        "pgp_fingerprint": "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
                        "syncthing_device_id": "DEV-ST",
                    }
                }
            },
        )
        from skcomms.registry import (
            PeerRegistry,
            SyncthingSharedBackend,
            TailscaleBackend,
        )

        ts = TailscaleBackend(status_runner=lambda: TS_STATUS)
        reg = PeerRegistry(backends=[SyncthingSharedBackend(), ts])
        rec = reg.resolve("opus@casey.douno")
        assert rec is not None
        # device id from syncthing-shared (first backend)
        assert rec.syncthing_device_id == "DEV-ST"
        # tailscale hint merged in
        assert rec.tailscale["node"] == "skcomms-opus-casey"
        assert rec.sources == ["syncthing-shared", "tailscale"]

    def test_order_is_respected(self, home):
        # Same fqid present in both backends with conflicting device ids.
        # The FIRST backend in order wins for an already-populated hint.
        _write_realm(
            home,
            {
                "peers": {
                    "opus@casey.douno": {
                        "fqid": "opus@casey.douno",
                        "syncthing_device_id": "DEV-FROM-SYNCTHING",
                    }
                }
            },
        )
        from skcomms.registry import (
            HttpsBackend,
            PeerRegistry,
            SyncthingSharedBackend,
        )

        https_payload = {
            "peers": {
                "opus@casey.douno": {
                    "fqid": "opus@casey.douno",
                    "syncthing_device_id": "DEV-FROM-HTTPS",
                }
            }
        }
        https = HttpsBackend(
            url_template="https://registry.{realm}/peers.json",
            realm="douno",
            fetcher=lambda url: json.dumps(https_payload),
        )
        reg = PeerRegistry(backends=[SyncthingSharedBackend(), https])
        rec = reg.resolve("opus@casey.douno")
        assert rec.syncthing_device_id == "DEV-FROM-SYNCTHING"

    def test_list_merges_all_backends(self, home):
        _write_realm(home)
        from skcomms.registry import PeerRegistry, SyncthingSharedBackend

        reg = PeerRegistry(backends=[SyncthingSharedBackend()])
        fqids = {r.fqid for r in reg.list()}
        assert fqids == {"opus@casey.douno", "jarvis@chef.skworld"}


# ---------------------------------------------------------------------------
# PeerRegistry.from_config
# ---------------------------------------------------------------------------


class TestPeerRegistryFromConfig:
    def test_default_config_enables_only_syncthing(self, home):
        _write_realm(home)
        from skcomms.registry import PeerRegistry

        reg = PeerRegistry.from_config()
        # only syncthing-shared enabled by default
        assert [b.name for b in reg.backends] == ["syncthing-shared"]
        rec = reg.resolve("opus@casey.douno")
        assert rec is not None
        assert rec.syncthing_device_id.startswith("ABCDEF1")

    def test_config_can_enable_and_order_backends(self, home):
        _write_realm(home)
        from skcomms.config import RegistryConfig
        from skcomms.registry import PeerRegistry

        cfg = RegistryConfig(
            enabled=["tailscale", "syncthing-shared"],
            order=["tailscale", "syncthing-shared"],
        )
        reg = PeerRegistry.from_config(
            cfg, tailscale_status_runner=lambda: TS_STATUS
        )
        assert [b.name for b in reg.backends] == ["tailscale", "syncthing-shared"]


# ---------------------------------------------------------------------------
# RegistryConfig
# ---------------------------------------------------------------------------


class TestRegistryConfig:
    def test_sovereign_defaults(self):
        from skcomms.config import RegistryConfig

        cfg = RegistryConfig()
        # Sovereign default: only the offline syncthing-shared backend.
        assert cfg.enabled == ["syncthing-shared"]
        assert cfg.order == ["syncthing-shared", "https", "tailscale"]
        assert cfg.https_url_template == "https://registry.{realm}/peers.json"
