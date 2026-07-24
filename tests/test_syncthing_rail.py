"""Tests for the Syncthing rail provisioning + share-health (coord ``2c103c2d``).

The file/syncthing failover rail replicates the realm message tree between
machines with Syncthing, driven by ``peers.json`` and the
Send-Only-self / Receive-Only-per-peer topology (docs/SYNCTHING_TOPOLOGY.md).
This suite covers:

  provisioning
    - build_topology derives the right self + per-peer folders/devices from peers.
    - plan_provision on an EMPTY config = create everything; idempotent re-run
      on a satisfied config = no changes.
    - provision_rail (apply) drives the injected REST client: devices added,
      folders PUT with the right type + device sharing; a second run is a no-op.
    - a folder that already exists with the WRONG type is reported, never flipped.

  share-health
    - a fully-shared, all-connected, synced, conflict-free tree = OK.
    - the self folder missing from config = FAIL (never provisioned).
    - a peer device not shared on the folder = FAIL.
    - zero connected peers = FAIL; some-but-not-all = WARN.
    - a *.sync-conflict-* file in the tree = FAIL.
    - an aged outbox envelope = WARN (distinct from queue depth).
    - no peers declared at all = FAIL (get-two collapsed).

Standalone: no real Syncthing daemon, no live config mutation — a FakeRest
supplies every REST response, and a tmp home holds the message tree.
"""

from __future__ import annotations

import time

import pytest

from skcomms.syncthing_rail import (
    FOLDER_RECEIVEONLY,
    FOLDER_SENDONLY,
    RailStatus,
    build_topology,
    check_share_health,
    find_conflict_files,
    find_stale_outbox,
    folder_id,
    fqid_parts,
    plan_provision,
    provision_rail,
)

REALM = "skworld"
OPERATOR = "chef"

# Two peers on distinct operators; a third peer sharing the same operator as the
# first exercises device de-dup + folder-per-operator grouping.
OPUS_DEV = "OPUSDEV-1111111-OPUSDEV-2222222-OPUSDEV-3333333-OPUSDEV-4444444"
JARVIS_DEV = "JARVDEV-1111111-JARVDEV-2222222-JARVDEV-3333333-JARVDEV-4444444"

PEERS = {
    "opus@casey.douno": {"syncthing_device_id": OPUS_DEV, "fingerprint": "AAAA", "added_at": "x"},
    "jarvis@rick.morty": {"syncthing_device_id": JARVIS_DEV, "fingerprint": "BBBB", "added_at": "y"},
}


class FakeRest:
    """In-memory Syncthing REST double — records writes, serves canned reads."""

    def __init__(self, config=None, connections=None, completion=None, my_id="SELFDEV"):
        self._config = config or {"devices": [], "folders": []}
        self._connections = connections or {"connections": {}}
        self._completion = completion or {}
        self._my_id = my_id
        self.put_devices = []
        self.put_folders = []

    def get_config(self):
        return self._config

    def connections(self):
        return self._connections

    def my_id(self):
        return self._my_id

    def completion(self, folder, device):
        return self._completion.get((folder, device), {"completion": 100, "needItems": 0})

    def put_device(self, device):
        self.put_devices.append(device)
        self._config["devices"].append(device)

    def put_folder(self, folder):
        self.put_folders.append(folder)
        # Replace-or-append by id so a re-plan sees the applied state.
        self._config["folders"] = [
            f for f in self._config["folders"] if f.get("id") != folder["id"]
        ] + [folder]


# ---------------------------------------------------------------------------
# helpers / conventions
# ---------------------------------------------------------------------------


def test_fqid_parts_and_folder_id():
    assert fqid_parts("opus@casey.douno") == ("opus", "casey", "douno")
    assert folder_id("douno", "casey") == "skcomms-douno-casey"
    with pytest.raises(ValueError):
        fqid_parts("not-an-fqid")


# ---------------------------------------------------------------------------
# topology
# ---------------------------------------------------------------------------


def test_build_topology_self_sendonly_and_peer_receiveonly(tmp_path):
    topo = build_topology(REALM, OPERATOR, tmp_path, PEERS)

    assert topo.self_folder.id == "skcomms-skworld-chef"
    assert topo.self_folder.type == FOLDER_SENDONLY
    assert topo.self_folder.path == str(tmp_path / "skworld" / "chef")
    # self folder is shared with BOTH peer devices
    assert set(topo.self_folder.device_ids) == {OPUS_DEV, JARVIS_DEV}

    # one receive-only folder per distinct peer operator
    peer_ids = {f.id for f in topo.peer_folders}
    assert peer_ids == {"skcomms-douno-casey", "skcomms-morty-rick"}
    for pf in topo.peer_folders:
        assert pf.type == FOLDER_RECEIVEONLY
        assert pf.path.startswith(str(tmp_path / "peers"))

    assert topo.devices == {OPUS_DEV: "casey", JARVIS_DEV: "rick"}


def test_build_topology_skips_peer_without_device_id(tmp_path):
    peers = {"ghost@nobody.nowhere": {"fingerprint": "CCCC"}}  # no device id
    topo = build_topology(REALM, OPERATOR, tmp_path, peers)
    assert topo.self_folder.device_ids == []
    assert topo.devices == {}


# ---------------------------------------------------------------------------
# provisioning
# ---------------------------------------------------------------------------


def test_plan_provision_empty_config_creates_everything():
    topo = build_topology(REALM, OPERATOR, "/home/x/.skcomms", PEERS)
    plan = plan_provision(topo, {"devices": [], "folders": []})

    assert not plan.unchanged
    assert set(plan.added_devices) == {OPUS_DEV, JARVIS_DEV}
    assert set(plan.added_folders) == {
        "skcomms-skworld-chef",
        "skcomms-douno-casey",
        "skcomms-morty-rick",
    }
    # self folder shared with both peers
    assert f"skcomms-skworld-chef+{OPUS_DEV}" in plan.shared
    assert f"skcomms-skworld-chef+{JARVIS_DEV}" in plan.shared


def test_provision_rail_apply_then_idempotent(tmp_path):
    rest = FakeRest()
    result = provision_rail(
        rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR, apply=True
    )
    assert result.applied
    assert not result.unchanged
    # both peer devices provisioned
    assert {d["deviceID"] for d in rest.put_devices} == {OPUS_DEV, JARVIS_DEV}
    # self folder PUT with sendonly + self device + both peers
    self_put = next(f for f in rest.put_folders if f["id"] == "skcomms-skworld-chef")
    assert self_put["type"] == FOLDER_SENDONLY
    dev_ids = {d["deviceID"] for d in self_put["devices"]}
    assert {"SELFDEV", OPUS_DEV, JARVIS_DEV} <= dev_ids

    # Second run: config now satisfied -> no changes.
    rest.put_devices.clear()
    rest.put_folders.clear()
    result2 = provision_rail(
        rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR, apply=True
    )
    assert result2.unchanged
    assert rest.put_devices == []
    assert rest.put_folders == []


def test_provision_rail_dry_run_writes_nothing(tmp_path):
    rest = FakeRest()
    result = provision_rail(
        rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR, apply=False
    )
    assert not result.applied
    assert not result.unchanged  # a plan exists...
    assert rest.put_devices == []  # ...but nothing was written
    assert rest.put_folders == []


def test_plan_reports_type_mismatch_without_flipping():
    topo = build_topology(REALM, OPERATOR, "/home/x/.skcomms", PEERS)
    # self folder already exists but as RECEIVE-ONLY (wrong) and fully shared
    config = {
        "devices": [{"deviceID": OPUS_DEV}, {"deviceID": JARVIS_DEV}],
        "folders": [
            {
                "id": "skcomms-skworld-chef",
                "type": FOLDER_RECEIVEONLY,
                "devices": [{"deviceID": OPUS_DEV}, {"deviceID": JARVIS_DEV}],
            },
            {
                "id": "skcomms-douno-casey",
                "type": FOLDER_RECEIVEONLY,
                "devices": [{"deviceID": OPUS_DEV}],
            },
            {
                "id": "skcomms-morty-rick",
                "type": FOLDER_RECEIVEONLY,
                "devices": [{"deviceID": JARVIS_DEV}],
            },
        ],
    }
    plan = plan_provision(topo, config)
    assert any("skcomms-skworld-chef" in m for m in plan.type_mismatches)
    # the mismatch is reported, but the plan does not try to re-share it
    assert not any(s.startswith("skcomms-skworld-chef+") for s in plan.shared)


# ---------------------------------------------------------------------------
# share-health
# ---------------------------------------------------------------------------


def _healthy_config():
    return {
        "devices": [{"deviceID": OPUS_DEV}, {"deviceID": JARVIS_DEV}],
        "folders": [
            {
                "id": "skcomms-skworld-chef",
                "type": FOLDER_SENDONLY,
                "devices": [
                    {"deviceID": "SELFDEV"},
                    {"deviceID": OPUS_DEV},
                    {"deviceID": JARVIS_DEV},
                ],
            }
        ],
    }


def _all_connected():
    return {"connections": {OPUS_DEV: {"connected": True}, JARVIS_DEV: {"connected": True}}}


def _find(report, name):
    return next(c for c in report.checks if c.name == name)


def test_health_all_green(tmp_path):
    rest = FakeRest(config=_healthy_config(), connections=_all_connected())
    report = check_share_health(
        rest=rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    assert report.status == RailStatus.OK
    assert _find(report, "rail_provisioned").status == RailStatus.OK
    assert _find(report, "folder_shared").status == RailStatus.OK
    assert _find(report, "peers_connected").status == RailStatus.OK
    assert _find(report, "conflicts").status == RailStatus.OK


def test_health_fail_when_self_folder_unconfigured(tmp_path):
    rest = FakeRest(config={"devices": [], "folders": []}, connections=_all_connected())
    report = check_share_health(
        rest=rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    assert report.status == RailStatus.FAIL
    assert _find(report, "rail_provisioned").status == RailStatus.FAIL


def test_health_fail_when_folder_not_shared_with_peer(tmp_path):
    cfg = _healthy_config()
    # drop JARVIS from the folder's device list -> unshared
    cfg["folders"][0]["devices"] = [{"deviceID": "SELFDEV"}, {"deviceID": OPUS_DEV}]
    rest = FakeRest(config=cfg, connections=_all_connected())
    report = check_share_health(
        rest=rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    assert report.status == RailStatus.FAIL
    shared = _find(report, "folder_shared")
    assert shared.status == RailStatus.FAIL
    assert JARVIS_DEV in shared.data["missing_devices"]


def test_health_fail_when_no_peer_connected(tmp_path):
    rest = FakeRest(config=_healthy_config(), connections={"connections": {}})
    report = check_share_health(
        rest=rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    assert report.status == RailStatus.FAIL
    assert _find(report, "peers_connected").status == RailStatus.FAIL


def test_health_warn_when_partially_connected(tmp_path):
    conns = {"connections": {OPUS_DEV: {"connected": True}, JARVIS_DEV: {"connected": False}}}
    rest = FakeRest(config=_healthy_config(), connections=conns)
    report = check_share_health(
        rest=rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    # partial connectivity is WARN (not FAIL), assuming nothing else fails
    assert _find(report, "peers_connected").status == RailStatus.WARN
    assert report.status == RailStatus.WARN


def test_health_fail_on_sync_conflict_file(tmp_path):
    # healthy REST, but a conflict file exists in the tree
    tree = tmp_path / "skworld" / "chef" / "lumina" / "inbox"
    tree.mkdir(parents=True)
    (tree / "msg.sync-conflict-20260718-120000-ABCD123.json").write_text("{}")
    rest = FakeRest(config=_healthy_config(), connections=_all_connected())
    report = check_share_health(
        rest=rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    assert report.status == RailStatus.FAIL
    conflicts = _find(report, "conflicts")
    assert conflicts.status == RailStatus.FAIL
    assert conflicts.data["count"] == 1


def test_health_warn_on_stale_outbox(tmp_path):
    outbox = tmp_path / "skworld" / "chef" / "lumina" / "outbox"
    outbox.mkdir(parents=True)
    old = outbox / "old-envelope.json"
    old.write_text("{}")
    # age it well past the threshold
    stale_time = time.time() - (48 * 3600)
    import os

    os.utime(old, (stale_time, stale_time))
    rest = FakeRest(config=_healthy_config(), connections=_all_connected())
    report = check_share_health(
        rest=rest,
        home=tmp_path,
        peers=PEERS,
        realm=REALM,
        operator=OPERATOR,
        stale_outbox_hours=6.0,
    )
    stale = _find(report, "stale_outbox")
    assert stale.status == RailStatus.WARN
    assert stale.data["count"] == 1
    assert report.status == RailStatus.WARN


def test_health_fresh_outbox_is_ok(tmp_path):
    outbox = tmp_path / "skworld" / "chef" / "lumina" / "outbox"
    outbox.mkdir(parents=True)
    (outbox / "fresh.json").write_text("{}")  # just written -> fresh
    rest = FakeRest(config=_healthy_config(), connections=_all_connected())
    report = check_share_health(
        rest=rest, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    assert _find(report, "stale_outbox").status == RailStatus.OK
    assert report.status == RailStatus.OK


def test_health_fail_when_no_peers_declared(tmp_path):
    rest = FakeRest(config={"devices": [], "folders": []}, connections={"connections": {}})
    report = check_share_health(
        rest=rest, home=tmp_path, peers={}, realm=REALM, operator=OPERATOR
    )
    assert report.status == RailStatus.FAIL
    assert _find(report, "peers_declared").status == RailStatus.FAIL


def test_health_degrades_without_rest_but_still_scans_fs(tmp_path):
    # conflict on disk, but no REST client -> conflicts still FAIL,
    # provisioning check is WARN (unknown) not a hard error.
    tree = tmp_path / "skworld" / "chef" / "lumina" / "inbox"
    tree.mkdir(parents=True)
    (tree / "m.sync-conflict-x.json").write_text("{}")
    report = check_share_health(
        rest=None, home=tmp_path, peers=PEERS, realm=REALM, operator=OPERATOR
    )
    assert _find(report, "conflicts").status == RailStatus.FAIL
    assert _find(report, "rail_provisioned").status == RailStatus.WARN
    assert report.status == RailStatus.FAIL


# ---------------------------------------------------------------------------
# filesystem scanners in isolation
# ---------------------------------------------------------------------------


def test_find_conflict_files(tmp_path):
    (tmp_path / "a").mkdir()
    good = tmp_path / "a" / "ok.json"
    good.write_text("{}")
    bad = tmp_path / "a" / "x.sync-conflict-20260101-000000-DEV.json"
    bad.write_text("{}")
    found = find_conflict_files(tmp_path)
    assert found == [bad]


def test_find_stale_outbox_only_flags_old(tmp_path):
    outbox = tmp_path / "skworld" / "chef" / "lumina" / "outbox"
    outbox.mkdir(parents=True)
    fresh = outbox / "fresh.json"
    fresh.write_text("{}")
    old = outbox / "old.json"
    old.write_text("{}")
    import os

    past = time.time() - (10 * 3600)
    os.utime(old, (past, past))
    stale = find_stale_outbox(tmp_path, REALM, OPERATOR, max_age_hours=6.0)
    assert stale == [old]
