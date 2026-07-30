"""Tests for the `skcomms operator` CLI and its probe module (R2.12).

The operator facet is the canonical explain/observe/act contract Atlas's skcomms
adapter (`skcapstone/src/skcapstone/operator_seat/skcomms_adapter.py`) mirrors.
These tests keep every probe hermetic (injected) so nothing touches a live
skcomms API, the real outbox, or systemd.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from skcomms import operator_probe as op
from skcomms.cli import main

# --- explain -----------------------------------------------------------------


def test_explain_shape_matches_contract():
    spec = op.explain()
    assert spec["kinds"] == ["path", "queue"]
    assert spec["conditions"] == ["PathHealthy", "QueueDrained"]
    names = {a["name"]: a for a in spec["actions"]}
    assert set(names) == {"restart_service", "failover_discovery"}

    # The reversible standard action.
    restart = names["restart_service"]
    assert restart["standard"] is True
    assert restart["reversible"] is True
    assert restart["blast_radius"] == "low"
    assert restart["kedb_refs"] == []

    # failover_discovery: NOT standard, reversible, fleet_restart blast (forces MAJOR).
    failover = names["failover_discovery"]
    assert failover["standard"] is False
    assert failover["reversible"] is True
    assert failover["blast_radius"] == "fleet_restart"


def test_explain_byte_compatible_with_adapter():
    # The adapter is the shared source of truth: explain() must match its shape
    # exactly (kinds/conditions/actions), so the operator brief reads one schema.
    from skcapstone.operator_seat.skcomms_adapter import skcomms_explain

    assert op.explain() == skcomms_explain()


def test_explain_cli_emits_contract_json():
    res = CliRunner().invoke(main, ["operator", "explain"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["conditions"] == op.CONDITIONS
    assert payload["kinds"] == op.KINDS


# --- observe -----------------------------------------------------------------


def _conditions(result: dict) -> dict:
    return {c["type"]: c["status"] for c in result["conditions"]}


def test_observe_all_healthy():
    probe = lambda: {  # noqa: E731
        "path_healthy": True,
        "queue_depth": 3,
        "queue_limit": 1000,
    }
    conds = _conditions(op.observe(probe))
    assert conds == {"PathHealthy": "True", "QueueDrained": "True"}


def test_observe_object_names_match_adapter():
    # observe output must be byte-compatible in shape with the adapter, down to
    # the per-condition object names.
    probe = lambda: {"path_healthy": True, "queue_depth": 0, "queue_limit": 1000}  # noqa: E731
    objects = {c["type"]: c["object"] for c in op.observe(probe)["conditions"]}
    assert objects == {"PathHealthy": "discovery-path", "QueueDrained": "queue"}


def test_observe_path_unhealthy_fires():
    probe = lambda: {  # noqa: E731
        "path_healthy": False,
        "queue_depth": 0,
        "queue_limit": 1000,
    }
    assert _conditions(op.observe(probe))["PathHealthy"] == "False"


def test_observe_queue_over_limit_fires():
    probe = lambda: {  # noqa: E731
        "path_healthy": True,
        "queue_depth": 1001,
        "queue_limit": 1000,
    }
    assert _conditions(op.observe(probe))["QueueDrained"] == "False"


def test_observe_queue_at_limit_ok():
    probe = lambda: {  # noqa: E731
        "path_healthy": True,
        "queue_depth": 1000,
        "queue_limit": 1000,
    }
    assert _conditions(op.observe(probe))["QueueDrained"] == "True"


def test_count_queue_counts_json_files(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    (tmp_path / "b.json").write_text("{}")
    (tmp_path / "c.txt").write_text("nope")  # non-json not counted
    (tmp_path / "sub").mkdir()  # dirs are not counted
    assert op._count_queue(tmp_path) == 2


def test_count_queue_missing_dir_is_zero(tmp_path):
    assert op._count_queue(tmp_path / "nope") == 0


def test_probe_path_healthy_fails_safe_when_unreachable(monkeypatch):
    # Unreachable endpoint -> healthy (True), never a false 'path down'.
    monkeypatch.setenv("SKCOMMS_HEALTH_URL", "http://127.0.0.1:1/health")
    assert op._probe_path_healthy() is True


def test_observe_cli_healthy_when_unreachable(monkeypatch, tmp_path):
    # No API, empty outbox: both conditions healthy.
    monkeypatch.setenv("SKCOMMS_HEALTH_URL", "http://127.0.0.1:1/health")
    monkeypatch.setenv("SKCOMMS_OUTBOX_DIR", str(tmp_path / "empty-outbox"))
    res = CliRunner().invoke(main, ["operator", "observe"])
    assert res.exit_code == 0, res.output
    conds = _conditions(json.loads(res.output))
    assert conds == {"PathHealthy": "True", "QueueDrained": "True"}


# --- act ---------------------------------------------------------------------


def test_act_restart_service_calls_runner_with_unit():
    calls = []

    def runner(cmd):
        calls.append(cmd)
        return {"ok": True, "returncode": 0}

    result = op.act("restart_service", runner=runner)
    assert result["performed"] is True
    assert result["unit"] == "skcomms-api.service"
    assert calls == [["systemctl", "--user", "restart", "skcomms-api.service"]]


def test_act_restart_service_honors_unit_override():
    calls = []

    def runner(cmd):
        calls.append(cmd)
        return {"ok": True, "returncode": 0}

    result = op.act("restart_service", runner=runner, unit="skcomm-daemon.service")
    assert result["performed"] is True
    assert result["unit"] == "skcomm-daemon.service"
    assert calls == [["systemctl", "--user", "restart", "skcomm-daemon.service"]]


def test_act_failover_discovery_refuses_and_escalates():
    ran = []
    result = op.act("failover_discovery", runner=lambda cmd: ran.append(cmd))
    assert result["performed"] is False
    assert result["escalate"] == "MAJOR"
    assert "non-standard" in result["reason"].lower()
    assert ran == []  # never actuates


def test_act_unknown_action_refused():
    with pytest.raises(ValueError):
        op.act("nuke-everything", runner=lambda cmd: None)


def test_act_cli_failover_reports_escalation():
    res = CliRunner().invoke(main, ["operator", "act", "failover_discovery"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["performed"] is False
    assert payload["escalate"] == "MAJOR"


def test_act_cli_unknown_action_errors():
    res = CliRunner().invoke(main, ["operator", "act", "bogus"])
    assert res.exit_code != 0
    assert "unknown" in res.output.lower()
