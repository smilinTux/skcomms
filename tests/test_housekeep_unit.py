"""The shipped housekeep unit must sweep every agent the node hosts.

A hub serves several agents behind one Syncthing node. The daemon's internal
loop covers only the active agent, so a unit without ``--all-agents`` leaves
every other agent's outbox and dead letters to grow (the 140k-file freeze
class). Found by the CMDB drift triage on noroc2027, 2026-11-11.
"""

from pathlib import Path

UNIT = Path(__file__).resolve().parents[1] / "contrib" / "systemd" / "skcomms-housekeep.service"


def test_housekeep_unit_runs_for_all_agents() -> None:
    exec_lines = [l for l in UNIT.read_text().splitlines() if l.startswith("ExecStart=")]
    assert exec_lines == ["ExecStart=%h/.skenv/bin/skcomms housekeep --all-agents"]
