"""Tests for ``skcomms cluster init`` (chiap08 send-path stopgap).

The realm anchor cluster.json had no creator command: hosts without one
failed deep in the send path. These tests prove the bootstrap writes a file
that load_cluster_config() accepts, refuses overwrite without --force, and
rejects schema-invalid values without writing.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from skcomms.cli import main
from skcomms.cluster import load_cluster_config


def _invoke(args: list[str]):
    return CliRunner().invoke(main, ["cluster", "init", *args])


def test_writes_valid_cluster_json(tmp_path) -> None:
    home = tmp_path / "skcapstone-home"
    result = _invoke(
        [
            "--realm",
            "skworld.io",
            "--operator",
            "chef",
            "--operator-fingerprint",
            "D8920EA86742260161A220C30355DE4AA63CCD69",
            "--home",
            str(home),
        ]
    )
    assert result.exit_code == 0, result.output
    path = home / "cluster.json"
    assert path.is_file()
    config = load_cluster_config(path)
    assert config.realm == "skworld.io"
    assert config.operator == "chef"
    assert config.operator_pubkey_fingerprint == "D8920EA86742260161A220C30355DE4AA63CCD69"
    assert config.created_at
    assert "Validation" in result.output


def test_minimal_document_round_trips(tmp_path) -> None:
    home = tmp_path / "skc"
    result = _invoke(["--realm", "mesh", "--operator", "ops", "--home", str(home)])
    assert result.exit_code == 0, result.output
    config = load_cluster_config(home / "cluster.json")
    assert config.realm == "mesh"
    assert config.operator_pubkey_fingerprint is None


def test_refuses_overwrite_without_force(tmp_path) -> None:
    home = tmp_path / "skc"
    home.mkdir()
    path = home / "cluster.json"
    original = {"realm": "original", "operator": "ops"}
    path.write_text(json.dumps(original), encoding="utf-8")
    result = _invoke(["--realm", "changed", "--operator", "ops", "--home", str(home)])
    assert result.exit_code == 1
    assert "already exists" in result.output
    assert json.loads(path.read_text(encoding="utf-8")) == original


def test_force_overwrites(tmp_path) -> None:
    home = tmp_path / "skc"
    home.mkdir()
    path = home / "cluster.json"
    path.write_text(json.dumps({"realm": "original", "operator": "ops"}), encoding="utf-8")
    result = _invoke(["--realm", "changed", "--operator", "ops", "--home", str(home), "--force"])
    assert result.exit_code == 0, result.output
    assert load_cluster_config(path).realm == "changed"


@pytest.mark.parametrize(
    "args",
    [
        ["--realm", "", "--operator", "ops"],
        ["--realm", "mesh", "--operator", "   "],
        ["--realm", "mesh", "--operator", "ops", "--operator-fingerprint", "not-hex"],
    ],
)
def test_invalid_values_are_rejected_without_writing(tmp_path, args) -> None:
    home = tmp_path / "skc"
    result = _invoke([*args, "--home", str(home)])
    assert result.exit_code == 1
    assert not (home / "cluster.json").exists()


def test_missing_required_options_fail(tmp_path) -> None:
    result = _invoke(["--realm", "mesh", "--home", str(tmp_path)])
    assert result.exit_code != 0
