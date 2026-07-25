"""Tests for the cluster.json schema + validated reader (coord task T1).

Covers:
    - ClusterConfig schema (full + minimal + invalid)
    - load_cluster_config: typed object on success, ClusterConfigError on
      missing / malformed JSON / schema violation
    - path argument + $SKCOMMS_CLUSTER_JSON env override + precedence
    - load_cluster (lenient) path argument
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skcomms.cluster import (
    CLUSTER_ENV_VAR,
    ClusterConfig,
    ClusterConfigError,
    load_cluster,
    load_cluster_config,
)

FULL = {
    "realm": "skworld.io",
    "operator": "chef",
    "operator_pubkey_fingerprint": "D8920EA86742260161A220C30355DE4AA63CCD69",
    "created_at": "2026-06-10T00:00:00+00:00",
}


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Ensure the env override never leaks in from the host."""
    monkeypatch.delenv(CLUSTER_ENV_VAR, raising=False)


def _write(tmp_path: Path, data) -> Path:
    f = tmp_path / "cluster.json"
    if isinstance(data, str):
        f.write_text(data)
    else:
        f.write_text(json.dumps(data))
    return f


# ---------------------------------------------------------------------------
# ClusterConfig schema
# ---------------------------------------------------------------------------


class TestClusterConfigSchema:
    def test_full_parses(self):
        cfg = ClusterConfig.model_validate(FULL)
        assert cfg.realm == "skworld.io"
        assert cfg.operator == "chef"
        assert cfg.operator_pubkey_fingerprint == FULL["operator_pubkey_fingerprint"]
        assert cfg.created_at == FULL["created_at"]

    def test_minimal_parses(self):
        cfg = ClusterConfig.model_validate({"realm": "skworld", "operator": "chef"})
        assert cfg.realm == "skworld"
        assert cfg.operator == "chef"
        assert cfg.operator_pubkey_fingerprint is None
        assert cfg.created_at is None

    def test_missing_operator_rejected(self):
        with pytest.raises(Exception):
            ClusterConfig.model_validate({"realm": "skworld"})

    def test_blank_realm_rejected(self):
        with pytest.raises(Exception):
            ClusterConfig.model_validate({"realm": "  ", "operator": "chef"})

    def test_bad_fingerprint_rejected(self):
        with pytest.raises(Exception):
            ClusterConfig.model_validate(
                {"realm": "skworld", "operator": "chef", "operator_pubkey_fingerprint": "nothex"}
            )

    def test_extra_fields_allowed(self):
        cfg = ClusterConfig.model_validate(
            {"realm": "skworld", "operator": "chef", "nodes": ["a", "b"]}
        )
        assert cfg.realm == "skworld"


# ---------------------------------------------------------------------------
# load_cluster_config (strict, validated)
# ---------------------------------------------------------------------------


class TestLoadClusterConfig:
    def test_valid_returns_typed_object(self, tmp_path: Path):
        f = _write(tmp_path, FULL)
        cfg = load_cluster_config(path=f)
        assert isinstance(cfg, ClusterConfig)
        assert cfg.realm == "skworld.io"
        assert cfg.operator == "chef"

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(ClusterConfigError, match="not found"):
            load_cluster_config(path=tmp_path / "nope.json")

    def test_malformed_json_raises(self, tmp_path: Path):
        f = _write(tmp_path, "{ not valid json ")
        with pytest.raises(ClusterConfigError, match="not valid JSON"):
            load_cluster_config(path=f)

    def test_schema_violation_raises(self, tmp_path: Path):
        f = _write(tmp_path, {"realm": "skworld"})  # missing operator
        with pytest.raises(ClusterConfigError, match="failed validation"):
            load_cluster_config(path=f)

    def test_bad_fingerprint_raises(self, tmp_path: Path):
        f = _write(
            tmp_path,
            {"realm": "skworld", "operator": "chef", "operator_pubkey_fingerprint": "zz"},
        )
        with pytest.raises(ClusterConfigError, match="failed validation"):
            load_cluster_config(path=f)

    def test_env_override_honored(self, tmp_path: Path, monkeypatch):
        f = _write(tmp_path, FULL)
        monkeypatch.setenv(CLUSTER_ENV_VAR, str(f))
        cfg = load_cluster_config()
        assert cfg.realm == "skworld.io"

    def test_explicit_path_beats_env(self, tmp_path: Path, monkeypatch):
        env_file = tmp_path / "env.json"
        env_file.write_text(json.dumps({"realm": "from-env", "operator": "chef"}))
        arg_file = tmp_path / "arg.json"
        arg_file.write_text(json.dumps({"realm": "from-arg", "operator": "chef"}))
        monkeypatch.setenv(CLUSTER_ENV_VAR, str(env_file))
        cfg = load_cluster_config(path=arg_file)
        assert cfg.realm == "from-arg"


# ---------------------------------------------------------------------------
# load_cluster (lenient) path argument
# ---------------------------------------------------------------------------


class TestLoadClusterLenient:
    def test_path_argument(self, tmp_path: Path):
        f = _write(tmp_path, FULL)
        data = load_cluster(path=f)
        assert data is not None
        assert data["realm"] == "skworld.io"

    def test_missing_returns_none(self, tmp_path: Path):
        assert load_cluster(path=tmp_path / "nope.json") is None

    def test_malformed_returns_none(self, tmp_path: Path):
        f = _write(tmp_path, "{ broken ")
        assert load_cluster(path=f) is None

    def test_env_override_honored(self, tmp_path: Path, monkeypatch):
        f = _write(tmp_path, FULL)
        monkeypatch.setenv(CLUSTER_ENV_VAR, str(f))
        data = load_cluster()
        assert data is not None
        assert data["operator"] == "chef"
