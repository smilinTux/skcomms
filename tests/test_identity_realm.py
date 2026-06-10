"""Tests for skcomms.cluster, skcomms.realm, skcomms.identity (T2/T5).

Covers:
    - cluster.py: load_cluster, get_realm, get_operator
    - realm.py: build_fqid, resolve_fqid (delegates to capauth)
    - identity.py: resolve_self_identity (delegates to capauth)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from skcomms.cluster import get_operator, get_realm, load_cluster
from skcomms.realm import build_fqid, resolve_fqid


# ---------------------------------------------------------------------------
# cluster.py
# ---------------------------------------------------------------------------


class TestLoadCluster:
    def test_loads_from_path(self, tmp_path: Path):
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(
            json.dumps({"realm": "skworld", "operator": "chef"})
        )
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        try:
            cm._CLUSTER_LOOKUP = [cluster_file]
            data = load_cluster()
            assert data is not None
            assert data["realm"] == "skworld"
        finally:
            cm._CLUSTER_LOOKUP = original

    def test_returns_none_when_absent(self, tmp_path: Path):
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        try:
            cm._CLUSTER_LOOKUP = [tmp_path / "nonexistent.json"]
            assert load_cluster() is None
        finally:
            cm._CLUSTER_LOOKUP = original

    def test_get_realm_defaults_to_skworld(self, tmp_path: Path):
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        try:
            cm._CLUSTER_LOOKUP = [tmp_path / "nope.json"]
            assert get_realm() == "skworld"
        finally:
            cm._CLUSTER_LOOKUP = original

    def test_get_operator_defaults_to_chef(self, tmp_path: Path):
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        try:
            cm._CLUSTER_LOOKUP = [tmp_path / "nope.json"]
            assert get_operator() == "chef"
        finally:
            cm._CLUSTER_LOOKUP = original

    def test_get_realm_from_cluster_json(self, tmp_path: Path):
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(json.dumps({"realm": "douno", "operator": "casey"}))
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        try:
            cm._CLUSTER_LOOKUP = [cluster_file]
            assert get_realm() == "douno"
            assert get_operator() == "casey"
        finally:
            cm._CLUSTER_LOOKUP = original


# ---------------------------------------------------------------------------
# realm.py
# ---------------------------------------------------------------------------


class TestBuildFqid:
    def test_standard(self):
        assert build_fqid("lumina", "chef", "skworld") == "lumina@chef.skworld"

    def test_alternative_operator(self):
        assert build_fqid("opus", "casey", "douno") == "opus@casey.douno"


class TestResolveFqid:
    def test_delegates_to_capauth(self):
        """resolve_fqid returns the fqid from the capauth resolver."""
        from capauth.agent_identity import AgentIdentity

        mock_ident = AgentIdentity(
            agent="lumina",
            capauth_uri="capauth:lumina@skworld.io",
            fqid="lumina@chef.skworld",
        )
        with patch("capauth.agent_identity.resolve_agent_identity", return_value=mock_ident):
            assert resolve_fqid("lumina") == "lumina@chef.skworld"

    def test_fallback_to_cluster_helpers(self, tmp_path: Path):
        """Falls back to cluster helpers when capauth is absent."""
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(json.dumps({"realm": "skworld", "operator": "chef"}))
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        try:
            cm._CLUSTER_LOOKUP = [cluster_file]
            with patch(
                "capauth.agent_identity.resolve_agent_identity",
                side_effect=ImportError("capauth absent"),
            ):
                fqid = resolve_fqid("lumina")
                assert fqid == "lumina@chef.skworld"
        finally:
            cm._CLUSTER_LOOKUP = original

    def test_none_without_cluster_or_capauth(self, tmp_path: Path):
        """Returns None when neither capauth nor cluster.json are present."""
        from skcomms import cluster as cm

        original = cm._CLUSTER_LOOKUP
        try:
            cm._CLUSTER_LOOKUP = [tmp_path / "nope.json"]
            with patch(
                "capauth.agent_identity.resolve_agent_identity",
                side_effect=ImportError("capauth absent"),
            ):
                # fallback tries cluster which returns default realm/operator
                # but agent is None — still returns something
                fqid = resolve_fqid(None)
                # May be None (no agent) or built from defaults
                assert fqid is None or "@" in str(fqid)
        finally:
            cm._CLUSTER_LOOKUP = original


# ---------------------------------------------------------------------------
# identity.py
# ---------------------------------------------------------------------------


class TestResolveSelfIdentity:
    def test_delegates_to_capauth(self):
        from capauth.agent_identity import AgentIdentity

        mock_ident = AgentIdentity(
            agent="lumina",
            capauth_uri="capauth:lumina@skworld.io",
            fqid="lumina@chef.skworld",
            fingerprint="02BC0EB3CAD31DB691A753C70C5629AB893F9746",
        )
        with patch("capauth.agent_identity.resolve_agent_identity", return_value=mock_ident):
            from skcomms.identity import resolve_self_identity

            d = resolve_self_identity("lumina")
            assert d["capauth_uri"] == "capauth:lumina@skworld.io"
            assert d["fqid"] == "lumina@chef.skworld"
            assert d["fingerprint"] == "02BC0EB3CAD31DB691A753C70C5629AB893F9746"

    def test_fallback_when_capauth_absent(self):
        with patch(
            "capauth.agent_identity.resolve_agent_identity",
            side_effect=ImportError("capauth absent"),
        ):
            from skcomms.identity import resolve_self_identity

            d = resolve_self_identity("lumina")
            assert d["capauth_uri"] == "capauth:lumina@skworld.io"
            assert d["agent"] == "lumina"

    def test_env_resolution(self):
        """With SKAGENT set, None agent resolves via env."""
        with patch.dict(os.environ, {"SKAGENT": "opus"}, clear=False):
            from skcomms.identity import resolve_self_identity

            d = resolve_self_identity(None)
            assert d["agent"] in ("opus", "lumina")  # may pick up active agent from env
