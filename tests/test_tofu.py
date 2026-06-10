"""Tests for the PGP fingerprint TOFU trust store (T3, ``bcf32eea``).

Covers:
    - record_fingerprint + fingerprint_for: first contact records, lookup returns it.
    - verify_fingerprint: TRUST_NEW on first sight (and records it),
      TRUST_MATCH on second sight, CONFLICT on mismatch (stored value
      unchanged — never silently overwritten).
    - lookup of an unknown fqid returns None.
    - the store lives under SKCOMMS_HOME (honors the env override).

Canonical identity is the PGP fingerprint; the fqid is just a handle.
No live keys needed — fingerprints are opaque strings here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def tofu_home(tmp_path, monkeypatch):
    """Tmp SKCOMMS_HOME so the store is isolated per-test."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


FP_A = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
FP_B = "FFFF9999EEEE8888DDDD7777CCCC6666BBBB5555"


# ---------------------------------------------------------------------------
# record + lookup
# ---------------------------------------------------------------------------


class TestRecordAndLookup:
    def test_record_then_lookup(self, tofu_home):
        from skcomms.tofu import fingerprint_for, record_fingerprint

        record_fingerprint("lumina@chef.skworld", FP_A)
        assert fingerprint_for("lumina@chef.skworld") == FP_A

    def test_lookup_unknown_returns_none(self, tofu_home):
        from skcomms.tofu import fingerprint_for

        assert fingerprint_for("nobody@nowhere.void") is None

    def test_record_persists_pubkey(self, tofu_home):
        from skcomms.tofu import record_fingerprint

        record_fingerprint("lumina@chef.skworld", FP_A, pubkey="-----PGP PUB-----")
        store_file = tofu_home / "known_fingerprints.json"
        data = json.loads(store_file.read_text())
        assert data["lumina@chef.skworld"]["fingerprint"] == FP_A
        assert data["lumina@chef.skworld"]["pubkey"] == "-----PGP PUB-----"
        assert "first_seen" in data["lumina@chef.skworld"]


# ---------------------------------------------------------------------------
# verify_fingerprint (TOFU state machine)
# ---------------------------------------------------------------------------


class TestVerifyFingerprint:
    def test_first_sight_records_and_returns_trust_new(self, tofu_home):
        from skcomms.tofu import TofuStatus, fingerprint_for, verify_fingerprint

        result = verify_fingerprint("opus@chef.skworld", FP_A)
        assert result.status == TofuStatus.TRUST_NEW
        assert result.trusted
        # first sight records it (TOFU)
        assert fingerprint_for("opus@chef.skworld") == FP_A

    def test_second_sight_match_returns_trust_match(self, tofu_home):
        from skcomms.tofu import TofuStatus, verify_fingerprint

        verify_fingerprint("opus@chef.skworld", FP_A)  # TRUST_NEW
        result = verify_fingerprint("opus@chef.skworld", FP_A)
        assert result.status == TofuStatus.TRUST_MATCH
        assert result.trusted

    def test_mismatch_returns_conflict_and_does_not_overwrite(self, tofu_home):
        from skcomms.tofu import TofuStatus, fingerprint_for, verify_fingerprint

        verify_fingerprint("opus@chef.skworld", FP_A)  # records FP_A
        result = verify_fingerprint("opus@chef.skworld", FP_B)
        assert result.status == TofuStatus.CONFLICT
        assert not result.trusted
        # stored value MUST be unchanged — never silently overwritten
        assert fingerprint_for("opus@chef.skworld") == FP_A
        assert result.stored_fingerprint == FP_A

    def test_store_honors_skcomms_home(self, tofu_home):
        from skcomms.tofu import record_fingerprint, store_path

        record_fingerprint("lumina@chef.skworld", FP_A)
        assert store_path() == tofu_home / "known_fingerprints.json"
        assert store_path().exists()
