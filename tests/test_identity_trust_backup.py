"""Identity + trust-state backup/restore and key-loss re-pin (coord ``7d5344f2``).

Covers:
    - backup_set / identity_check: the canonical backup set and the
      private-key presence report.
    - create_backup: fail-closed refusal without a private key, 0600
      archive mode, manifest checksums, pending-outbox inclusion.
    - restore_backup: roundtrip onto a wiped machine, checksum verification
      (tampered archives rejected whole), path-traversal rejection,
      conflict semantics (never silently overwrite; force works), dry-run.
    - enforce_identity_gate: loud by default, FATAL under
      SKCOMMS_REQUIRE_IDENTITY (the daemon can no longer come up green with
      dead crypto).
    - crypto.from_capauth: missing key now logs WARNING, not INFO (the old
      quiet behavior is dead).
    - tofu.repin_fingerprint: the ONLY sanctioned pin overwrite; the
      receive-path verify still hard-CONFLICTs, previous pin is audited.
    - CLI verbs: identity check --strict / backup / restore / repin.
"""

from __future__ import annotations

import io
import json
import logging
import stat
import tarfile
from pathlib import Path

import pytest

FP_OLD = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
FP_NEW = "FFFF9999EEEE8888DDDD7777CCCC6666BBBB5555"

PRIV = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake-private\n-----END PGP PRIVATE KEY BLOCK-----\n"
PUB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake-public\n-----END PGP PUBLIC KEY BLOCK-----\n"


@pytest.fixture
def iso(tmp_path, monkeypatch):
    """Isolated HOME + SKCOMMS_HOME + agent so no real identity is touched."""
    home = tmp_path / "home"
    skhome = tmp_path / "skcomms"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SKCOMMS_HOME", str(skhome))
    monkeypatch.setenv("SKAGENT", "testagent")
    monkeypatch.delenv("SKCOMMS_REQUIRE_IDENTITY", raising=False)
    return {"home": home, "skhome": skhome}


def _populate(iso_env: dict, with_private: bool = True) -> None:
    """Lay down a full identity + trust-state file set."""
    home = iso_env["home"]
    skhome = iso_env["skhome"]
    cap = home / ".capauth" / "identity"
    cap.mkdir(parents=True, exist_ok=True)
    if with_private:
        (cap / "private.asc").write_text(PRIV)
    (cap / "public.asc").write_text(PUB)
    (cap / "profile.json").write_text(json.dumps({"key_info": {"fingerprint": FP_OLD}}))

    agent = home / ".skcapstone" / "agents" / "testagent" / "identity"
    agent.mkdir(parents=True, exist_ok=True)
    (agent / "agent.pub").write_text(PUB)

    (home / ".skcapstone" / "cluster.json").write_text(
        json.dumps({"realm": "skworld", "operator": "chef"})
    )

    skhome.mkdir(parents=True, exist_ok=True)
    (skhome / "known_fingerprints.json").write_text(
        json.dumps({"peer@chef.skworld": {"fingerprint": FP_OLD, "first_seen": "x"}})
    )
    (skhome / "peers.json").write_text(json.dumps({"peer@chef.skworld": {"device": "abc"}}))

    pending = skhome / "outbox" / "pending"
    pending.mkdir(parents=True, exist_ok=True)
    (pending / "msg-1.json").write_text(json.dumps({"envelope_id": "msg-1"}))


# ---------------------------------------------------------------------------
# backup set + identity check
# ---------------------------------------------------------------------------


class TestIdentityCheck:
    def test_missing_key_reported(self, iso):
        from skcomms.trustbackup import identity_check

        _populate(iso, with_private=False)
        check = identity_check()
        assert check["ok"] is False
        assert check["private_key_present"] is False
        assert "capauth-private-key" in check["missing"]

    def test_present_key_ok(self, iso):
        from skcomms.trustbackup import identity_check

        _populate(iso)
        check = identity_check()
        assert check["ok"] is True
        assert check["private_key_present"] is True

    def test_backup_set_covers_spec(self, iso):
        from skcomms.trustbackup import backup_set

        _populate(iso)
        roles = {i.role for i in backup_set()}
        for role in (
            "capauth-private-key",
            "capauth-public-key",
            "capauth-profile",
            "agent-pubkey",
            "cluster",
            "tofu-store",
            "peers",
            "outbox-pending",
        ):
            assert role in roles


# ---------------------------------------------------------------------------
# create_backup
# ---------------------------------------------------------------------------


class TestCreateBackup:
    def test_refuses_without_private_key(self, iso, tmp_path):
        from skcomms.trustbackup import TrustBackupError, create_backup

        _populate(iso, with_private=False)
        with pytest.raises(TrustBackupError, match="private key"):
            create_backup(tmp_path / "out.tar.gz")

    def test_allow_partial_overrides(self, iso, tmp_path):
        from skcomms.trustbackup import create_backup

        _populate(iso, with_private=False)
        report = create_backup(tmp_path / "out.tar.gz", allow_partial=True)
        assert Path(report["archive"]).is_file()

    def test_archive_mode_0600_and_manifest(self, iso, tmp_path):
        from skcomms.trustbackup import MANIFEST_NAME, create_backup

        _populate(iso)
        dest = tmp_path / "backup.tar.gz"
        report = create_backup(dest)
        assert stat.S_IMODE(dest.stat().st_mode) == 0o600
        assert report["count"] >= 7
        with tarfile.open(dest) as tar:
            manifest = json.loads(tar.extractfile(MANIFEST_NAME).read())
        assert manifest["version"] == 1
        members = manifest["files"]
        assert "home/.capauth/identity/private.asc" in members
        assert "skcomms_home/known_fingerprints.json" in members
        assert "skcomms_home/outbox/pending/msg-1.json" in members
        for meta in members.values():
            assert len(meta["sha256"]) == 64


# ---------------------------------------------------------------------------
# restore_backup
# ---------------------------------------------------------------------------


class TestRestoreBackup:
    def _backup(self, iso, tmp_path) -> Path:
        from skcomms.trustbackup import create_backup

        _populate(iso)
        dest = tmp_path / "backup.tar.gz"
        create_backup(dest)
        return dest

    def _wipe(self, tmp_path, monkeypatch) -> dict:
        """Point HOME/SKCOMMS_HOME at fresh roots: the 'rebuilt machine'."""
        home = tmp_path / "home2"
        skhome = tmp_path / "skcomms2"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("SKCOMMS_HOME", str(skhome))
        return {"home": home, "skhome": skhome}

    def test_roundtrip_onto_wiped_machine(self, iso, tmp_path, monkeypatch):
        from skcomms.trustbackup import identity_check, restore_backup

        archive = self._backup(iso, tmp_path)
        fresh = self._wipe(tmp_path, monkeypatch)

        report = restore_backup(archive)
        assert report["ok"] is True
        assert not report["conflicts"]

        priv = fresh["home"] / ".capauth" / "identity" / "private.asc"
        assert priv.read_text() == PRIV
        assert stat.S_IMODE(priv.stat().st_mode) == 0o600
        tofu = fresh["skhome"] / "known_fingerprints.json"
        assert json.loads(tofu.read_text())["peer@chef.skworld"]["fingerprint"] == FP_OLD
        pending = fresh["skhome"] / "outbox" / "pending" / "msg-1.json"
        assert pending.is_file()
        assert identity_check()["private_key_present"] is True

    def test_dry_run_writes_nothing(self, iso, tmp_path, monkeypatch):
        from skcomms.trustbackup import restore_backup

        archive = self._backup(iso, tmp_path)
        fresh = self._wipe(tmp_path, monkeypatch)
        report = restore_backup(archive, dry_run=True)
        assert report["restored"]
        assert not (fresh["home"] / ".capauth").exists()

    def test_conflict_never_silently_overwrites(self, iso, tmp_path, monkeypatch):
        from skcomms.trustbackup import restore_backup

        archive = self._backup(iso, tmp_path)
        fresh = self._wipe(tmp_path, monkeypatch)
        cap = fresh["home"] / ".capauth" / "identity"
        cap.mkdir(parents=True)
        (cap / "private.asc").write_text("A DIFFERENT LIVE KEY\n")

        report = restore_backup(archive)
        assert report["ok"] is False
        assert str(cap / "private.asc") in report["conflicts"]
        # fail closed: the live key was NOT touched
        assert (cap / "private.asc").read_text() == "A DIFFERENT LIVE KEY\n"

    def test_force_overwrites_conflict(self, iso, tmp_path, monkeypatch):
        from skcomms.trustbackup import restore_backup

        archive = self._backup(iso, tmp_path)
        fresh = self._wipe(tmp_path, monkeypatch)
        cap = fresh["home"] / ".capauth" / "identity"
        cap.mkdir(parents=True)
        (cap / "private.asc").write_text("A DIFFERENT LIVE KEY\n")

        report = restore_backup(archive, force=True)
        assert report["ok"] is True
        assert (cap / "private.asc").read_text() == PRIV

    def test_tampered_payload_rejected_whole(self, iso, tmp_path, monkeypatch):
        from skcomms.trustbackup import MANIFEST_NAME, TrustBackupError, restore_backup

        archive = self._backup(iso, tmp_path)
        # Rebuild the archive with one payload flipped but the manifest intact.
        evil = tmp_path / "evil.tar.gz"
        with tarfile.open(archive) as src, tarfile.open(evil, "w:gz") as dst:
            for member in src.getmembers():
                data = src.extractfile(member).read()
                if member.name == "home/.capauth/identity/private.asc":
                    data = b"ATTACKER KEY MATERIAL"
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                dst.addfile(info, io.BytesIO(data))
        fresh = self._wipe(tmp_path, monkeypatch)
        with pytest.raises(TrustBackupError, match="checksum"):
            restore_backup(evil)
        # nothing was written before the verify failed
        assert not (fresh["home"] / ".capauth").exists()
        assert MANIFEST_NAME  # keep the import honest

    def test_traversal_relpath_rejected(self, iso, tmp_path, monkeypatch):
        from skcomms.trustbackup import MANIFEST_NAME, TrustBackupError, restore_backup

        payload = b"pwned"
        import hashlib

        manifest = {
            "version": 1,
            "files": {
                "home/../../etc/evil": {
                    "role": "capauth-private-key",
                    "root": "home",
                    "relpath": "../../etc/evil",
                    "secret": True,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            },
        }
        evil = tmp_path / "traversal.tar.gz"
        with tarfile.open(evil, "w:gz") as tar:
            mdata = json.dumps(manifest).encode()
            info = tarfile.TarInfo(MANIFEST_NAME)
            info.size = len(mdata)
            tar.addfile(info, io.BytesIO(mdata))
            info = tarfile.TarInfo("home/../../etc/evil")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        self._wipe(tmp_path, monkeypatch)
        with pytest.raises(TrustBackupError, match="unsafe path"):
            restore_backup(evil)

    def test_missing_manifest_rejected(self, iso, tmp_path):
        from skcomms.trustbackup import TrustBackupError, restore_backup

        bogus = tmp_path / "bogus.tar.gz"
        with tarfile.open(bogus, "w:gz") as tar:
            data = b"not a backup"
            info = tarfile.TarInfo("random.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        with pytest.raises(TrustBackupError, match="MANIFEST"):
            restore_backup(bogus)


# ---------------------------------------------------------------------------
# startup gate: the daemon can no longer come up green with dead crypto
# ---------------------------------------------------------------------------


class TestIdentityGate:
    def test_gate_warns_by_default(self, iso, caplog):
        from skcomms.trustbackup import enforce_identity_gate

        _populate(iso, with_private=False)
        with caplog.at_level(logging.ERROR, logger="skcomms.trustbackup"):
            check = enforce_identity_gate()
        assert check["private_key_present"] is False
        assert any("ABSENT" in rec.message for rec in caplog.records)

    def test_gate_fatal_when_required(self, iso, monkeypatch):
        from skcomms.trustbackup import IdentityMissingError, enforce_identity_gate

        _populate(iso, with_private=False)
        monkeypatch.setenv("SKCOMMS_REQUIRE_IDENTITY", "1")
        with pytest.raises(IdentityMissingError):
            enforce_identity_gate()

    def test_gate_passes_with_key(self, iso, monkeypatch):
        from skcomms.trustbackup import enforce_identity_gate

        _populate(iso)
        monkeypatch.setenv("SKCOMMS_REQUIRE_IDENTITY", "1")
        assert enforce_identity_gate()["private_key_present"] is True


class TestCryptoMissingKeyIsLoud:
    def test_from_capauth_missing_key_logs_warning(self, iso, caplog):
        """The old quiet INFO 'encryption disabled' is dead: WARNING now."""
        from skcomms.crypto import EnvelopeCrypto

        with caplog.at_level(logging.INFO, logger="skcomms.crypto"):
            engine = EnvelopeCrypto.from_capauth(iso["home"] / ".capauth")
        assert engine is None
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings, "missing-key path must log at WARNING or higher"
        assert any("restore" in r.getMessage().lower() for r in warnings)


# ---------------------------------------------------------------------------
# TOFU re-pin (key-loss recovery)
# ---------------------------------------------------------------------------


class TestTofuRepin:
    def test_verify_still_conflicts_without_repin(self, iso):
        from skcomms.tofu import TofuStatus, record_fingerprint, verify_fingerprint

        record_fingerprint("lumina@chef.skworld", FP_OLD)
        result = verify_fingerprint("lumina@chef.skworld", FP_NEW)
        assert result.status == TofuStatus.CONFLICT
        assert not result.trusted

    def test_repin_replaces_and_audits(self, iso):
        from skcomms.tofu import (
            TofuStatus,
            fingerprint_for,
            record_fingerprint,
            repin_fingerprint,
            verify_fingerprint,
        )

        record_fingerprint("lumina@chef.skworld", FP_OLD)
        entry = repin_fingerprint("lumina@chef.skworld", FP_NEW, reason="key loss drill")
        assert entry["fingerprint"] == FP_NEW
        assert entry["previous_fingerprint"] == FP_OLD
        assert entry["repin_reason"] == "key loss drill"
        assert "repinned_at" in entry

        assert fingerprint_for("lumina@chef.skworld") == FP_NEW
        assert verify_fingerprint("lumina@chef.skworld", FP_NEW).status == TofuStatus.TRUST_MATCH
        # the OLD (lost/compromised) fingerprint is now the conflicting one
        assert verify_fingerprint("lumina@chef.skworld", FP_OLD).status == TofuStatus.CONFLICT

    def test_repin_drops_stale_pubkey(self, iso):
        from skcomms.tofu import record_fingerprint, repin_fingerprint

        record_fingerprint("lumina@chef.skworld", FP_OLD, pubkey="OLD KEY BLOCK")
        entry = repin_fingerprint("lumina@chef.skworld", FP_NEW)
        assert "pubkey" not in entry

    def test_repin_on_unknown_fqid_records_fresh(self, iso):
        from skcomms.tofu import fingerprint_for, repin_fingerprint

        entry = repin_fingerprint("new@peer.realm", FP_NEW)
        assert "previous_fingerprint" not in entry
        assert fingerprint_for("new@peer.realm") == FP_NEW


# ---------------------------------------------------------------------------
# CLI verbs
# ---------------------------------------------------------------------------


class TestIdentityCli:
    def _runner(self):
        from click.testing import CliRunner

        return CliRunner()

    def test_check_strict_exits_1_without_key(self, iso):
        from skcomms.cli import main

        _populate(iso, with_private=False)
        result = self._runner().invoke(main, ["identity", "check", "--strict"])
        assert result.exit_code == 1

    def test_check_strict_exits_0_with_key(self, iso):
        from skcomms.cli import main

        _populate(iso)
        result = self._runner().invoke(main, ["identity", "check", "--strict"])
        assert result.exit_code == 0

    def test_backup_refused_without_key(self, iso, tmp_path):
        from skcomms.cli import main

        _populate(iso, with_private=False)
        out = tmp_path / "cli-backup.tar.gz"
        result = self._runner().invoke(main, ["identity", "backup", "-o", str(out)])
        assert result.exit_code == 1
        assert not out.exists()

    def test_backup_restore_roundtrip(self, iso, tmp_path, monkeypatch):
        from skcomms.cli import main

        _populate(iso)
        out = tmp_path / "cli-backup.tar.gz"
        result = self._runner().invoke(main, ["identity", "backup", "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert out.is_file()

        home2 = tmp_path / "home2"
        home2.mkdir()
        monkeypatch.setenv("HOME", str(home2))
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms2"))
        result = self._runner().invoke(main, ["identity", "restore", str(out)])
        assert result.exit_code == 0, result.output
        assert (home2 / ".capauth" / "identity" / "private.asc").read_text() == PRIV

    def test_restore_conflict_exits_1(self, iso, tmp_path, monkeypatch):
        from skcomms.cli import main

        _populate(iso)
        out = tmp_path / "cli-backup.tar.gz"
        assert self._runner().invoke(main, ["identity", "backup", "-o", str(out)]).exit_code == 0

        home2 = tmp_path / "home2"
        cap = home2 / ".capauth" / "identity"
        cap.mkdir(parents=True)
        (cap / "private.asc").write_text("LIVE KEY, DO NOT CLOBBER\n")
        monkeypatch.setenv("HOME", str(home2))
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms2"))
        result = self._runner().invoke(main, ["identity", "restore", str(out)])
        assert result.exit_code == 1
        assert (cap / "private.asc").read_text() == "LIVE KEY, DO NOT CLOBBER\n"

    def test_repin_cli(self, iso):
        from skcomms.cli import main
        from skcomms.tofu import fingerprint_for, record_fingerprint

        record_fingerprint("lumina@chef.skworld", FP_OLD)
        result = self._runner().invoke(
            main,
            [
                "identity",
                "repin",
                "lumina@chef.skworld",
                FP_NEW,
                "--yes",
                "--reason",
                "drill",
            ],
        )
        assert result.exit_code == 0, result.output
        assert fingerprint_for("lumina@chef.skworld") == FP_NEW

    def test_repin_aborts_without_confirmation(self, iso):
        from skcomms.cli import main
        from skcomms.tofu import fingerprint_for, record_fingerprint

        record_fingerprint("lumina@chef.skworld", FP_OLD)
        result = self._runner().invoke(
            main,
            ["identity", "repin", "lumina@chef.skworld", FP_NEW],
            input="n\n",
        )
        assert result.exit_code == 1
        assert fingerprint_for("lumina@chef.skworld") == FP_OLD
