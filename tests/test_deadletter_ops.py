"""Dead-letter operator surface + retention policy (coord 40c50478).

PersistentOutbox dead-letters after max_retries and ``requeue_dead`` existed,
but there was no CLI verb to review dead letters, and ``dead/`` plus
``archive/`` had no retention: a persistent peer outage grew them forever,
exactly like the 140k-file sender outbox leak. These tests pin the fix:

  * ``PersistentOutbox.get_dead`` / per-id ``purge_dead`` for triage,
  * ``prune_dead`` / ``prune_archive`` retention (TTL + max-count bounds),
  * ``run_housekeeping_pass`` enforces that retention when handed the outbox
    (and leaves the outbox alone when not, preserving the old contract),
  * the ``skcomms deadletter list|show|requeue|purge`` CLI verbs,
  * ``skcomms housekeep`` sweeps dead/ and archive/ in the same pass,
  * ``observability.dead_letter_depth`` reads the real depth (the original
    wiring called the ``dead_count`` property as a method, so every scrape
    and alert saw 0 forever).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from skcomms.config import HousekeepingConfig
from skcomms.housekeeping import run_housekeeping_pass
from skcomms.observability import dead_letter_depth
from skcomms.outbox import PersistentOutbox, default_outbox_dir


def _backdate(path: Path, hours: float) -> None:
    """Set *path*'s atime/mtime to *hours* ago."""
    old = time.time() - hours * 3600.0
    os.utime(path, (old, old))


def _legacy_json(envelope_id: str = "e1") -> str:
    return json.dumps(
        {"sender": "a", "recipient": "b", "payload": {"content": "x"}, "id": envelope_id}
    )


def _dead_letter(outbox: PersistentOutbox, envelope_id: str, error: str = "peer down") -> Path:
    """Enqueue *envelope_id* and move it straight to dead/; return the dead file."""
    outbox.enqueue(envelope_id, "peer-1", _legacy_json(envelope_id), error=error)
    assert outbox.mark_dead(envelope_id, error=error)
    return outbox.dead_dir / f"{envelope_id}.json"


@pytest.fixture
def outbox(tmp_path):
    return PersistentOutbox(outbox_dir=tmp_path / "outbox")


# ---------------------------------------------------------------------------
# Default outbox dir env override
# ---------------------------------------------------------------------------


class TestDefaultOutboxDir:
    def test_env_override_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_OUTBOX_DIR", str(tmp_path / "elsewhere"))
        assert default_outbox_dir() == tmp_path / "elsewhere"
        ob = PersistentOutbox()
        assert ob.root == tmp_path / "elsewhere"

    def test_explicit_dir_beats_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_OUTBOX_DIR", str(tmp_path / "env"))
        ob = PersistentOutbox(outbox_dir=tmp_path / "explicit")
        assert ob.root == tmp_path / "explicit"


# ---------------------------------------------------------------------------
# Triage primitives: get_dead / purge_dead(id)
# ---------------------------------------------------------------------------


class TestDeadLetterTriagePrimitives:
    def test_get_dead_returns_entry(self, outbox):
        _dead_letter(outbox, "aaa", error="relay 422")
        entry = outbox.get_dead("aaa")
        assert entry is not None
        assert entry.envelope_id == "aaa"
        assert entry.last_error == "relay 422"

    def test_get_dead_missing_is_none(self, outbox):
        assert outbox.get_dead("nope") is None

    def test_purge_dead_single_id(self, outbox):
        _dead_letter(outbox, "aaa")
        _dead_letter(outbox, "bbb")
        assert outbox.purge_dead("aaa") == 1
        assert outbox.get_dead("aaa") is None
        assert outbox.get_dead("bbb") is not None

    def test_purge_dead_missing_id_is_zero(self, outbox):
        assert outbox.purge_dead("nope") == 0

    def test_purge_dead_all_backward_compatible(self, outbox):
        _dead_letter(outbox, "aaa")
        _dead_letter(outbox, "bbb")
        assert outbox.purge_dead() == 2
        assert outbox.dead_count == 0


# ---------------------------------------------------------------------------
# Retention: prune_dead / prune_archive
# ---------------------------------------------------------------------------


class TestDeadLetterRetention:
    def test_ttl_deletes_stale_keeps_fresh(self, outbox):
        stale = _dead_letter(outbox, "stale")
        _backdate(stale, hours=800)
        _dead_letter(outbox, "fresh")

        assert outbox.prune_dead(ttl_hours=720.0) == 1
        assert outbox.get_dead("stale") is None
        assert outbox.get_dead("fresh") is not None

    def test_ttl_disabled_prunes_nothing(self, outbox):
        stale = _dead_letter(outbox, "ancient")
        os.utime(stale, (0, 0))
        assert outbox.prune_dead(ttl_hours=0) == 0
        assert outbox.get_dead("ancient") is not None

    def test_max_count_keeps_newest(self, outbox):
        for i, eid in enumerate(["one", "two", "three"]):
            path = _dead_letter(outbox, eid)
            _backdate(path, hours=30 - i * 10)  # one=oldest, three=newest

        assert outbox.prune_dead(max_count=2) == 1
        assert outbox.get_dead("one") is None
        assert outbox.get_dead("two") is not None
        assert outbox.get_dead("three") is not None

    def test_max_count_disabled_prunes_nothing(self, outbox):
        _dead_letter(outbox, "aaa")
        _dead_letter(outbox, "bbb")
        assert outbox.prune_dead(max_count=0) == 0
        assert outbox.dead_count == 2

    def test_both_bounds_compose(self, outbox):
        very_old = _dead_letter(outbox, "veryold")
        _backdate(very_old, hours=1000)
        for i, eid in enumerate(["a", "b", "c"]):
            _backdate(_dead_letter(outbox, eid), hours=10 - i)

        removed = outbox.prune_dead(ttl_hours=720.0, max_count=2)
        assert removed == 2  # TTL kills veryold, max_count kills the oldest of a/b/c
        assert outbox.dead_count == 2

    def test_prune_archive_ttl_and_count(self, outbox):
        stale = outbox.archive_dir / "stale.json"
        stale.write_text("{}")
        _backdate(stale, hours=800)
        fresh = outbox.archive_dir / "fresh.json"
        fresh.write_text("{}")

        assert outbox.prune_archive(ttl_hours=720.0) == 1
        assert not stale.exists()
        assert fresh.exists()

        extra = outbox.archive_dir / "extra.json"
        extra.write_text("{}")
        _backdate(fresh, hours=1)  # fresh is now the older of the two
        assert outbox.prune_archive(max_count=1) == 1
        assert not fresh.exists()
        assert extra.exists()

    def test_prune_archive_disabled_is_noop(self, outbox):
        f = outbox.archive_dir / "keep.json"
        f.write_text("{}")
        os.utime(f, (0, 0))
        assert outbox.prune_archive(ttl_hours=0, max_count=0) == 0
        assert f.exists()


# ---------------------------------------------------------------------------
# Housekeeping pass enforces the retention
# ---------------------------------------------------------------------------


class TestHousekeepingEnforcesDeadRetention:
    def test_pass_with_outbox_prunes_dead_and_archive(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        ob = PersistentOutbox(outbox_dir=tmp_path / "outbox")
        _backdate(_dead_letter(ob, "stale"), hours=800)
        _dead_letter(ob, "fresh")
        old_arch = ob.archive_dir / "old.json"
        old_arch.write_text("{}")
        _backdate(old_arch, hours=800)

        results = run_housekeeping_pass([], HousekeepingConfig(), ob)

        assert results["dead_pruned"] == 1
        assert results["outbox_archive_pruned"] == 1
        assert ob.get_dead("stale") is None
        assert ob.get_dead("fresh") is not None
        assert not old_arch.exists()

    def test_pass_without_outbox_leaves_dead_untouched(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        ob = PersistentOutbox(outbox_dir=tmp_path / "outbox")
        _backdate(_dead_letter(ob, "stale"), hours=9000)

        results = run_housekeeping_pass([], HousekeepingConfig())

        assert "dead_pruned" not in results
        assert "outbox_archive_pruned" not in results
        assert ob.get_dead("stale") is not None

    def test_pass_survives_exploding_outbox(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))

        class _Exploding:
            def prune_dead(self, **kw):
                raise RuntimeError("boom")

            def prune_archive(self, **kw):
                raise RuntimeError("boom")

        results = run_housekeeping_pass([], HousekeepingConfig(), _Exploding())
        assert results["dead_pruned"] == 0
        assert results["outbox_archive_pruned"] == 0

    def test_retention_disabled_by_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
        ob = PersistentOutbox(outbox_dir=tmp_path / "outbox")
        _backdate(_dead_letter(ob, "ancient"), hours=99999)

        cfg = HousekeepingConfig(
            dead_letter_ttl_hours=0,
            dead_letter_max_count=0,
            outbox_archive_ttl_hours=0,
            outbox_archive_max_count=0,
        )
        results = run_housekeeping_pass([], cfg, ob)
        assert results["dead_pruned"] == 0
        assert ob.get_dead("ancient") is not None


# ---------------------------------------------------------------------------
# Observability regression: dead-letter depth was always 0
# ---------------------------------------------------------------------------


class TestDeadLetterDepth:
    def test_reads_the_real_property(self, outbox):
        # The old wiring did outbox.dead_count() on the property, raised
        # TypeError, swallowed it, and reported 0 forever. Prove the real
        # PersistentOutbox now yields the true depth.
        _dead_letter(outbox, "aaa")
        _dead_letter(outbox, "bbb")
        assert dead_letter_depth(outbox) == 2

    def test_accepts_method_shaped_doubles(self):
        class _Double:
            def dead_count(self):
                return 7

        assert dead_letter_depth(_Double()) == 7

    def test_none_is_zero(self):
        assert dead_letter_depth(None) == 0


# ---------------------------------------------------------------------------
# CLI: skcomms deadletter list / show / requeue / purge
# ---------------------------------------------------------------------------


class TestDeadLetterCLI:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def cli_main(self):
        from skcomms.cli import main

        return main

    def test_list_json(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa", error="relay 422")

        result = runner.invoke(
            cli_main, ["deadletter", "list", "--outbox-dir", str(tmp_path), "--json-out"]
        )
        assert result.exit_code == 0, result.output
        entries = json.loads(result.output)
        assert len(entries) == 1
        assert entries[0]["envelope_id"] == "aaa"
        assert entries[0]["last_error"] == "relay 422"

    def test_list_empty(self, runner, cli_main, tmp_path):
        result = runner.invoke(cli_main, ["deadletter", "list", "--outbox-dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "empty" in result.output.lower()

    def test_show_json_classifies_shape(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa", error="peer down")

        result = runner.invoke(
            cli_main,
            ["deadletter", "show", "aaa", "--outbox-dir", str(tmp_path), "--json-out"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["envelope_id"] == "aaa"
        assert data["envelope_shape"] == "legacy"
        assert data["last_error"] == "peer down"
        # Raw envelope withheld unless --raw is passed.
        assert "envelope_json" not in data

    def test_show_raw_includes_envelope(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa")

        result = runner.invoke(
            cli_main,
            ["deadletter", "show", "aaa", "--outbox-dir", str(tmp_path), "--json-out", "--raw"],
        )
        assert result.exit_code == 0, result.output
        assert "envelope_json" in json.loads(result.output)

    def test_show_missing_exits_nonzero(self, runner, cli_main, tmp_path):
        result = runner.invoke(
            cli_main, ["deadletter", "show", "nope", "--outbox-dir", str(tmp_path)]
        )
        assert result.exit_code == 1

    def test_requeue_one(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa")
        _dead_letter(ob, "bbb")

        result = runner.invoke(
            cli_main, ["deadletter", "requeue", "aaa", "--outbox-dir", str(tmp_path)]
        )
        assert result.exit_code == 0, result.output
        assert ob.dead_count == 1
        assert ob.get("aaa") is not None  # back in pending
        assert ob.get_dead("bbb") is not None

    def test_requeue_all(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa")
        _dead_letter(ob, "bbb")

        result = runner.invoke(
            cli_main, ["deadletter", "requeue", "--all", "--outbox-dir", str(tmp_path)]
        )
        assert result.exit_code == 0, result.output
        assert ob.dead_count == 0
        assert ob.pending_count == 2

    def test_requeue_requires_id_or_all(self, runner, cli_main, tmp_path):
        result = runner.invoke(cli_main, ["deadletter", "requeue", "--outbox-dir", str(tmp_path)])
        assert result.exit_code != 0
        result = runner.invoke(
            cli_main, ["deadletter", "requeue", "aaa", "--all", "--outbox-dir", str(tmp_path)]
        )
        assert result.exit_code != 0

    def test_requeue_missing_exits_nonzero(self, runner, cli_main, tmp_path):
        result = runner.invoke(
            cli_main, ["deadletter", "requeue", "nope", "--outbox-dir", str(tmp_path)]
        )
        assert result.exit_code == 1

    def test_purge_one(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa")
        _dead_letter(ob, "bbb")

        result = runner.invoke(
            cli_main, ["deadletter", "purge", "aaa", "--outbox-dir", str(tmp_path)]
        )
        assert result.exit_code == 0, result.output
        assert ob.get_dead("aaa") is None
        assert ob.get_dead("bbb") is not None

    def test_purge_all_with_yes(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa")
        _dead_letter(ob, "bbb")

        result = runner.invoke(
            cli_main, ["deadletter", "purge", "--all", "--yes", "--outbox-dir", str(tmp_path)]
        )
        assert result.exit_code == 0, result.output
        assert ob.dead_count == 0

    def test_purge_all_declined_confirmation_keeps_entries(self, runner, cli_main, tmp_path):
        ob = PersistentOutbox(outbox_dir=tmp_path)
        _dead_letter(ob, "aaa")

        result = runner.invoke(
            cli_main,
            ["deadletter", "purge", "--all", "--outbox-dir", str(tmp_path)],
            input="n\n",
        )
        assert result.exit_code == 0, result.output
        assert ob.dead_count == 1

    def test_purge_requires_id_or_all(self, runner, cli_main, tmp_path):
        result = runner.invoke(cli_main, ["deadletter", "purge", "--outbox-dir", str(tmp_path)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# CLI: skcomms housekeep sweeps dead/ and archive/ in the same pass
# ---------------------------------------------------------------------------


class TestHousekeepSweepsDeadLetters:
    def test_housekeep_prunes_stale_dead_letters(self, tmp_path, monkeypatch):
        from skcomms.cli import main as cli_main

        monkeypatch.delenv("SKAGENT", raising=False)
        monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))

        ob_dir = tmp_path / "outbox"
        ob = PersistentOutbox(outbox_dir=ob_dir)
        _backdate(_dead_letter(ob, "stale"), hours=800)
        _dead_letter(ob, "fresh")

        cfg = tmp_path / "config.yml"
        cfg.write_text("skcomms:\n  transports: {}\n")

        runner = CliRunner()
        result = runner.invoke(
            cli_main,
            ["housekeep", "-c", str(cfg), "--outbox-dir", str(ob_dir), "--json-out"],
        )
        assert result.exit_code == 0, result.output
        counts = json.loads(result.output)
        assert counts["dead_pruned"] == 1
        assert ob.get_dead("stale") is None
        assert ob.get_dead("fresh") is not None

    def test_housekeep_dead_ttl_override(self, tmp_path, monkeypatch):
        from skcomms.cli import main as cli_main

        monkeypatch.delenv("SKAGENT", raising=False)
        monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))

        ob_dir = tmp_path / "outbox"
        ob = PersistentOutbox(outbox_dir=ob_dir)
        # 10h old: inside the 720h default, stale for a 5h override.
        _backdate(_dead_letter(ob, "tenhours"), hours=10)

        cfg = tmp_path / "config.yml"
        cfg.write_text("skcomms:\n  transports: {}\n")

        runner = CliRunner()
        result = runner.invoke(
            cli_main,
            [
                "housekeep",
                "-c",
                str(cfg),
                "--outbox-dir",
                str(ob_dir),
                "--dead-ttl-hours",
                "5",
                "--json-out",
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["dead_pruned"] == 1
        assert ob.get_dead("tenhours") is None
