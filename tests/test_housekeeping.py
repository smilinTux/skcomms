"""Housekeeping: outbox pruning, archive TTL, mailbox retention (coord 8bf3fcfc).

The 140k-file outbox leak: FileTransport.send / SyncthingTransport.send write
``{id}.skc.json`` into the sender outbox and nothing ever deleted those files;
SyncthingTransport.prune_outbox existed but had ZERO callers, FileTransport had
no pruner at all, and receiver archive dirs + mailbox outbox records grew
unbounded. These tests pin the fix:

  * FileTransport.prune_outbox mirrors the syncthing pruner (age-based),
  * both transports trim their archive dirs on a TTL,
  * prune_mailbox_outboxes sweeps stale mailbox outbox records,
  * run_housekeeping_pass aggregates all of it and never dies on one failure,
  * the daemon lifespan actually starts a loop that calls prune_outbox, and
  * the ``skcomms housekeep`` CLI verb runs one full pass.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

from skcomms.config import HousekeepingConfig, SKCommsConfig
from skcomms.housekeeping import (
    housekeeping_loop,
    prune_mailbox_outboxes,
    run_housekeeping_pass,
)
from skcomms.transports.file import ENVELOPE_SUFFIX, FileTransport
from skcomms.transports.syncthing import SyncthingTransport


def _backdate(path: Path, hours: float) -> None:
    """Set *path*'s atime/mtime to *hours* ago."""
    old = time.time() - hours * 3600.0
    os.utime(path, (old, old))


def _envelope_bytes(envelope_id: str = "e1") -> bytes:
    return json.dumps({"envelope_id": envelope_id, "payload": {"content": "x"}}).encode()


# ---------------------------------------------------------------------------
# FileTransport.prune_outbox
# ---------------------------------------------------------------------------


class TestFileTransportPruneOutbox:
    @pytest.fixture
    def transport(self, tmp_path):
        return FileTransport(
            outbox_path=tmp_path / "outbox",
            inbox_path=tmp_path / "inbox",
            archive_path=tmp_path / "archive",
        )

    def test_deletes_stale_keeps_fresh(self, transport, tmp_path):
        outbox = tmp_path / "outbox"
        outbox.mkdir(parents=True)

        fresh = outbox / f"fresh{ENVELOPE_SUFFIX}"
        fresh.write_bytes(_envelope_bytes("fresh"))

        stale = outbox / f"stale{ENVELOPE_SUFFIX}"
        stale.write_bytes(_envelope_bytes("stale"))
        _backdate(stale, hours=100)

        deleted = transport.prune_outbox(max_age_hours=48.0)

        assert deleted == 1
        assert fresh.exists()
        assert not stale.exists()

    def test_skips_hidden_and_non_envelope_files(self, transport, tmp_path):
        outbox = tmp_path / "outbox"
        outbox.mkdir(parents=True)

        hidden = outbox / f".inflight{ENVELOPE_SUFFIX}"
        hidden.write_bytes(b"{}")
        other = outbox / "notes.txt"
        other.write_bytes(b"keep me")
        _backdate(hidden, hours=1000)
        _backdate(other, hours=1000)

        assert transport.prune_outbox(max_age_hours=48.0) == 0
        assert hidden.exists()
        assert other.exists()

    def test_zero_max_age_prunes_nothing(self, transport, tmp_path):
        outbox = tmp_path / "outbox"
        outbox.mkdir(parents=True)
        f = outbox / f"ancient{ENVELOPE_SUFFIX}"
        f.write_bytes(_envelope_bytes())
        os.utime(f, (0, 0))

        assert transport.prune_outbox(max_age_hours=0) == 0
        assert f.exists()

    def test_missing_outbox_returns_zero(self, tmp_path):
        transport = FileTransport(outbox_path=tmp_path / "nope")
        assert transport.prune_outbox() == 0


# ---------------------------------------------------------------------------
# Archive TTL (both transports)
# ---------------------------------------------------------------------------


class TestArchiveTTL:
    def test_file_transport_prune_archive(self, tmp_path):
        transport = FileTransport(
            outbox_path=tmp_path / "outbox",
            inbox_path=tmp_path / "inbox",
            archive_path=tmp_path / "archive",
        )
        archive = tmp_path / "archive"
        archive.mkdir(parents=True)

        fresh = archive / f"fresh{ENVELOPE_SUFFIX}"
        fresh.write_bytes(_envelope_bytes())
        stale = archive / f"stale{ENVELOPE_SUFFIX}"
        stale.write_bytes(_envelope_bytes())
        _backdate(stale, hours=200)

        assert transport.prune_archive(ttl_hours=168.0) == 1
        assert fresh.exists()
        assert not stale.exists()

    def test_syncthing_transport_prune_archive(self, tmp_path):
        transport = SyncthingTransport(comms_root=tmp_path / "comms", archive=True)
        archive = tmp_path / "comms" / "archive"
        archive.mkdir(parents=True)

        stale = archive / f"old{ENVELOPE_SUFFIX}"
        stale.write_bytes(_envelope_bytes())
        _backdate(stale, hours=200)

        assert transport.prune_archive(ttl_hours=168.0) == 1
        assert not stale.exists()

    def test_zero_ttl_prunes_nothing(self, tmp_path):
        transport = FileTransport(archive_path=tmp_path / "archive")
        archive = tmp_path / "archive"
        archive.mkdir(parents=True)
        f = archive / f"x{ENVELOPE_SUFFIX}"
        f.write_bytes(_envelope_bytes())
        os.utime(f, (0, 0))

        assert transport.prune_archive(ttl_hours=0) == 0
        assert f.exists()

    def test_missing_archive_returns_zero(self, tmp_path):
        transport = FileTransport(archive_path=tmp_path / "nope")
        assert transport.prune_archive() == 0


# ---------------------------------------------------------------------------
# Mailbox outbox retention
# ---------------------------------------------------------------------------


class TestMailboxOutboxRetention:
    def _make_tree(self, root: Path) -> Path:
        outbox = root / "skworld" / "chef" / "lumina" / "outbox"
        outbox.mkdir(parents=True)
        return outbox

    def test_deletes_stale_records_keeps_fresh_and_inbox(self, tmp_path):
        outbox = self._make_tree(tmp_path)
        inbox = outbox.parent / "inbox"
        inbox.mkdir()

        fresh = outbox / "20260710-fresh.json"
        fresh.write_text("{}")
        stale = outbox / "20260101-stale.json"
        stale.write_text("{}")
        _backdate(stale, hours=500)

        # Inbox files are the delivery path and must NEVER be swept.
        unread = inbox / "20260101-unread.json"
        unread.write_text("{}")
        _backdate(unread, hours=500)

        deleted = prune_mailbox_outboxes(168.0, home=tmp_path)

        assert deleted == 1
        assert fresh.exists()
        assert not stale.exists()
        assert unread.exists()

    def test_honors_skcomms_home_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        outbox = self._make_tree(tmp_path)
        stale = outbox / "old.json"
        stale.write_text("{}")
        _backdate(stale, hours=500)

        assert prune_mailbox_outboxes(168.0) == 1
        assert not stale.exists()

    def test_zero_ttl_and_missing_home_are_noops(self, tmp_path):
        assert prune_mailbox_outboxes(0, home=tmp_path) == 0
        assert prune_mailbox_outboxes(168.0, home=tmp_path / "nope") == 0


# ---------------------------------------------------------------------------
# run_housekeeping_pass
# ---------------------------------------------------------------------------


class _FakePrunableTransport:
    """Records pruner calls; stands in for a file-based transport."""

    name = "fake"

    def __init__(self, outbox_result: int = 3, archive_result: int = 2):
        self.outbox_calls: list[float] = []
        self.archive_calls: list[float] = []
        self._outbox_result = outbox_result
        self._archive_result = archive_result

    def prune_outbox(self, max_age_hours: float) -> int:
        self.outbox_calls.append(max_age_hours)
        return self._outbox_result

    def prune_archive(self, ttl_hours: float) -> int:
        self.archive_calls.append(ttl_hours)
        return self._archive_result


class _PrunerlessTransport:
    """A transport with no pruners (e.g. a network rail)."""

    name = "prunerless"


class _ExplodingTransport:
    name = "exploding"

    def prune_outbox(self, max_age_hours: float) -> int:
        raise RuntimeError("boom")

    def prune_archive(self, ttl_hours: float) -> int:
        raise RuntimeError("boom")


class TestRunHousekeepingPass:
    def test_aggregates_across_transports_with_configured_retention(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        t1 = _FakePrunableTransport(outbox_result=3, archive_result=2)
        t2 = _FakePrunableTransport(outbox_result=1, archive_result=0)
        cfg = HousekeepingConfig(
            outbox_max_age_hours=24.0, archive_ttl_hours=72.0, mailbox_ttl_hours=96.0
        )

        results = run_housekeeping_pass([t1, t2, _PrunerlessTransport()], cfg)

        assert results == {"outbox_pruned": 4, "archive_pruned": 2, "mailbox_pruned": 0}
        assert t1.outbox_calls == [24.0]
        assert t1.archive_calls == [72.0]
        assert t2.outbox_calls == [24.0]

    def test_one_failing_transport_never_aborts_the_pass(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        good = _FakePrunableTransport(outbox_result=5, archive_result=1)

        results = run_housekeeping_pass([_ExplodingTransport(), good])

        assert results["outbox_pruned"] == 5
        assert results["archive_pruned"] == 1

    def test_prunes_mailbox_records(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        outbox = tmp_path / "realm" / "op" / "agent" / "outbox"
        outbox.mkdir(parents=True)
        stale = outbox / "old.json"
        stale.write_text("{}")
        _backdate(stale, hours=500)

        results = run_housekeeping_pass([], HousekeepingConfig())

        assert results["mailbox_pruned"] == 1
        assert not stale.exists()


# ---------------------------------------------------------------------------
# housekeeping_loop
# ---------------------------------------------------------------------------


class TestHousekeepingLoop:
    async def test_loop_calls_pruners_periodically(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        transport = _FakePrunableTransport()
        cfg = HousekeepingConfig(interval_s=0.01, outbox_max_age_hours=48.0)

        task = asyncio.create_task(housekeeping_loop(lambda: [transport], cfg))
        try:
            for _ in range(200):
                await asyncio.sleep(0.01)
                if len(transport.outbox_calls) >= 2:
                    break
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        # Called MORE than once: this is a periodic loop, not a one-shot.
        assert len(transport.outbox_calls) >= 2
        assert transport.outbox_calls[0] == 48.0
        assert len(transport.archive_calls) >= 2

    async def test_loop_survives_a_failing_pass(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        transport = _FakePrunableTransport()
        calls = {"n": 0}

        def flaky_get_transports():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            return [transport]

        cfg = HousekeepingConfig(interval_s=0.01)
        task = asyncio.create_task(housekeeping_loop(flaky_get_transports, cfg))
        try:
            for _ in range(200):
                await asyncio.sleep(0.01)
                if transport.outbox_calls:
                    break
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert transport.outbox_calls  # kept going after the failure


# ---------------------------------------------------------------------------
# Daemon lifespan wiring (the acceptance-criteria test: the RUNNING daemon
# periodically invokes prune_outbox)
# ---------------------------------------------------------------------------


class TestLifespanHousekeepingWiring:
    class _StubSKComms:
        """Minimal SKComms stand-in so lifespan startup skips crypto."""

        identity = "test-agent"

        def __init__(self, transports, hk_cfg):
            class _Router:
                pass

            self.router = _Router()
            self.router.transports = transports
            self._config = SKCommsConfig(housekeeping=hk_cfg)

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
        import skcomms.api as api

        monkeypatch.setattr(api, "SignalingBroker", lambda *a, **k: object())
        monkeypatch.setattr(api, "CapAuthValidator", lambda *a, **k: object())
        monkeypatch.setattr(
            "skcomms.config.load_adapters_block", lambda *a, **k: {"adapters": {}}
        )
        yield

    async def test_daemon_lifespan_periodically_calls_prune_outbox(self, monkeypatch):
        import skcomms.api as api

        transport = _FakePrunableTransport()
        stub = self._StubSKComms([transport], HousekeepingConfig(interval_s=0.01))
        monkeypatch.setattr(api.SKComms, "from_config", classmethod(lambda cls: stub))

        async with api.lifespan(api.app):
            assert api._housekeeping_task is not None
            for _ in range(200):
                await asyncio.sleep(0.01)
                if len(transport.outbox_calls) >= 2:
                    break

        assert len(transport.outbox_calls) >= 2
        assert len(transport.archive_calls) >= 2
        # Shutdown cancelled and cleared the task.
        assert api._housekeeping_task is None

    async def test_lifespan_respects_housekeeping_disabled(self, monkeypatch):
        import skcomms.api as api

        transport = _FakePrunableTransport()
        stub = self._StubSKComms(
            [transport], HousekeepingConfig(enabled=False, interval_s=0.01)
        )
        monkeypatch.setattr(api.SKComms, "from_config", classmethod(lambda cls: stub))

        async with api.lifespan(api.app):
            assert api._housekeeping_task is None
            await asyncio.sleep(0.05)

        assert transport.outbox_calls == []


# ---------------------------------------------------------------------------
# CLI: skcomms housekeep
# ---------------------------------------------------------------------------


class TestHousekeepCLI:
    def test_housekeep_runs_one_full_pass(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from skcomms.cli import main as cli_main

        # No per-agent path rewrite: keep the config's explicit tmp paths.
        monkeypatch.delenv("SKAGENT", raising=False)
        monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))

        outbox = tmp_path / "outbox"
        outbox.mkdir()
        stale = outbox / f"stale{ENVELOPE_SUFFIX}"
        stale.write_bytes(_envelope_bytes("stale"))
        _backdate(stale, hours=100)
        fresh = outbox / f"fresh{ENVELOPE_SUFFIX}"
        fresh.write_bytes(_envelope_bytes("fresh"))

        # A stale mailbox outbox record in the realm tree under SKCOMMS_HOME.
        mb_outbox = tmp_path / "realm" / "op" / "agent" / "outbox"
        mb_outbox.mkdir(parents=True)
        mb_stale = mb_outbox / "old.json"
        mb_stale.write_text("{}")
        _backdate(mb_stale, hours=500)

        cfg = tmp_path / "config.yml"
        cfg.write_text(
            "skcomms:\n"
            "  transports:\n"
            "    file:\n"
            "      enabled: true\n"
            "      priority: 1\n"
            "      settings:\n"
            f"        outbox_path: {outbox}\n"
            f"        inbox_path: {tmp_path / 'inbox'}\n"
            f"        archive_path: {tmp_path / 'archive'}\n"
        )

        runner = CliRunner()
        result = runner.invoke(cli_main, ["housekeep", "-c", str(cfg), "--json-out"])

        assert result.exit_code == 0, result.output
        counts = json.loads(result.output)
        assert counts["outbox_pruned"] == 1
        assert counts["mailbox_pruned"] == 1
        assert not stale.exists()
        assert fresh.exists()
        assert not mb_stale.exists()

    def test_housekeep_ttl_overrides(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from skcomms.cli import main as cli_main

        monkeypatch.delenv("SKAGENT", raising=False)
        monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)
        monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))

        outbox = tmp_path / "outbox"
        outbox.mkdir()
        # 10h old: stale for a 5h override, fresh for the 48h default.
        f = outbox / f"tenhours{ENVELOPE_SUFFIX}"
        f.write_bytes(_envelope_bytes())
        _backdate(f, hours=10)

        cfg = tmp_path / "config.yml"
        cfg.write_text(
            "skcomms:\n"
            "  transports:\n"
            "    file:\n"
            "      enabled: true\n"
            "      settings:\n"
            f"        outbox_path: {outbox}\n"
            f"        inbox_path: {tmp_path / 'inbox'}\n"
        )

        runner = CliRunner()
        result = runner.invoke(
            cli_main,
            ["housekeep", "-c", str(cfg), "--outbox-max-age-hours", "5", "--json-out"],
        )

        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["outbox_pruned"] == 1
        assert not f.exists()


# ---------------------------------------------------------------------------
# Config defaults
# ---------------------------------------------------------------------------


class TestHousekeepingConfig:
    def test_sane_defaults(self):
        cfg = HousekeepingConfig()
        assert cfg.enabled is True
        assert cfg.interval_s == 3600.0
        assert cfg.outbox_max_age_hours == 48.0
        assert cfg.archive_ttl_hours == 168.0
        assert cfg.mailbox_ttl_hours == 168.0

    def test_loaded_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "config.yml"
        cfg_file.write_text(
            "skcomms:\n"
            "  housekeeping:\n"
            "    enabled: false\n"
            "    interval_s: 600\n"
            "    outbox_max_age_hours: 12\n"
            "    archive_ttl_hours: 24\n"
            "    mailbox_ttl_hours: 36\n"
        )
        cfg = SKCommsConfig.from_yaml(cfg_file)
        hk = cfg.housekeeping
        assert hk.enabled is False
        assert hk.interval_s == 600.0
        assert hk.outbox_max_age_hours == 12.0
        assert hk.archive_ttl_hours == 24.0
        assert hk.mailbox_ttl_hours == 36.0

    def test_absent_block_uses_defaults(self, tmp_path):
        cfg_file = tmp_path / "config.yml"
        cfg_file.write_text("skcomms:\n  version: '1.0.0'\n")
        assert SKCommsConfig.from_yaml(cfg_file).housekeeping == HousekeepingConfig()
