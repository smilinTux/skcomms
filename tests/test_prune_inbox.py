"""Workstream B7: FileTransport / SyncthingTransport ``prune_inbox`` primitive.

RC5 (inbox never GC'd): inbox envelopes are write-once/read-maybe/delete-never,
so ~270k un-GC'd ``comms/inbox`` files pinned Syncthing on a fleet laptop.
Delete-on-consume is the primary fix (skcapstone C1); this is the TTL-backstop
primitive skcapstone F6 consumes. ``prune_inbox(ttl_hours)`` deletes inbox
envelope files older than the TTL, reusing ``_prune_dir_by_ttl``, and the
housekeeping pass calls it via ``HousekeepingConfig.inbox_ttl_hours``.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from skcomms.config import HousekeepingConfig
from skcomms.housekeeping import run_housekeeping_pass
from skcomms.transports.file import ENVELOPE_SUFFIX, FileTransport
from skcomms.transports.syncthing import SyncthingTransport


def _write(path: Path, age_hours: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    if age_hours:
        old = time.time() - age_hours * 3600.0
        os.utime(path, (old, old))


def test_file_prune_inbox_removes_only_aged_files(tmp_path):
    inbox = tmp_path / "inbox"
    t = FileTransport(outbox_path=tmp_path / "outbox", inbox_path=inbox)

    _write(inbox / f"old{ENVELOPE_SUFFIX}", age_hours=200)
    _write(inbox / f"fresh{ENVELOPE_SUFFIX}", age_hours=1)

    deleted = t.prune_inbox(ttl_hours=168.0)

    assert deleted == 1
    assert not (inbox / f"old{ENVELOPE_SUFFIX}").exists()
    assert (inbox / f"fresh{ENVELOPE_SUFFIX}").exists()


def test_file_prune_inbox_skips_hidden_and_zero_ttl(tmp_path):
    inbox = tmp_path / "inbox"
    t = FileTransport(outbox_path=tmp_path / "outbox", inbox_path=inbox)
    _write(inbox / f".partial{ENVELOPE_SUFFIX}.tmp", age_hours=500)
    _write(inbox / f"aged{ENVELOPE_SUFFIX}", age_hours=500)

    # ttl<=0 disables the sweep entirely.
    assert t.prune_inbox(ttl_hours=0) == 0
    assert (inbox / f"aged{ENVELOPE_SUFFIX}").exists()

    # A real sweep never touches the hidden in-flight temp file.
    deleted = t.prune_inbox(ttl_hours=168.0)
    assert deleted == 1
    assert (inbox / f".partial{ENVELOPE_SUFFIX}.tmp").exists()


def test_syncthing_prune_inbox_sweeps_peer_subdirs(tmp_path):
    root = tmp_path / "comms"
    t = SyncthingTransport(comms_root=root)
    inbox = root / "inbox"
    _write(inbox / "jarvis" / f"old{ENVELOPE_SUFFIX}", age_hours=300)
    _write(inbox / "jarvis" / f"fresh{ENVELOPE_SUFFIX}", age_hours=1)
    _write(inbox / "chef" / f"old{ENVELOPE_SUFFIX}", age_hours=300)

    deleted = t.prune_inbox(ttl_hours=168.0)

    assert deleted == 2
    assert not (inbox / "jarvis" / f"old{ENVELOPE_SUFFIX}").exists()
    assert (inbox / "jarvis" / f"fresh{ENVELOPE_SUFFIX}").exists()
    assert not (inbox / "chef" / f"old{ENVELOPE_SUFFIX}").exists()


def test_housekeeping_config_has_inbox_ttl_default():
    cfg = HousekeepingConfig()
    assert cfg.inbox_ttl_hours == 168.0


def test_run_housekeeping_pass_calls_prune_inbox(tmp_path, monkeypatch):
    # Isolate the mailbox/reseal sweep away from the real skcomms home.
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    inbox = tmp_path / "inbox"
    t = FileTransport(outbox_path=tmp_path / "outbox", inbox_path=inbox)
    _write(inbox / f"old{ENVELOPE_SUFFIX}", age_hours=400)

    cfg = HousekeepingConfig(
        inbox_ttl_hours=168.0,
        mailbox_ttl_hours=0,  # keep the pass scoped to transport sweeps
    )
    results = run_housekeeping_pass([t], cfg)

    assert results["inbox_pruned"] == 1
    assert not (inbox / f"old{ENVELOPE_SUFFIX}").exists()
