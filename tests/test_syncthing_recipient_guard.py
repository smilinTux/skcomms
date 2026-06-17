"""Tests for the Syncthing transport recipient-name guard + outbox self-trim.

Regression coverage for the v1 broadcast-directory disk-fill / overheat
incident: a ``recipient="*"`` presence broadcast was written verbatim as a
literal ``outbox/*/`` directory, and ~256k stale envelopes accumulated inside
it until a Framework 13 laptop overheated.

Covers:
    - _validate_peer_name / send() reject glob metacharacters (``*`` et al.),
      path separators, traversal, NUL, and empty names — and create NO directory.
    - a valid peer name still sends and creates the outbox dir.
    - receive() skips junk peer directories (defense in depth).
    - prune_outbox() deletes stale envelopes, keeps fresh ones, and removes
      emptied peer dirs.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from skcomms.transports.syncthing import (
    ENVELOPE_SUFFIX,
    SyncthingTransport,
    _validate_peer_name,
)


def _envelope_bytes(envelope_id: str = "test-id-0001") -> bytes:
    """Minimal serialized envelope for send()."""
    return json.dumps({"envelope_id": envelope_id, "body": "hi"}).encode("utf-8")


@pytest.fixture
def transport(tmp_path):
    """A SyncthingTransport rooted at a tmp comms dir."""
    return SyncthingTransport(comms_root=tmp_path / "comms", archive=False)


# ---------------------------------------------------------------------------
# _validate_peer_name (unit)
# ---------------------------------------------------------------------------


class TestValidatePeerName:
    def test_valid_name_returned_stripped(self):
        assert _validate_peer_name("  lumina  ") == "lumina"

    @pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
    def test_rejects_empty_or_whitespace(self, bad):
        with pytest.raises(ValueError, match="empty or whitespace"):
            _validate_peer_name(bad)

    @pytest.mark.parametrize("bad", ["*", "lumina?", "a[bc]d", "wild*card"])
    def test_rejects_glob_metacharacters(self, bad):
        with pytest.raises(ValueError, match="glob metacharacter"):
            _validate_peer_name(bad)

    @pytest.mark.parametrize("bad", ["a/b", "a\\b", "/etc", "..\\x"])
    def test_rejects_path_separators(self, bad):
        with pytest.raises(ValueError, match="path separator|path traversal"):
            _validate_peer_name(bad)

    def test_rejects_traversal(self):
        with pytest.raises(ValueError, match="path traversal"):
            _validate_peer_name("..")

    def test_rejects_nul(self):
        with pytest.raises(ValueError, match="NUL"):
            _validate_peer_name("lumi\x00na")


# ---------------------------------------------------------------------------
# send() guard — the literal-`*` bug
# ---------------------------------------------------------------------------


class TestSendGuard:
    def test_star_recipient_raises_and_creates_no_dir(self, transport, tmp_path):
        outbox = tmp_path / "comms" / "outbox"
        with pytest.raises(ValueError, match="glob metacharacter"):
            transport.send(_envelope_bytes(), "*")

        # The whole point: NO outbox/*/ directory may exist.
        assert not (outbox / "*").exists()
        if outbox.exists():
            assert list(outbox.iterdir()) == []

    @pytest.mark.parametrize("bad", ["../escape", "a/b", "..", "   "])
    def test_path_traversal_and_separators_rejected(self, transport, tmp_path, bad):
        outbox = tmp_path / "comms" / "outbox"
        with pytest.raises(ValueError):
            transport.send(_envelope_bytes(), bad)
        if outbox.exists():
            # No junk peer dir was created for the bad name.
            assert all(d.name not in {bad, bad.strip(), ".."} for d in outbox.iterdir())

    def test_valid_recipient_creates_outbox_and_succeeds(self, transport, tmp_path):
        result = transport.send(_envelope_bytes("good-1"), "lumina")
        assert result.success is True

        peer_outbox = tmp_path / "comms" / "outbox" / "lumina"
        assert peer_outbox.is_dir()
        files = list(peer_outbox.glob(f"*{ENVELOPE_SUFFIX}"))
        assert len(files) == 1
        assert files[0].name == f"good-1{ENVELOPE_SUFFIX}"


# ---------------------------------------------------------------------------
# receive() skips junk peer directories
# ---------------------------------------------------------------------------


class TestReceiveSkipsJunkDirs:
    def test_star_outbox_dir_is_not_scanned(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SKAGENT", raising=False)
        monkeypatch.delenv("SKCAPSTONE_AGENT", raising=False)

        comms = tmp_path / "comms"
        transport = SyncthingTransport(comms_root=comms, archive=False)
        transport._local_names = ["*"]  # pathological identity

        # Simulate a v1 leftover: outbox/*/ stuffed with an envelope.
        junk = comms / "outbox" / "*"
        junk.mkdir(parents=True)
        (junk / f"stale{ENVELOPE_SUFFIX}").write_bytes(_envelope_bytes("stale"))

        received = transport.receive()
        # The junk dir name is invalid, so it must never be scanned/consumed.
        assert received == []
        assert (junk / f"stale{ENVELOPE_SUFFIX}").exists()


# ---------------------------------------------------------------------------
# prune_outbox()
# ---------------------------------------------------------------------------


class TestPruneOutbox:
    def test_deletes_stale_keeps_fresh_and_removes_empty_dirs(self, transport, tmp_path):
        outbox = tmp_path / "comms" / "outbox"

        # Fresh peer: one recent file.
        fresh_dir = outbox / "fresh-peer"
        fresh_dir.mkdir(parents=True)
        fresh_file = fresh_dir / f"recent{ENVELOPE_SUFFIX}"
        fresh_file.write_bytes(_envelope_bytes("recent"))

        # Stale peer: one old file (mtime 100h ago).
        stale_dir = outbox / "stale-peer"
        stale_dir.mkdir(parents=True)
        stale_file = stale_dir / f"old{ENVELOPE_SUFFIX}"
        stale_file.write_bytes(_envelope_bytes("old"))
        old_time = time.time() - (100 * 3600)
        os.utime(stale_file, (old_time, old_time))

        deleted = transport.prune_outbox(max_age_hours=48.0)

        assert deleted == 1
        assert fresh_file.exists()  # fresh kept
        assert not stale_file.exists()  # stale deleted
        assert not stale_dir.exists()  # emptied peer dir removed
        assert fresh_dir.exists()  # non-empty peer dir kept

    def test_zero_max_age_prunes_nothing(self, transport, tmp_path):
        outbox = tmp_path / "comms" / "outbox"
        d = outbox / "peer"
        d.mkdir(parents=True)
        f = d / f"x{ENVELOPE_SUFFIX}"
        f.write_bytes(_envelope_bytes())
        os.utime(f, (0, 0))  # ancient

        assert transport.prune_outbox(max_age_hours=0) == 0
        assert f.exists()

    def test_missing_outbox_returns_zero(self, tmp_path):
        transport = SyncthingTransport(comms_root=tmp_path / "nope", archive=False)
        assert transport.prune_outbox() == 0
