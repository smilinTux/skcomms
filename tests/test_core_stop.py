"""SKComms.stop() must halt the outbox retry worker.

Regression: ``from_config`` starts a persistent ``skcomms-outbox-retry`` daemon
thread. Any short-lived engine built only to read router state (a health probe,
a doctor check) leaks one such thread per construction unless it is stopped. A
polled dashboard once accumulated 400+ leaked workers, saturating CPU and
starving its asyncio event loop.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

from skcomms.core import SKComms
from skcomms.outbox import PersistentOutbox
from skcomms.router import Router


def _retry_threads() -> int:
    return sum(1 for t in threading.enumerate() if "outbox-retry" in (t.name or ""))


def _engine(tmp_path: Path) -> SKComms:
    comm = SKComms(router=Router(transports=[]))
    comm._outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=comm._router)
    return comm


def test_stop_halts_outbox_worker(tmp_path):
    """A started outbox worker is joined and gone after stop()."""
    comm = _engine(tmp_path)
    before = _retry_threads()
    comm._outbox.start(interval=30)
    assert _retry_threads() == before + 1
    comm.stop()
    time.sleep(0.2)  # allow the joined thread to clear the enumeration
    assert _retry_threads() == before


def test_stop_is_idempotent_and_safe_when_never_started(tmp_path):
    """stop() is a no-op (not an error) when the worker was never started."""
    comm = _engine(tmp_path)
    before = _retry_threads()
    comm.stop()  # never started
    comm.stop()  # twice
    assert _retry_threads() == before
