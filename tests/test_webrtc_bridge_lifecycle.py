"""Regression tests for the WebRTC async/threading bridge (card 2df53aa5).

``WebRTCTransport`` runs an asyncio event loop in a background daemon thread
(``_run_loop``) and bridges the synchronous ``Transport`` API into it via
``asyncio.run_coroutine_threadsafe`` (``_run_in_loop``). That async/threading
boundary has several sharp edges that had no coverage:

  * loop closure + clean thread exit on ``stop()`` (no leaked/open loop),
  * an exception during ``run_until_complete`` (deliberate ``loop.stop()``
    mid-await, or a genuine ``_main_loop`` crash) must not escape the thread,
  * cross-thread submission when the loop is not running / stopped / closed,
  * the ``_running`` flag vs. async ops race — concurrent ``send()`` to a new
    peer must schedule exactly one offer,
  * an exception in a bridged send must surface as a failure, not deadlock,
  * cleanup on disconnect closes every peer connection.

All tests are deterministic: no real network, no real ICE. The bridge is
driven with controlled loops/threads and fake peers/channels.
"""

from __future__ import annotations

import asyncio
import threading
import time
import warnings

import pytest

from skcomms.transports.webrtc import PeerConnection, WebRTCTransport

# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────


class _CapturedThreadExc:
    """Context manager that records uncaught exceptions from worker threads.

    ``run_until_complete`` raising out of ``_run_loop`` would otherwise only
    manifest as a stderr traceback via ``threading.excepthook`` — invisible to
    assertions. This captures those so a test can assert the background thread
    exited cleanly.
    """

    def __init__(self):
        self.exceptions: list = []
        self._prev = None

    def __enter__(self):
        self._prev = threading.excepthook

        def _hook(args):
            self.exceptions.append(args)

        threading.excepthook = _hook
        return self

    def __exit__(self, *exc):
        threading.excepthook = self._prev
        return False


class _FakeChannel:
    """Minimal stand-in for an aiortc RTCDataChannel."""

    def __init__(self, raise_on_send: bool = False):
        self.sent: list[bytes] = []
        self.raise_on_send = raise_on_send

    def send(self, data: bytes) -> None:
        if self.raise_on_send:
            raise RuntimeError("simulated channel send failure")
        self.sent.append(data)


class _FakePC:
    """Minimal stand-in for an aiortc RTCPeerConnection (close() is awaitable)."""

    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


def _envelope(eid: str = "env-1") -> bytes:
    return b'{"envelope_id": "%s"}' % eid.encode()


def _make_running_transport() -> WebRTCTransport:
    """Start a transport whose loop is really running in its thread.

    Signaling points at an unroutable URL so no broker is contacted, but the
    background asyncio loop is live, so ``_run_in_loop`` round-trips work.
    """
    t = WebRTCTransport(signaling_url="ws://127.0.0.1:59999/nope", agent_name="test")
    t.start()
    # start() already blocks CONNECT_SETTLE; make sure the loop is running.
    for _ in range(100):
        if t._loop is not None and t._loop.is_running():
            break
        time.sleep(0.01)
    assert t._loop is not None and t._loop.is_running()
    return t


# ──────────────────────────────────────────────────────────────────────────
# Loop closure + clean thread exit on shutdown
# ──────────────────────────────────────────────────────────────────────────


def test_start_then_stop_closes_loop_and_joins_thread():
    t = _make_running_transport()
    thread = t._loop_thread
    assert thread is not None and thread.is_alive()

    t.stop()

    assert not thread.is_alive()
    assert t._loop.is_closed()
    assert t._running is False
    assert t._signaling_connected is False


def test_clean_shutdown_raises_no_thread_exception():
    """Regression: stop() while _main_loop is mid-await must not crash the thread.

    stop() shuts the loop with ``call_soon_threadsafe(loop.stop)``. With the
    loop almost always sleeping in reconnect backoff (or blocked on recv),
    ``run_until_complete`` raises ``RuntimeError: Event loop stopped before
    Future completed``. Before the fix that RuntimeError escaped ``_run_loop``
    and Python printed "Exception in thread skcomms-webrtc" on every ordinary
    shutdown. ``_run_loop`` now swallows it.
    """
    with _CapturedThreadExc() as cap:
        t = _make_running_transport()
        # Let the connect fail and _main_loop settle into asyncio.sleep(backoff).
        time.sleep(0.5)
        t.stop()
        time.sleep(0.2)

    assert not t._loop_thread.is_alive()
    assert t._loop.is_closed()
    webrtc_excs = [e for e in cap.exceptions if e.thread and e.thread.name == "skcomms-webrtc"]
    assert webrtc_excs == [], (
        f"background loop thread raised on shutdown: "
        f"{[ (e.exc_type.__name__, str(e.exc_value)) for e in webrtc_excs ]}"
    )


def test_run_loop_swallows_stop_but_logs_real_crash(caplog):
    """A genuine _main_loop crash is logged (not silently dropped); loop closes.

    Drives ``_run_loop`` directly with an injected ``_main_loop`` that raises a
    non-RuntimeError, exercising the exception-during-run_until_complete branch
    the card names without needing signaling.
    """
    t = WebRTCTransport(agent_name="test")
    t._loop = asyncio.new_event_loop()

    async def _boom():
        raise ValueError("boom in main loop")

    t._main_loop = _boom  # type: ignore[assignment]

    with caplog.at_level("ERROR", logger="skcomms.transports.webrtc"):
        thr = threading.Thread(target=t._run_loop, name="skcomms-webrtc-test", daemon=True)
        with _CapturedThreadExc() as cap:
            thr.start()
            thr.join(timeout=5.0)

    assert not thr.is_alive()
    assert t._loop.is_closed()  # finally: closed even after a crash
    assert cap.exceptions == []  # did not escape the thread target
    assert any("crashed" in r.getMessage() for r in caplog.records)


def test_stop_before_start_is_noop():
    t = WebRTCTransport(agent_name="test")
    # Never started: no loop, no thread. Must not raise.
    t.stop()
    assert t._running is False


def test_double_stop_is_idempotent():
    t = _make_running_transport()
    t.stop()
    closed_after_first = t._loop.is_closed()
    # Second stop must not raise even though the loop is closed and thread gone.
    t.stop()
    assert closed_after_first and t._loop.is_closed()


# ──────────────────────────────────────────────────────────────────────────
# Cross-thread submission guard (_run_in_loop) — loop not running/stopped/closed
# ──────────────────────────────────────────────────────────────────────────


def test_run_in_loop_raises_when_never_started():
    t = WebRTCTransport(agent_name="test")

    async def _noop():
        return 1

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # a leaked coroutine -> RuntimeWarning -> error
        with pytest.raises(RuntimeError, match="not running"):
            t._run_in_loop(_noop())


def test_run_in_loop_raises_after_stop():
    t = _make_running_transport()
    t.stop()

    async def _noop():
        return 1

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(RuntimeError, match="not running"):
            t._run_in_loop(_noop())


def test_run_in_loop_closes_coroutine_on_reject():
    """Rejected submission must close the coroutine (no 'never awaited' warning)."""
    t = WebRTCTransport(agent_name="test")

    async def _noop():
        return 1

    coro = _noop()
    with pytest.raises(RuntimeError):
        t._run_in_loop(coro)
    # A closed coroutine cannot be awaited/sent again.
    with pytest.raises((RuntimeError, StopIteration)):
        coro.send(None)


def test_run_in_loop_roundtrips_on_running_loop():
    t = _make_running_transport()
    try:

        async def _add():
            return 40 + 2

        fut = t._run_in_loop(_add())
        assert fut.result(timeout=5.0) == 42
    finally:
        t.stop()


# ──────────────────────────────────────────────────────────────────────────
# send() surface — not started / bridged exception (no deadlock)
# ──────────────────────────────────────────────────────────────────────────


def test_send_when_not_started_returns_failure_not_exception():
    t = WebRTCTransport(agent_name="test")
    res = t.send(_envelope("e1"), recipient="peerfp")
    assert res.success is False
    assert res.transport_name == "webrtc"
    assert res.envelope_id == "e1"
    assert "not started" in (res.error or "")


def test_send_happy_path_bridges_to_loop():
    """A connected peer's send round-trips through the background loop."""
    t = _make_running_transport()
    try:
        chan = _FakeChannel()
        with t._peers_lock:
            t._peers["peerfp"] = PeerConnection(
                peer_fingerprint="peerfp", pc=_FakePC(), channel=chan, connected=True
            )
        res = t.send(_envelope("e2"), recipient="peerfp")
        assert res.success is True
        assert res.envelope_id == "e2"
        assert chan.sent == [_envelope("e2")]
    finally:
        t.stop()


def test_send_channel_exception_returns_failure_without_deadlock():
    """An exception in the bridged send must surface as failure, not hang.

    Marks the peer disconnected and returns within the send timeout — a
    deadlock would instead time out the test.
    """
    t = _make_running_transport()
    try:
        peer = PeerConnection(
            peer_fingerprint="peerfp",
            pc=_FakePC(),
            channel=_FakeChannel(raise_on_send=True),
            connected=True,
        )
        with t._peers_lock:
            t._peers["peerfp"] = peer

        start = time.monotonic()
        res = t.send(_envelope("e3"), recipient="peerfp")
        elapsed = time.monotonic() - start

        assert res.success is False
        assert "simulated channel send failure" in (res.error or "")
        assert peer.connected is False  # marked down under lock
        assert elapsed < 5.0  # returned well within SEND_TIMEOUT — no deadlock
    finally:
        t.stop()


# ──────────────────────────────────────────────────────────────────────────
# _running flag vs. async ops race — concurrent send() schedules one offer
# ──────────────────────────────────────────────────────────────────────────


def test_concurrent_send_new_peer_schedules_single_offer():
    """N threads sending to the same new peer must schedule exactly one offer.

    The negotiating-stub decision is made under ``_peers_lock``; only the one
    thread that flips ``should_offer`` may dispatch ``_initiate_offer``. This
    exercises the flag/async-op race directly (submission is stubbed so no real
    loop/ICE is involved).
    """
    t = WebRTCTransport(agent_name="test")
    # Present the send() should_offer branch with a live-looking bridge.
    t._running = True
    t._loop = object()  # truthy; _run_in_loop is stubbed below so it's never used

    scheduled: list = []
    sched_lock = threading.Lock()

    def _fake_run_in_loop(coro):
        # Close the (unawaited) _initiate_offer coroutine and record the call.
        coro.close()
        with sched_lock:
            scheduled.append(True)

        class _F:
            def result(self, timeout=None):
                return None

        return _F()

    t._run_in_loop = _fake_run_in_loop  # type: ignore[assignment]

    n = 24
    barrier = threading.Barrier(n)
    results: list = []
    res_lock = threading.Lock()

    def _worker():
        barrier.wait()  # maximize contention
        r = t.send(_envelope(), recipient="samepeer")
        with res_lock:
            results.append(r)

    threads = [threading.Thread(target=_worker) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=5.0)

    assert len(scheduled) == 1, f"expected exactly one offer scheduled, got {len(scheduled)}"
    assert len(results) == n
    # Exactly one peer stub exists and it is marked negotiating.
    assert list(t._peers.keys()) == ["samepeer"]
    assert t._peers["samepeer"].negotiating is True


# ──────────────────────────────────────────────────────────────────────────
# Cleanup on disconnect — stop() closes every peer connection
# ──────────────────────────────────────────────────────────────────────────


def test_stop_closes_all_peer_connections():
    t = _make_running_transport()
    pcs = [_FakePC() for _ in range(3)]
    with t._peers_lock:
        for i, pc in enumerate(pcs):
            t._peers[f"peer{i}"] = PeerConnection(peer_fingerprint=f"peer{i}", pc=pc)

    t.stop()

    assert all(pc.closed for pc in pcs), "stop() must close every peer's RTCPeerConnection"
    assert t._loop.is_closed()


def test_cleanup_peer_removes_and_closes():
    t = _make_running_transport()
    try:
        pc = _FakePC()
        with t._peers_lock:
            t._peers["gone"] = PeerConnection(peer_fingerprint="gone", pc=pc)

        fut = t._run_in_loop(t._cleanup_peer("gone"))
        fut.result(timeout=5.0)

        assert pc.closed is True
        with t._peers_lock:
            assert "gone" not in t._peers
    finally:
        t.stop()
