"""Shared test isolation for the skcomms suite.

Two cross-file hazards the access-plane tests surfaced:
  * sync tests that call ``asyncio.get_event_loop().run_until_complete`` on the
    shared default loop can leave it closed → later async/sync tests fail;
  * the process-wide ``DEFAULT_REGISTRY`` accumulates tools across files.

This autouse fixture heals a closed default loop and clears the default access
registry around every test, so order/combination no longer matters.
"""

from __future__ import annotations

import asyncio

import pytest


@pytest.fixture(autouse=True)
def _isolate_skcomms_home(tmp_path, monkeypatch):
    """Keep every test's skcomms home off the real ~/.skcapstone/skcomms.

    AccessServer (and api._get_nonce_cache) open a durable nonce store under
    ``skcomms_home()/state/`` by default (coord f465b407 / 11e295a3); without
    isolation, tests that build servers with defaults would write replay
    state into the operator's live home. Tests that need a specific home
    still win: their own ``monkeypatch.setenv`` runs after this fixture.
    """
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms-home"))
    # Nonce caches are node-local (outside the synced home) by default; keep
    # tests off the operator's real ~/.local/state/skcomms as well.
    monkeypatch.setenv("SKCOMMS_NONCE_CACHE_DIR", str(tmp_path / "skcomms-local-state"))
    monkeypatch.delenv("SKCOMMS_NONCE_CACHE", raising=False)
    monkeypatch.delenv("SKCOMMS_NONCE_DB", raising=False)
    monkeypatch.delenv("SKCOMMS_ACCESS_NONCE_DB", raising=False)


@pytest.fixture(autouse=True)
def _isolate_loop_and_registry():
    # Ensure a usable default loop exists before the test.
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            asyncio.set_event_loop(asyncio.new_event_loop())
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    try:
        from skcomms.access.registry import DEFAULT_REGISTRY
        DEFAULT_REGISTRY.clear()
    except Exception:  # pragma: no cover — access pkg optional
        pass

    yield

    # Heal again so a test that closed the loop doesn't poison the next one.
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            asyncio.set_event_loop(asyncio.new_event_loop())
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    try:
        from skcomms.access.registry import DEFAULT_REGISTRY
        DEFAULT_REGISTRY.clear()
    except Exception:  # pragma: no cover
        pass
