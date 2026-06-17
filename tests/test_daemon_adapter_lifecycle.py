"""
Daemon ⇄ adapter-registry lifecycle wiring.

The :class:`~skcomms.adapters.registry.AdapterRegistry` + factory were fully
unit-tested but never instantiated by the running daemon. These tests assert
the FastAPI ``lifespan`` actually:

  * builds a registry from the raw ``adapters:`` config block,
  * ``connect()``s every enabled+credentialed adapter on startup, and
  * ``disconnect()``s them on shutdown,

while staying backward-compatible: with no ``adapters:`` block, startup and
shutdown are clean no-ops (empty registry, nothing connected).

We drive the real ``lifespan`` async context manager, isolating the unrelated
heavyweight startup (SKComms crypto/outbox + the WebRTC signaling broker) by
patching their constructors. The adapter wiring under test runs for real.
"""

from __future__ import annotations

import pytest

import skcomms.api as api
from skcomms.adapters.fake import FakeAdapter


class _StubSKComms:
    """Minimal stand-in for SKComms so lifespan startup doesn't touch crypto."""

    identity = "test-agent"

    class _Router:
        transports: list = []

    router = _Router()


@pytest.fixture(autouse=True)
def _isolate_heavyweight(monkeypatch):
    """Stub out SKComms + the signaling broker; leave adapter wiring real."""
    monkeypatch.setattr(api.SKComms, "from_config", classmethod(lambda cls: _StubSKComms()))
    monkeypatch.setattr(api, "SignalingBroker", lambda *a, **k: object())
    monkeypatch.setattr(api, "CapAuthValidator", lambda *a, **k: object())
    yield


def _patch_adapters_block(monkeypatch, block: dict) -> None:
    """Make the lifespan's ``load_adapters_block()`` return *block*."""
    monkeypatch.setattr(
        "skcomms.config.load_adapters_block",
        lambda *a, **k: block,
    )


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_configured_adapter(monkeypatch):
    _patch_adapters_block(
        monkeypatch,
        {"adapters": {"fake": {"enabled": True, "adapter_name": "fake-A"}}},
    )

    async with api.lifespan(api.app):
        reg = api._adapter_registry
        assert reg is not None
        adapter = reg.get("fake-A")
        assert isinstance(adapter, FakeAdapter)
        # start() called connect() on the registered adapter
        assert adapter._connected is True

    # On shutdown the registry is stopped (adapter disconnected) and cleared.
    assert adapter._connected is False
    assert api._adapter_registry is None


@pytest.mark.asyncio
async def test_lifespan_no_adapters_block_is_clean_noop(monkeypatch):
    # Absent adapters block → empty registry, nothing connected, no error.
    _patch_adapters_block(monkeypatch, {"adapters": {}})

    async with api.lifespan(api.app):
        reg = api._adapter_registry
        assert reg is not None
        # empty registry: no adapters registered
        assert reg.get("fake-A") is None

    assert api._adapter_registry is None


@pytest.mark.asyncio
async def test_lifespan_handles_missing_adapters_key(monkeypatch):
    # Even a bare dict (no "adapters" key at all) must not crash startup.
    _patch_adapters_block(monkeypatch, {})

    async with api.lifespan(api.app):
        assert api._adapter_registry is not None

    assert api._adapter_registry is None
