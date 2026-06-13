"""Radio abstraction + FakeRadio in-memory bus (spec §8).

`Radio` is the seam every driver implements: P1 ships FakeRadio (no hardware);
P2 adds BleakRadio (real BLE) implementing the same interface. A MeshNode talks
only to `Radio`, so all mesh logic is tested through FakeRadio in CI.

`FakeMedium` models a who-can-hear-whom topology: only linked radios deliver each
other's broadcasts (one BLE hop). Multi-hop emerges from MeshNodes relaying.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

ReceiveCb = Callable[[bytes, str], None]  # (data, source_radio_id)


class Radio(ABC):
    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def broadcast(self, data: bytes) -> None:
        """Send `data` to every radio within one hop."""

    @abstractmethod
    def on_receive(self, cb: ReceiveCb) -> None:
        """Register the callback invoked for each received frame."""


class FakeMedium:
    """Shared in-memory medium; tracks links (adjacency) between radio ids."""

    def __init__(self) -> None:
        self._radios: dict[str, "FakeRadio"] = {}
        self._adj: dict[str, set[str]] = {}

    def register(self, radio: "FakeRadio") -> None:
        self._radios[radio.radio_id] = radio
        self._adj.setdefault(radio.radio_id, set())

    def link(self, a: str, b: str) -> None:
        self._adj.setdefault(a, set()).add(b)
        self._adj.setdefault(b, set()).add(a)

    def unlink(self, a: str, b: str) -> None:
        self._adj.get(a, set()).discard(b)
        self._adj.get(b, set()).discard(a)

    def neighbors(self, rid: str) -> set[str]:
        return set(self._adj.get(rid, set()))

    async def deliver(self, src: str, data: bytes) -> None:
        for nid in self.neighbors(src):
            radio = self._radios.get(nid)
            if radio is not None and radio.running:
                radio._inbound(data, src)


class FakeRadio(Radio):
    def __init__(self, radio_id: str, medium: FakeMedium) -> None:
        self.radio_id = radio_id
        self._medium = medium
        self._cb: ReceiveCb | None = None
        self.running = False
        medium.register(self)

    async def start(self) -> None:
        self.running = True

    async def stop(self) -> None:
        self.running = False

    async def broadcast(self, data: bytes) -> None:
        if not self.running:
            raise RuntimeError("radio not started")
        await self._medium.deliver(self.radio_id, data)

    def on_receive(self, cb: ReceiveCb) -> None:
        self._cb = cb

    def _inbound(self, data: bytes, src: str) -> None:
        if self._cb is not None:
            self._cb(data, src)
