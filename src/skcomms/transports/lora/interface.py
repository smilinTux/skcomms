"""LoRaMeshInterface seam + FakeLoRaInterface (spec §4, §7).

The seam every LoRa backend implements. FakeLoRaInterface is an in-memory bus
with airtime accounting so the store-and-forward scheduler is testable without a
radio. MeshtasticInterface (L2) implements the same seam over real hardware.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

ReceiveCb = Callable[[bytes, str], None]  # (frame, source_node_id)


class LoRaMeshInterface(ABC):
    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def send_frame(self, data: bytes, *, dest: str | None) -> None:
        """Send one LoRa frame; dest=None means broadcast on the SK channel."""

    @abstractmethod
    def on_receive(self, cb: ReceiveCb) -> None: ...

    @abstractmethod
    def info(self) -> dict: ...


class FakeLoRaMedium:
    """Shared in-memory medium; every started interface hears every broadcast."""

    def __init__(self) -> None:
        self._nodes: dict[str, "FakeLoRaInterface"] = {}

    def register(self, iface: "FakeLoRaInterface") -> None:
        self._nodes[iface.node_id] = iface

    async def deliver(self, src: str, data: bytes, dest: str | None) -> None:
        for nid, iface in self._nodes.items():
            if nid == src or not iface.running:
                continue
            if dest is not None and nid != dest:
                continue
            iface._inbound(data, src)


class FakeLoRaInterface(LoRaMeshInterface):
    """In-memory bus for tests.

    `bytes_sent` is RAW TELEMETRY ONLY (total bytes ever transmitted by this
    node) — it does NOT enforce any cap. Duty-cycle enforcement lives in the
    transport's AirtimeBudget (see store.py); the interface never second-guesses
    it, so there is exactly one enforcement path.
    """

    def __init__(self, node_id: str, medium: FakeLoRaMedium) -> None:
        self.node_id = node_id
        self._medium = medium
        self._cb: ReceiveCb | None = None
        self.running = False
        self.bytes_sent = 0   # telemetry only; not a cap
        medium.register(self)

    async def start(self) -> None:
        self.running = True

    async def stop(self) -> None:
        self.running = False

    async def send_frame(self, data: bytes, *, dest: str | None) -> None:
        if not self.running:
            raise RuntimeError("interface not started")
        self.bytes_sent += len(data)
        await self._medium.deliver(self.node_id, data, dest)

    def on_receive(self, cb: ReceiveCb) -> None:
        self._cb = cb

    def info(self) -> dict:
        return {"node_id": self.node_id, "bytes_sent": self.bytes_sent,
                "running": self.running}

    def _inbound(self, data: bytes, src: str) -> None:
        if self._cb is not None:
            self._cb(data, src)
