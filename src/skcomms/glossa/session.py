"""GlossaSession (spec §3, §8) — the per-peer API agents use: handshake, say,
on_message. Encodes at the negotiated level, decodes inbound, logs the English
gloss of everything (the audit invariant)."""

from __future__ import annotations

from typing import Callable

from skcomms.glossa import codec, gloss
from skcomms.glossa.codebook import Codebook
from skcomms.glossa.handshake import CapabilityDescriptor, Session, negotiate
from skcomms.glossa.message import Message


class GlossaSession:
    def __init__(self, *, local: CapabilityDescriptor, codebook: Codebook) -> None:
        self.local = local
        self.codebook = codebook
        self._session: Session | None = None
        self._transport: Callable[[bytes], None] | None = None
        self._on_message: Callable[[Message], None] | None = None
        self.audit_log: list[str] = []

    @property
    def level(self) -> int:
        return self._session.level if self._session else codec.L0_ENGLISH

    def set_transport(self, send: Callable[[bytes], None]) -> None:
        self._transport = send

    def on_message(self, cb: Callable[[Message], None]) -> None:
        self._on_message = cb

    def handshake(self, remote: CapabilityDescriptor) -> None:
        self._session = negotiate(self.local, remote)

    def say(self, m: Message) -> None:
        raw = codec.encode(m, self.level, self.codebook)
        self.audit_log.append(f"[tx L{self.level}] {gloss.to_english(m)}")
        if self._transport is not None:
            self._transport(raw)

    def receive(self, raw: bytes) -> None:
        try:
            m = codec.decode(raw, self.level, self.codebook)
        except Exception as exc:
            # Inbound frame not decodable at our level (e.g. peer hasn't
            # handshaked us yet, so we're still at L0 while it sent denser).
            # Log the failure rather than crashing the sender's transport call.
            self.audit_log.append(f"[rx L{self.level}] <undecodable: {exc}>")
            return
        self.audit_log.append(f"[rx L{self.level}] {gloss.to_english(m)}")
        if self._on_message is not None:
            self._on_message(m)
