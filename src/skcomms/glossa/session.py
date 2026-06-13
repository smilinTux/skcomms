"""GlossaSession (spec §3, §8) — the per-peer API agents use: handshake, say,
on_message. Encodes at the negotiated level, decodes inbound, logs the English
gloss of everything (the audit invariant)."""

from __future__ import annotations

from typing import Callable

import cbor2

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
        self._on_error: Callable[[bytes, Exception], None] | None = None
        self.audit_log: list[str] = []

    @property
    def level(self) -> int:
        return self._session.level if self._session else codec.L0_ENGLISH

    def set_transport(self, send: Callable[[bytes], None]) -> None:
        self._transport = send

    def on_message(self, cb: Callable[[Message], None]) -> None:
        self._on_message = cb

    def on_error(self, cb: Callable[[bytes, Exception], None]) -> None:
        self._on_error = cb

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
        except (cbor2.CBORDecodeError, UnicodeDecodeError, ValueError) as exc:
            # A decode-shape failure on an inbound frame. Distinguish two cases:
            self.audit_log.append(f"[rx L{self.level}] <undecodable: {exc}>")
            if self._session is None:
                # Not yet handshaked (still at our default level) — a denser
                # frame from a peer that hasn't handshaked us is a tolerable
                # pre-handshake transient. The degenerate one-sided case.
                return
            # Handshaked: both peers AGREED a level, so a decode failure here is
            # a REAL fault (corruption / truncation / version skew). Surface it.
            if self._on_error is not None:
                self._on_error(raw, exc)
                return
            raise
        self.audit_log.append(f"[rx L{self.level}] {gloss.to_english(m)}")
        if self._on_message is not None:
            self._on_message(m)
