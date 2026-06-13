"""GlossaSession (spec §3, §8) — the per-peer API agents use: handshake, say,
on_message. Encodes at the negotiated level, decodes inbound, logs the English
gloss of everything (the audit invariant)."""

from __future__ import annotations

from dataclasses import replace as _replace
from typing import Callable

import cbor2

from skcomms.glossa import codec, gloss
from skcomms.glossa.codebook import Codebook
from skcomms.glossa.handshake import CapabilityDescriptor, Session, negotiate
from skcomms.glossa.macros import MacroLexicon, expand_macros
from skcomms.glossa.message import Message


class GlossaSession:
    def __init__(self, *, local: CapabilityDescriptor, codebook: Codebook,
                 lexicon: MacroLexicon | None = None) -> None:
        self.local = local
        self.codebook = codebook
        self._lexicon = lexicon
        self._session: Session | None = None
        self._transport: Callable[[bytes], None] | None = None
        self._on_message: Callable[[Message], None] | None = None
        self._on_error: Callable[[bytes, Exception], None] | None = None
        self.audit_log: list[str] = []

    def macro_prompt_block(self) -> str:
        return self._lexicon.render_prompt_block() if self._lexicon else ""

    def _audit_gloss(self, m: Message) -> str:
        # Expand macros in the TEXT SLOT ONLY: gloss a copy whose text is
        # pre-expanded, so only the ": <text>" clause carries the expansion
        # (a global replace would also rewrite a matching intent/arg).
        if self._lexicon is not None and m.text:
            expanded = expand_macros(m.text, self._lexicon)
            return gloss.to_english(_replace(m, text=expanded))
        return gloss.to_english(m)

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
        self.audit_log.append(f"[tx L{self.level}] {self._audit_gloss(m)}")
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
        self.audit_log.append(f"[rx L{self.level}] {self._audit_gloss(m)}")
        if self._on_message is not None:
            self._on_message(m)
