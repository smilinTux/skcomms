"""Noise_XX_25519_ChaChaPoly_SHA256 session (spec §2, §3).

Thin wrapper over dissononce that exposes a minimal state machine:
    write_handshake() / read_handshake()  until handshake_complete,
    then encrypt() / decrypt() for transport messages.

XX gives mutual authentication: after the 3-message handshake each side knows the
other's static public key (used to bind to a fqid/fingerprint upstream).
"""

from __future__ import annotations

from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.private import PrivateKey
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.XX import (
    XXHandshakePattern,
)
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState


def _new_handshake_state(static_priv_bytes: bytes) -> HandshakeState:
    # dissononce's HandshakeState expects the local static `s` to be a full
    # KeyPair (it reads `s.public.data` when writing its static into the
    # handshake), not a bare PrivateKey. Build the KeyPair from the raw private
    # bytes via the DH's generate_keypair(privatekey=...).
    dh = X25519DH()
    static = dh.generate_keypair(PrivateKey(static_priv_bytes))
    return HandshakeState(
        SymmetricState(CipherState(ChaChaPolyCipher()), SHA256Hash()),
        dh,
    ), static


class NoiseSession:
    def __init__(self, *, initiator: bool, static_priv_bytes: bytes) -> None:
        self._initiator = initiator
        self._hs, self._s = _new_handshake_state(static_priv_bytes)
        self._hs.initialize(XXHandshakePattern(), initiator, b"", s=self._s)
        self._send_cs: CipherState | None = None
        self._recv_cs: CipherState | None = None
        self._peer_static_pub: bytes | None = None

    @classmethod
    def initiator(cls, static_priv_bytes: bytes) -> "NoiseSession":
        return cls(initiator=True, static_priv_bytes=static_priv_bytes)

    @classmethod
    def responder(cls, static_priv_bytes: bytes) -> "NoiseSession":
        return cls(initiator=False, static_priv_bytes=static_priv_bytes)

    @property
    def handshake_complete(self) -> bool:
        return self._send_cs is not None and self._recv_cs is not None

    @property
    def peer_static_pub(self) -> bytes | None:
        return self._peer_static_pub

    def write_handshake(self, payload: bytes = b"") -> bytes:
        buf = bytearray()
        result = self._hs.write_message(payload, buf)
        self._capture_split(result)
        return bytes(buf)

    def read_handshake(self, message: bytes) -> bytes:
        buf = bytearray()
        result = self._hs.read_message(bytes(message), buf)
        self._capture_split(result)
        return bytes(buf)

    def _capture_split(self, result) -> None:
        # dissononce returns a (CipherState, CipherState) tuple on the final
        # handshake message; order is (initiator_send, responder_send).
        if result is not None:
            cs_i, cs_r = result
            if self._initiator:
                self._send_cs, self._recv_cs = cs_i, cs_r
            else:
                self._send_cs, self._recv_cs = cs_r, cs_i
            rs = self._hs.rs
            if rs is not None:
                self._peer_static_pub = rs.data

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.handshake_complete:
            raise RuntimeError("handshake not complete")
        return self._send_cs.encrypt_with_ad(b"", plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.handshake_complete:
            raise RuntimeError("handshake not complete")
        return self._recv_cs.decrypt_with_ad(b"", ciphertext)
