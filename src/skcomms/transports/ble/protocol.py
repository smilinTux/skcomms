"""MeshPacket binary codec (spec §4).

Header layout (big-endian), fixed 38 bytes, then payload, then optional 64-byte
Ed25519 signature:

    version       1   uint8   (== gatt.PROTOCOL_VERSION)
    type          1   uint8   (PacketType)
    ttl           1   uint8
    flags         1   uint8   bit0=has-signature bit1=fragmented bit2=encrypted
    timestamp     8   uint64  ms since epoch (sender clock)
    msg_id        8   bytes   dedup key
    sender_id     8   bytes   first 8 of SHA-256(sender fqid)
    recipient_id  8   bytes   first 8 of SHA-256(recipient fqid); FF*8=broadcast
    payload_len   2   uint16
    --- payload (payload_len bytes) ---
    --- signature (64 bytes) iff flags bit0 ---
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from skcomms.transports.ble import gatt

_HEADER = struct.Struct(">BBBBQ8s8s8sH")  # 1+1+1+1+8+8+8+8+2 = 38 bytes
HEADER_SIZE = _HEADER.size  # 38

FLAG_SIGNED = 0x01
FLAG_FRAGMENTED = 0x02
FLAG_ENCRYPTED = 0x04


class PacketType(IntEnum):
    ANNOUNCE = 1
    MESSAGE = 2
    ACK = 3
    FRAGMENT_START = 4
    FRAGMENT_CONTINUE = 5
    FRAGMENT_END = 6
    NOISE_HANDSHAKE = 7
    LEAVE = 8


@dataclass(eq=True)
class MeshPacket:
    type: PacketType
    ttl: int
    flags: int
    timestamp: int
    msg_id: bytes        # 8 bytes
    sender_id: bytes     # 8 bytes
    recipient_id: bytes  # 8 bytes
    payload: bytes
    signature: bytes | None = None  # 64 bytes when FLAG_SIGNED

    def is_broadcast(self) -> bool:
        return self.recipient_id == gatt.BROADCAST_ID


def encode(p: MeshPacket) -> bytes:
    if p.flags & FLAG_SIGNED and not p.signature:
        raise ValueError("FLAG_SIGNED set but signature is missing")
    if p.signature is not None and len(p.signature) != 64:
        raise ValueError("signature must be 64 bytes")
    for name, val in (("msg_id", p.msg_id), ("sender_id", p.sender_id),
                      ("recipient_id", p.recipient_id)):
        if len(val) != 8:
            raise ValueError(f"{name} must be 8 bytes")
    head = _HEADER.pack(
        gatt.PROTOCOL_VERSION, int(p.type), p.ttl & 0xFF, p.flags & 0xFF,
        p.timestamp, p.msg_id, p.sender_id, p.recipient_id, len(p.payload),
    )
    body = head + p.payload
    if p.flags & FLAG_SIGNED:
        body += p.signature
    return body


def decode(raw: bytes) -> MeshPacket:
    if len(raw) < HEADER_SIZE:
        raise ValueError("packet shorter than header")
    (ver, typ, ttl, flags, ts, msg_id, sender_id, recipient_id,
     plen) = _HEADER.unpack(raw[:HEADER_SIZE])
    if ver != gatt.PROTOCOL_VERSION:
        raise ValueError(f"unsupported protocol version {ver}")
    off = HEADER_SIZE
    payload = raw[off:off + plen]
    if len(payload) != plen:
        raise ValueError("payload truncated")
    off += plen
    sig = None
    if flags & FLAG_SIGNED:
        sig = raw[off:off + 64]
        if len(sig) != 64:
            raise ValueError("signature truncated")
    return MeshPacket(
        type=PacketType(typ), ttl=ttl, flags=flags, timestamp=ts,
        msg_id=msg_id, sender_id=sender_id, recipient_id=recipient_id,
        payload=payload, signature=sig,
    )


def pad(body: bytes) -> bytes:
    """PKCS#7-pad to the next gatt.PAD_BLOCKS size (spec §4).

    If body+1 exceeds the largest block, pad to a multiple of the largest block.
    PKCS#7 pad value is the count of pad bytes; count is encoded modulo 256 with a
    leading 2-byte big-endian true-length prefix so unpad is unambiguous for large
    bodies.
    """
    target = None
    need = len(body) + 2  # 2-byte length prefix
    for blk in gatt.PAD_BLOCKS:
        if need <= blk:
            target = blk
            break
    if target is None:
        last = gatt.PAD_BLOCKS[-1]
        target = ((need + last - 1) // last) * last
    prefixed = struct.pack(">H", len(body)) + body
    padlen = target - len(prefixed)
    return prefixed + bytes([padlen & 0xFF]) * padlen


def unpad(padded: bytes) -> bytes:
    if len(padded) < 2:
        raise ValueError("padded data too short")
    (true_len,) = struct.unpack(">H", padded[:2])
    body = padded[2:2 + true_len]
    if len(body) != true_len:
        raise ValueError("padded length prefix exceeds data")
    return body
