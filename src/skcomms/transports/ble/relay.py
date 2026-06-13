"""Gossip relay engine (spec §3): bloom-filter dedup + TTL-bounded flooding.

Pure decision logic — no I/O. The MeshNode performs the actual rebroadcast based
on the RelayDecision returned by `consider`.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from skcomms.transports.ble import gatt
from skcomms.transports.ble.protocol import MeshPacket


@dataclass
class RelayDecision:
    packet: MeshPacket      # possibly TTL-decremented copy
    deliver_local: bool     # addressed to me or broadcast → hand up the stack
    forward: bool           # rebroadcast to other peers
    duplicate: bool = False


class _BloomFilter:
    """Tiny counting-free bloom filter for msg_id dedup. Fixed size, k hashes.

    False positives are acceptable per spec §4 (redundant gossip ensures eventual
    delivery); false negatives never happen for already-seen ids until reset.
    """

    def __init__(self, size_bits: int = 1 << 16, k: int = 4) -> None:
        self._size = size_bits
        self._k = k
        self._bits = bytearray(size_bits // 8)

    def _hashes(self, item: bytes):
        for i in range(self._k):
            h = hash((item, i)) % self._size
            yield h

    def add(self, item: bytes) -> None:
        for h in self._hashes(item):
            self._bits[h >> 3] |= 1 << (h & 7)

    def __contains__(self, item: bytes) -> bool:
        return all(self._bits[h >> 3] & (1 << (h & 7)) for h in self._hashes(item))


class RelayEngine:
    def __init__(self, my_id: bytes, *, bloom: _BloomFilter | None = None) -> None:
        self.my_id = my_id
        self._seen = bloom or _BloomFilter()

    def consider(self, pkt: MeshPacket) -> RelayDecision:
        if pkt.msg_id in self._seen:
            return RelayDecision(packet=pkt, deliver_local=False,
                                 forward=False, duplicate=True)
        self._seen.add(pkt.msg_id)

        for_me = pkt.recipient_id == self.my_id
        broadcast = pkt.recipient_id == gatt.BROADCAST_ID
        deliver_local = for_me or broadcast

        new_ttl = max(0, pkt.ttl - 1)
        decremented = replace(pkt, ttl=new_ttl)
        # Forward if there is hop budget left and it is not addressed solely to me.
        forward = new_ttl > 0 and not for_me
        return RelayDecision(packet=decremented, deliver_local=deliver_local,
                             forward=forward)
