# SK Mesh Protocol (SMP) — P1 Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the hardware-free Python core of the BLE mesh transport — packet codec, gossip relay, Noise_XX sessions, identity binding, and an in-memory `FakeRadio` that proves multi-hop messaging end-to-end with zero Bluetooth.

**Architecture:** A new `src/skcomms/transports/ble/` package. Pure-logic modules (`protocol`, `relay`, `noise`, `identity`, `gatt`) compose into a `MeshNode` that drives a `Radio` abstraction. `FakeRadio` implements `Radio` as an in-memory bus with a who-can-hear-whom topology, so the entire mesh (relay, TTL, dedup, fragmentation, encryption) is testable in CI. The real `bleak` driver is P2 and implements the same `Radio` interface.

**Tech Stack:** Python 3.10+, `cryptography` (already a dep: X25519, Ed25519, ChaCha20Poly1305, SHA-256), `dissononce` (pure-Python Noise_XX), `pytest` + `pytest-asyncio` (`asyncio_mode=auto`). Line length 99, ruff (E,W,F,I; ignore E501).

**Spec:** `docs/superpowers/specs/2026-06-13-ble-mesh-proximity-transport-design.md` (§3 layers, §4 wire format, §5 identity, §8 testing).

**Conventions to follow:**
- Tests are flat files `tests/test_ble_<module>.py`.
- Run tests from `~` is NOT required for skcomms (that's a skchat-only namespace quirk); run from repo root: `~/.skenv/bin/python -m pytest tests/ -q`.
- All new modules live under `src/skcomms/transports/ble/`.

---

## Task 0: Package skeleton + dependency

**Files:**
- Create: `src/skcomms/transports/ble/__init__.py`
- Modify: `pyproject.toml` (add `dissononce` to the core dependencies list)

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, find the core `dependencies = [` list (the one containing `"cryptography>=42.0,<44.0",` around line 58) and add this line to it:

```toml
    "dissononce>=0.34.3",
```

- [ ] **Step 2: Create the package init**

Create `src/skcomms/transports/ble/__init__.py`:

```python
"""SK Mesh Protocol (SMP) — sovereign BLE proximity transport.

Bitchat-inspired, SK-native: TTL gossip mesh, Noise_XX sessions, capauth/fqid
identity. This package is the hardware-free core (P1); the bleak radio driver is
P2. See docs/superpowers/specs/2026-06-13-ble-mesh-proximity-transport-design.md.
"""

__all__ = []
```

- [ ] **Step 3: Install the new dep into the venv**

Run: `~/.skenv/bin/pip install dissononce>=0.34.3`
Expected: `Successfully installed dissononce-...` (and its deps `cryptography`, `transitions`).

- [ ] **Step 4: Verify import**

Run: `~/.skenv/bin/python -c "import dissononce; import skcomms.transports.ble; print('ok')"`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/skcomms/transports/ble/__init__.py
git commit -m "feat(ble): scaffold ble package + dissononce dep"
```

---

## Task 1: GATT profile constants

**Files:**
- Create: `src/skcomms/transports/ble/gatt.py`
- Test: `tests/test_ble_gatt.py`

These constants are the single source of truth shared by the Python driver (P2)
and the Flutter driver (P4). They must be stable, well-known UUIDs.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_gatt.py`:

```python
import re
import uuid

from skcomms.transports.ble import gatt

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def test_uuids_are_valid_and_distinct():
    vals = [gatt.SERVICE_UUID, gatt.MESH_CHAR_UUID]
    for v in vals:
        assert _UUID_RE.match(v), f"{v} is not a lowercase canonical UUID"
        uuid.UUID(v)  # parses
    assert len(set(vals)) == len(vals), "UUIDs must be distinct"


def test_protocol_constants():
    assert gatt.PROTOCOL_VERSION == 1
    assert gatt.DEFAULT_TTL == 7
    assert gatt.HEADER_LEN == 30
    assert gatt.PAD_BLOCKS == (256, 512, 1024, 2048)
    assert gatt.BROADCAST_ID == b"\xff" * 8
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_gatt.py -v`
Expected: FAIL with `ModuleNotFoundError` / `AttributeError: module ... has no attribute 'SERVICE_UUID'`.

- [ ] **Step 3: Write the implementation**

Create `src/skcomms/transports/ble/gatt.py`:

```python
"""BLE GATT profile + protocol constants — shared by every SMP radio driver.

These UUIDs identify the SK mesh service/characteristic and MUST stay stable so
Python (bleak), Flutter (flutter_blue_plus), and any future driver interoperate.
"""

# SK-mesh GATT profile (custom 128-bit UUIDs, lowercase canonical form).
SERVICE_UUID = "534b4d45-5348-0000-8000-00805f9b34fb"   # "SKME SH" namespaced
MESH_CHAR_UUID = "534b4d45-5348-0001-8000-00805f9b34fb"  # write + notify

# Protocol constants (see spec §4).
PROTOCOL_VERSION = 1
DEFAULT_TTL = 7
# Fixed header byte layout (see protocol.py): version(1) type(1) ttl(1) flags(1)
# timestamp(8) msg_id(8) sender_id(8) recipient_id(8) payload_len(2) = 38? No:
# 1+1+1+1+8+8+8+8+2 = 38. Keep HEADER_LEN authoritative here.
HEADER_LEN = 30  # version+type+ttl+flags(4) + timestamp(8) + msg_id(8) + payload_len(2) + ids handled separately
PAD_BLOCKS = (256, 512, 1024, 2048)
BROADCAST_ID = b"\xff" * 8
```

> **NOTE for implementer:** `HEADER_LEN` must equal the exact number of bytes the
> `protocol.py` codec writes for the fixed-size header *excluding* the variable
> signature. Task 2 fixes the layout; if your struct differs, update `HEADER_LEN`
> and this test together so they agree. Do **not** leave them inconsistent.

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_gatt.py -v`
Expected: PASS (2 tests). If `test_protocol_constants` fails on `HEADER_LEN`, reconcile with Task 2's actual layout.

- [ ] **Step 5: Commit**

```bash
git add src/skcomms/transports/ble/gatt.py tests/test_ble_gatt.py
git commit -m "feat(ble): GATT profile + protocol constants"
```

---

## Task 2: MeshPacket codec (encode/decode + padding)

**Files:**
- Create: `src/skcomms/transports/ble/protocol.py`
- Test: `tests/test_ble_protocol.py`

Implements the §4 wire format: a fixed header + variable payload + optional
64-byte Ed25519 signature, then PKCS#7 padding to the next `PAD_BLOCKS` size.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_protocol.py`:

```python
import pytest

from skcomms.transports.ble import gatt
from skcomms.transports.ble.protocol import (
    MeshPacket,
    PacketType,
    decode,
    encode,
    pad,
    unpad,
)


def _pkt(**kw):
    base = dict(
        type=PacketType.MESSAGE,
        ttl=7,
        flags=0,
        timestamp=1_700_000_000_000,
        msg_id=b"\x01" * 8,
        sender_id=b"\xaa" * 8,
        recipient_id=b"\xbb" * 8,
        payload=b"hello mesh",
        signature=None,
    )
    base.update(kw)
    return MeshPacket(**base)


def test_roundtrip_unsigned():
    p = _pkt()
    raw = encode(p)
    out = decode(raw)
    assert out == p


def test_roundtrip_signed():
    p = _pkt(flags=0x01, signature=b"\x07" * 64)
    raw = encode(p)
    out = decode(raw)
    assert out == p
    assert out.signature == b"\x07" * 64


def test_broadcast_recipient():
    p = _pkt(recipient_id=gatt.BROADCAST_ID)
    out = decode(encode(p))
    assert out.recipient_id == gatt.BROADCAST_ID
    assert out.is_broadcast()


def test_version_is_stamped():
    raw = encode(_pkt())
    assert raw[0] == gatt.PROTOCOL_VERSION


def test_decode_rejects_wrong_version():
    raw = bytearray(encode(_pkt()))
    raw[0] = 9
    with pytest.raises(ValueError, match="version"):
        decode(bytes(raw))


def test_decode_rejects_truncated():
    raw = encode(_pkt())
    with pytest.raises(ValueError):
        decode(raw[:10])


def test_pad_rounds_to_block_and_unpads():
    for n in (10, 200, 256, 257, 1000):
        body = b"x" * n
        padded = pad(body)
        assert len(padded) in gatt.PAD_BLOCKS or len(padded) > gatt.PAD_BLOCKS[-1]
        assert unpad(padded) == body


def test_signature_flag_without_sig_raises():
    p = _pkt(flags=0x01, signature=None)
    with pytest.raises(ValueError, match="signature"):
        encode(p)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_protocol.py -v`
Expected: FAIL with `ModuleNotFoundError: skcomms.transports.ble.protocol`.

- [ ] **Step 3: Write the implementation**

Create `src/skcomms/transports/ble/protocol.py`:

```python
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
```

> **Reconcile `gatt.HEADER_LEN`:** the real fixed header is `HEADER_SIZE == 38`.
> Update `gatt.py` `HEADER_LEN = 30` → `HEADER_LEN = 38` and the matching assert in
> `tests/test_ble_gatt.py` (`assert gatt.HEADER_LEN == 38`). Make all three agree.

- [ ] **Step 4: Reconcile the header length constant**

Edit `src/skcomms/transports/ble/gatt.py`: change `HEADER_LEN = 30` to `HEADER_LEN = 38` and simplify the comment to `# fixed MeshPacket header size (see protocol.HEADER_SIZE)`.
Edit `tests/test_ble_gatt.py`: change `assert gatt.HEADER_LEN == 30` to `assert gatt.HEADER_LEN == 38`.

- [ ] **Step 5: Run both test files**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_protocol.py tests/test_ble_gatt.py -v`
Expected: PASS (all tests green).

- [ ] **Step 6: Commit**

```bash
git add src/skcomms/transports/ble/protocol.py tests/test_ble_protocol.py \
        src/skcomms/transports/ble/gatt.py tests/test_ble_gatt.py
git commit -m "feat(ble): MeshPacket codec + PKCS#7 padding"
```

---

## Task 3: Fragmentation (split >MTU, reassemble)

**Files:**
- Modify: `src/skcomms/transports/ble/protocol.py` (add `fragment` / `Reassembler`)
- Test: `tests/test_ble_fragment.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_fragment.py`:

```python
from skcomms.transports.ble.protocol import (
    MeshPacket,
    PacketType,
    Reassembler,
    decode,
    encode,
    fragment,
)


def _msg(payload):
    return MeshPacket(
        type=PacketType.MESSAGE, ttl=7, flags=0, timestamp=1,
        msg_id=b"\x09" * 8, sender_id=b"\xaa" * 8, recipient_id=b"\xbb" * 8,
        payload=payload,
    )


def test_small_payload_single_fragment():
    frags = fragment(_msg(b"tiny"), mtu=512)
    assert len(frags) == 1
    assert decode(frags[0]).type == PacketType.MESSAGE


def test_large_payload_splits_and_reassembles():
    original = bytes(range(256)) * 8  # 2048 bytes
    frags = fragment(_msg(original), mtu=185)
    assert len(frags) > 1
    types = [decode(f).type for f in frags]
    assert types[0] == PacketType.FRAGMENT_START
    assert types[-1] == PacketType.FRAGMENT_END
    assert all(t == PacketType.FRAGMENT_CONTINUE for t in types[1:-1])

    r = Reassembler()
    out = None
    for f in frags:
        out = r.feed(decode(f))
    assert out is not None
    assert out.payload == original
    assert out.type == PacketType.MESSAGE


def test_reassembler_ignores_unrelated_fragment_ids():
    r = Reassembler()
    big = fragment(_msg(b"y" * 1000), mtu=185)
    # feed all but last → no output yet
    last = None
    for f in big[:-1]:
        last = r.feed(decode(f))
    assert last is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_fragment.py -v`
Expected: FAIL with `ImportError: cannot import name 'fragment'`.

- [ ] **Step 3: Add the implementation to `protocol.py`**

Append to `src/skcomms/transports/ble/protocol.py`:

```python
# --- Fragmentation -----------------------------------------------------------

def fragment(p: MeshPacket, *, mtu: int) -> list[bytes]:
    """Encode `p`; if it fits in `mtu`, return [bytes]. Otherwise split the
    encoded packet into FRAGMENT_* packets sharing the original msg_id.

    Fragment payload = 2-byte index + 2-byte total + chunk. The original packet
    type is recovered by the Reassembler from the reassembled bytes.
    """
    whole = encode(p)
    if len(whole) <= mtu:
        return [whole]

    # room for our own header + 4 bytes of fragment metadata
    chunk_room = mtu - HEADER_SIZE - 4
    if chunk_room <= 0:
        raise ValueError("mtu too small to fragment")
    chunks = [whole[i:i + chunk_room] for i in range(0, len(whole), chunk_room)]
    total = len(chunks)
    out: list[bytes] = []
    for idx, chunk in enumerate(chunks):
        if idx == 0:
            ftype = PacketType.FRAGMENT_START
        elif idx == total - 1:
            ftype = PacketType.FRAGMENT_END
        else:
            ftype = PacketType.FRAGMENT_CONTINUE
        meta = struct.pack(">HH", idx, total) + chunk
        frag = MeshPacket(
            type=ftype, ttl=p.ttl, flags=FLAG_FRAGMENTED, timestamp=p.timestamp,
            msg_id=p.msg_id, sender_id=p.sender_id, recipient_id=p.recipient_id,
            payload=meta,
        )
        out.append(encode(frag))
    return out


class Reassembler:
    """Collects FRAGMENT_* packets keyed by msg_id and returns the original
    MeshPacket once all fragments for a msg_id have arrived."""

    def __init__(self) -> None:
        self._buf: dict[bytes, dict[int, bytes]] = {}
        self._totals: dict[bytes, int] = {}

    def feed(self, frag: MeshPacket) -> MeshPacket | None:
        if not (frag.flags & FLAG_FRAGMENTED):
            return frag  # not a fragment; pass through
        idx, total = struct.unpack(">HH", frag.payload[:4])
        chunk = frag.payload[4:]
        slots = self._buf.setdefault(frag.msg_id, {})
        slots[idx] = chunk
        self._totals[frag.msg_id] = total
        if len(slots) < total:
            return None
        whole = b"".join(slots[i] for i in range(total))
        del self._buf[frag.msg_id]
        del self._totals[frag.msg_id]
        return decode(whole)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_fragment.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/skcomms/transports/ble/protocol.py tests/test_ble_fragment.py
git commit -m "feat(ble): MTU fragmentation + reassembly"
```

---

## Task 4: Relay engine (bloom dedup + TTL)

**Files:**
- Create: `src/skcomms/transports/ble/relay.py`
- Test: `tests/test_ble_relay.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_relay.py`:

```python
from skcomms.transports.ble.protocol import MeshPacket, PacketType
from skcomms.transports.ble.relay import RelayDecision, RelayEngine


def _pkt(ttl=7, msg_id=b"\x01" * 8, recipient=b"\xbb" * 8):
    return MeshPacket(
        type=PacketType.MESSAGE, ttl=ttl, flags=0, timestamp=1,
        msg_id=msg_id, sender_id=b"\xaa" * 8, recipient_id=recipient,
        payload=b"hi",
    )


def test_first_sight_is_relayed_with_decremented_ttl():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    d = eng.consider(_pkt(ttl=7))
    assert d.deliver_local is False  # not addressed to me
    assert d.forward is True
    assert d.packet.ttl == 6


def test_duplicate_is_dropped():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    eng.consider(_pkt(msg_id=b"\x05" * 8))
    d = eng.consider(_pkt(msg_id=b"\x05" * 8))
    assert d.forward is False
    assert d.duplicate is True


def test_ttl_zero_not_forwarded():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    d = eng.consider(_pkt(ttl=1))  # decrements to 0 → no forward
    assert d.forward is False
    assert d.packet.ttl == 0


def test_addressed_to_me_delivers_and_does_not_forward():
    me = b"\xcc" * 8
    eng = RelayEngine(my_id=me)
    d = eng.consider(_pkt(recipient=me))
    assert d.deliver_local is True
    assert d.forward is False


def test_broadcast_delivers_locally_and_forwards():
    eng = RelayEngine(my_id=b"\xcc" * 8)
    d = eng.consider(_pkt(recipient=b"\xff" * 8))
    assert d.deliver_local is True
    assert d.forward is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_relay.py -v`
Expected: FAIL with `ModuleNotFoundError: skcomms.transports.ble.relay`.

- [ ] **Step 3: Write the implementation**

Create `src/skcomms/transports/ble/relay.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_relay.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/skcomms/transports/ble/relay.py tests/test_ble_relay.py
git commit -m "feat(ble): gossip relay engine (bloom dedup + TTL)"
```

---

## Task 5: Identity binding (BLE keypair, fingerprint, id-hash)

**Files:**
- Create: `src/skcomms/transports/ble/identity.py`
- Test: `tests/test_ble_identity.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_identity.py`:

```python
import hashlib

from skcomms.transports.ble.identity import (
    MeshIdentity,
    fingerprint_of,
    id_hash,
)


def test_id_hash_is_first_8_of_sha256_of_fqid():
    fqid = "lumina@chef.skworld"
    expected = hashlib.sha256(fqid.encode()).digest()[:8]
    assert id_hash(fqid) == expected
    assert len(id_hash(fqid)) == 8


def test_generate_yields_distinct_keypairs():
    a = MeshIdentity.generate("a@x.y")
    b = MeshIdentity.generate("b@x.y")
    assert a.noise_static_pub != b.noise_static_pub
    assert a.ed25519_pub != b.ed25519_pub
    assert len(a.noise_static_pub) == 32
    assert len(a.ed25519_pub) == 32


def test_fingerprint_is_sha256_of_noise_static_pub_hex():
    ident = MeshIdentity.generate("z@x.y")
    assert fingerprint_of(ident.noise_static_pub) == \
        hashlib.sha256(ident.noise_static_pub).hexdigest()
    assert ident.fingerprint == fingerprint_of(ident.noise_static_pub)


def test_sign_and_verify_roundtrip():
    ident = MeshIdentity.generate("s@x.y")
    msg = b"announce-me"
    sig = ident.sign(msg)
    assert len(sig) == 64
    assert MeshIdentity.verify(ident.ed25519_pub, msg, sig) is True
    assert MeshIdentity.verify(ident.ed25519_pub, b"tampered", sig) is False


def test_my_id_matches_id_hash():
    ident = MeshIdentity.generate("me@x.y")
    assert ident.my_id == id_hash("me@x.y")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_identity.py -v`
Expected: FAIL with `ModuleNotFoundError: skcomms.transports.ble.identity`.

- [ ] **Step 3: Write the implementation**

Create `src/skcomms/transports/ble/identity.py`:

```python
"""Bind a capauth/fqid identity to its BLE mesh keypair (spec §5).

- Ed25519 signing key  → signs ANNOUNCE/packets.
- X25519 (Curve25519) static key → Noise_XX static identity.
- fingerprint = SHA-256(noise static pubkey).hex  (TOFU id, matches pairing.py).
- id_hash(fqid) = SHA-256(fqid)[:8]  (the 8-byte wire sender/recipient id).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


def id_hash(fqid: str) -> bytes:
    return hashlib.sha256(fqid.encode()).digest()[:8]


def fingerprint_of(noise_static_pub: bytes) -> str:
    return hashlib.sha256(noise_static_pub).hexdigest()


def _x_raw_pub(k: X25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _ed_raw_pub(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass
class MeshIdentity:
    fqid: str
    _ed_priv: Ed25519PrivateKey
    _x_priv: X25519PrivateKey

    @classmethod
    def generate(cls, fqid: str) -> "MeshIdentity":
        return cls(fqid=fqid, _ed_priv=Ed25519PrivateKey.generate(),
                   _x_priv=X25519PrivateKey.generate())

    @property
    def ed25519_pub(self) -> bytes:
        return _ed_raw_pub(self._ed_priv)

    @property
    def noise_static_pub(self) -> bytes:
        return _x_raw_pub(self._x_priv)

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.noise_static_pub)

    @property
    def my_id(self) -> bytes:
        return id_hash(self.fqid)

    def noise_static_private_bytes(self) -> bytes:
        return self._x_priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, data: bytes) -> bytes:
        return self._ed_priv.sign(data)

    @staticmethod
    def verify(ed_pub: bytes, data: bytes, sig: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, data)
            return True
        except InvalidSignature:
            return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_identity.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/skcomms/transports/ble/identity.py tests/test_ble_identity.py
git commit -m "feat(ble): mesh identity (Ed25519 sign + X25519 noise static + fingerprint)"
```

---

## Task 6: Noise_XX session

**Files:**
- Create: `src/skcomms/transports/ble/noise.py`
- Test: `tests/test_ble_noise.py`

Wrap `dissononce` to give a clean two-method session: drive the XX handshake to
completion, then encrypt/decrypt transport messages.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_noise.py`:

```python
from skcomms.transports.ble.identity import MeshIdentity
from skcomms.transports.ble.noise import NoiseSession


def _drive_handshake(initiator: NoiseSession, responder: NoiseSession):
    """XX is a 3-message handshake: i->r, r->i, i->r."""
    m1 = initiator.write_handshake()       # -> e
    responder.read_handshake(m1)
    m2 = responder.write_handshake()       # -> e, ee, s, es
    initiator.read_handshake(m2)
    m3 = initiator.write_handshake()       # -> s, se
    responder.read_handshake(m3)
    assert initiator.handshake_complete
    assert responder.handshake_complete


def test_xx_handshake_then_encrypted_roundtrip():
    a_id = MeshIdentity.generate("a@x.y")
    b_id = MeshIdentity.generate("b@x.y")
    a = NoiseSession.initiator(a_id.noise_static_private_bytes())
    b = NoiseSession.responder(b_id.noise_static_private_bytes())

    _drive_handshake(a, b)

    ct = a.encrypt(b"secret over ble")
    assert ct != b"secret over ble"
    assert b.decrypt(ct) == b"secret over ble"

    # reverse direction
    ct2 = b.encrypt(b"reply")
    assert a.decrypt(ct2) == b"reply"


def test_peer_static_key_is_learned_after_handshake():
    a_id = MeshIdentity.generate("a@x.y")
    b_id = MeshIdentity.generate("b@x.y")
    a = NoiseSession.initiator(a_id.noise_static_private_bytes())
    b = NoiseSession.responder(b_id.noise_static_private_bytes())
    _drive_handshake(a, b)
    # initiator learns responder's static pubkey (XX authenticates both)
    assert a.peer_static_pub == b_id.noise_static_pub
    assert b.peer_static_pub == a_id.noise_static_pub
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_noise.py -v`
Expected: FAIL with `ModuleNotFoundError: skcomms.transports.ble.noise`.

- [ ] **Step 3: Write the implementation**

Create `src/skcomms/transports/ble/noise.py`:

```python
"""Noise_XX_25519_ChaChaPoly_SHA256 session (spec §2, §3).

Thin wrapper over dissononce that exposes a minimal state machine:
    write_handshake() / read_handshake()  until handshake_complete,
    then encrypt() / decrypt() for transport messages.

XX gives mutual authentication: after the 3-message handshake each side knows the
other's static public key (used to bind to a fqid/fingerprint upstream).
"""

from __future__ import annotations

from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.dh.x25519.private import PrivateKey
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState


def _new_handshake_state(static_priv_bytes: bytes) -> HandshakeState:
    return HandshakeState(
        SymmetricState(CipherState(ChaChaPolyCipher()), SHA256Hash()),
        X25519DH(),
    ), PrivateKey(static_priv_bytes)


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
```

> **NOTE for implementer:** `dissononce`'s exact return type for the final
> `write_message`/`read_message` is the split cipher-state pair, and the peer
> static is exposed as `self._hs.rs` (a `PublicKey` whose `.data` is the 32 raw
> bytes). If the installed dissononce version names these differently, adapt the
> two access points (`result` unpacking and `self._hs.rs.data`) — the test pins
> the required external behavior (handshake completes, both learn peer static,
> bidirectional encrypt/decrypt works). Do not change the test to match a broken
> impl; make the wrapper satisfy the test.

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_noise.py -v`
Expected: PASS (2 tests). If a dissononce API mismatch appears, adapt the two documented access points until green.

- [ ] **Step 5: Commit**

```bash
git add src/skcomms/transports/ble/noise.py tests/test_ble_noise.py
git commit -m "feat(ble): Noise_XX session wrapper (dissononce)"
```

---

## Task 7: Radio interface + FakeRadio in-memory bus

**Files:**
- Create: `src/skcomms/transports/ble/radio.py`
- Test: `tests/test_ble_radio.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_radio.py`:

```python
import asyncio

import pytest

from skcomms.transports.ble.radio import FakeMedium, FakeRadio


@pytest.mark.asyncio
async def test_direct_neighbors_receive_broadcast():
    medium = FakeMedium()
    a = FakeRadio("a", medium)
    b = FakeRadio("b", medium)
    medium.link("a", "b")  # a and b can hear each other

    got: list[bytes] = []
    b.on_receive(lambda data, src: got.append(data))
    await a.start()
    await b.start()

    await a.broadcast(b"ping")
    await asyncio.sleep(0.01)
    assert got == [b"ping"]


@pytest.mark.asyncio
async def test_non_neighbors_do_not_hear_directly():
    medium = FakeMedium()
    a = FakeRadio("a", medium)
    c = FakeRadio("c", medium)
    # no link between a and c
    got: list[bytes] = []
    c.on_receive(lambda data, src: got.append(data))
    await a.start()
    await c.start()
    await a.broadcast(b"ping")
    await asyncio.sleep(0.01)
    assert got == []


@pytest.mark.asyncio
async def test_source_id_is_passed_to_callback():
    medium = FakeMedium()
    a = FakeRadio("a", medium)
    b = FakeRadio("b", medium)
    medium.link("a", "b")
    seen = []
    b.on_receive(lambda data, src: seen.append(src))
    await a.start()
    await b.start()
    await a.broadcast(b"x")
    await asyncio.sleep(0.01)
    assert seen == ["a"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_radio.py -v`
Expected: FAIL with `ModuleNotFoundError: skcomms.transports.ble.radio`.

- [ ] **Step 3: Write the implementation**

Create `src/skcomms/transports/ble/radio.py`:

```python
"""Radio abstraction + FakeRadio in-memory bus (spec §8).

`Radio` is the seam every driver implements: P1 ships FakeRadio (no hardware);
P2 adds BleakRadio (real BLE) implementing the same interface. A MeshNode talks
only to `Radio`, so all mesh logic is tested through FakeRadio in CI.

`FakeMedium` models a who-can-hear-whom topology: only linked radios deliver each
other's broadcasts (one BLE hop). Multi-hop emerges from MeshNodes relaying.
"""

from __future__ import annotations

import asyncio
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_radio.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/skcomms/transports/ble/radio.py tests/test_ble_radio.py
git commit -m "feat(ble): Radio interface + FakeRadio in-memory bus"
```

---

## Task 8: MeshNode + multi-hop integration test

**Files:**
- Create: `src/skcomms/transports/ble/node.py`
- Test: `tests/test_ble_mesh.py`

Ties packet + relay + identity over a `Radio`. The headline proof: a 3-node line
topology (A—B—C, A and C NOT linked) delivers A→C **only by B relaying** it.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_mesh.py`:

```python
import asyncio

import pytest

from skcomms.transports.ble.identity import MeshIdentity, id_hash
from skcomms.transports.ble.node import MeshNode
from skcomms.transports.ble.radio import FakeMedium, FakeRadio


def _node(fqid, medium):
    ident = MeshIdentity.generate(fqid)
    radio = FakeRadio(fqid, medium)
    return MeshNode(identity=ident, radio=radio)


@pytest.mark.asyncio
async def test_three_hop_line_relays_through_middle():
    medium = FakeMedium()
    a = _node("a@x.y", medium)
    b = _node("b@x.y", medium)
    c = _node("c@x.y", medium)
    medium.link("a@x.y", "b@x.y")
    medium.link("b@x.y", "c@x.y")  # A—B—C ; A and C are NOT linked

    inbox: list[bytes] = []
    c.on_message(lambda pkt: inbox.append(pkt.payload))
    for n in (a, b, c):
        await n.start()

    await a.send_broadcast(b"relayed-hello")
    await asyncio.sleep(0.05)

    assert b"relayed-hello" in inbox  # reached C only via B


@pytest.mark.asyncio
async def test_duplicate_does_not_loop_forever():
    medium = FakeMedium()
    a = _node("a@x.y", medium)
    b = _node("b@x.y", medium)
    c = _node("c@x.y", medium)
    # triangle: every node hears every other → without dedup this would storm
    medium.link("a@x.y", "b@x.y")
    medium.link("b@x.y", "c@x.y")
    medium.link("a@x.y", "c@x.y")

    counts: list[int] = []
    c.on_message(lambda pkt: counts.append(1))
    for n in (a, b, c):
        await n.start()

    await a.send_broadcast(b"once")
    await asyncio.sleep(0.05)
    assert sum(counts) == 1  # delivered exactly once despite the loop


@pytest.mark.asyncio
async def test_directed_message_only_delivers_to_recipient():
    medium = FakeMedium()
    a = _node("a@x.y", medium)
    b = _node("b@x.y", medium)
    c = _node("c@x.y", medium)
    medium.link("a@x.y", "b@x.y")
    medium.link("b@x.y", "c@x.y")

    b_inbox, c_inbox = [], []
    b.on_message(lambda pkt: b_inbox.append(pkt.payload))
    c.on_message(lambda pkt: c_inbox.append(pkt.payload))
    for n in (a, b, c):
        await n.start()

    await a.send_to(id_hash("c@x.y"), b"for-c-only")
    await asyncio.sleep(0.05)
    assert c_inbox == [b"for-c-only"]
    assert b_inbox == []  # B relays but does not deliver locally
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_mesh.py -v`
Expected: FAIL with `ModuleNotFoundError: skcomms.transports.ble.node`.

- [ ] **Step 3: Write the implementation**

Create `src/skcomms/transports/ble/node.py`:

```python
"""MeshNode — wires packet + relay + identity over a Radio (spec §3).

This is the orchestrator the FakeRadio tests drive to prove multi-hop delivery.
It deliberately does NOT do Noise encryption yet for broadcast traffic (broadcast
is signed-plaintext per spec §3); directed-message encryption rides on the Noise
session work and is exercised at the transport layer in P3. P1 proves routing.
"""

from __future__ import annotations

import os
from typing import Callable

from skcomms.transports.ble import gatt
from skcomms.transports.ble.identity import MeshIdentity
from skcomms.transports.ble.protocol import (
    MeshPacket,
    PacketType,
    decode,
    encode,
)
from skcomms.transports.ble.radio import Radio
from skcomms.transports.ble.relay import RelayEngine

MessageCb = Callable[[MeshPacket], None]


class MeshNode:
    def __init__(self, *, identity: MeshIdentity, radio: Radio) -> None:
        self.identity = identity
        self.radio = radio
        self.relay = RelayEngine(my_id=identity.my_id)
        self._on_message: MessageCb | None = None
        radio.on_receive(self._handle_frame)

    def on_message(self, cb: MessageCb) -> None:
        self._on_message = cb

    async def start(self) -> None:
        await self.radio.start()

    async def stop(self) -> None:
        await self.radio.stop()

    def _new_packet(self, recipient_id: bytes, payload: bytes,
                    ptype: PacketType = PacketType.MESSAGE) -> MeshPacket:
        return MeshPacket(
            type=ptype, ttl=gatt.DEFAULT_TTL, flags=0, timestamp=0,
            msg_id=os.urandom(8), sender_id=self.identity.my_id,
            recipient_id=recipient_id, payload=payload,
        )

    async def send_broadcast(self, payload: bytes) -> None:
        pkt = self._new_packet(gatt.BROADCAST_ID, payload)
        self.relay.consider(pkt)  # mark our own msg_id as seen (no self-loop)
        await self.radio.broadcast(encode(pkt))

    async def send_to(self, recipient_id: bytes, payload: bytes) -> None:
        pkt = self._new_packet(recipient_id, payload)
        self.relay.consider(pkt)
        await self.radio.broadcast(encode(pkt))

    def _handle_frame(self, data: bytes, src: str) -> None:
        try:
            pkt = decode(data)
        except ValueError:
            return
        decision = self.relay.consider(pkt)
        if decision.duplicate:
            return
        if decision.deliver_local and pkt.sender_id != self.identity.my_id:
            if self._on_message is not None:
                self._on_message(pkt)
        if decision.forward:
            # schedule rebroadcast of the TTL-decremented packet
            import asyncio
            asyncio.create_task(self.radio.broadcast(encode(decision.packet)))
```

> **NOTE for implementer:** `send_broadcast`/`send_to` call `relay.consider` on
> the outgoing packet so the node's own `msg_id` is in the bloom filter before the
> frame can echo back — preventing self-delivery and self-relay. The inbound path
> guards delivery with `pkt.sender_id != my_id` as a second belt. The
> `asyncio.create_task` rebroadcast is fire-and-forget; in the FakeMedium this
> resolves synchronously enough for the `await asyncio.sleep(0.05)` settle window.

- [ ] **Step 4: Run test to verify it passes**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_mesh.py -v`
Expected: PASS (3 tests) — multi-hop relay, loop-suppression, and directed delivery all green.

- [ ] **Step 5: Run the whole BLE suite**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_*.py -v`
Expected: PASS (all BLE tests across Tasks 1–8).

- [ ] **Step 6: Commit**

```bash
git add src/skcomms/transports/ble/node.py tests/test_ble_mesh.py
git commit -m "feat(ble): MeshNode + multi-hop FakeRadio integration tests"
```

---

## Task 9: Extend PairingBundle with the Noise static key

**Files:**
- Modify: `src/skcomms/transports/ble/__init__.py` (export nothing new — n/a)
- Modify: `src/skcomms/pairing.py:22-90` (add field + URI param)
- Test: `tests/test_ble_pairing_bundle.py`

This is what makes "scan QR → chat over BLE" work: the pairing bundle must carry
the peer's Noise static pubkey so a session can be opened.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ble_pairing_bundle.py`:

```python
import base64

from skcomms.pairing import PairingBundle, parse_skp_uri, to_skp_uri


def test_bundle_carries_noise_static_pubkey_through_uri():
    raw_pub = bytes(range(32))
    b = PairingBundle(
        fqid="lumina@chef.skworld",
        fingerprint="a" * 64,
        noise_static_pubkey=base64.urlsafe_b64encode(raw_pub).decode(),
    )
    uri = to_skp_uri(b)
    assert "ns=" in uri
    out = parse_skp_uri(uri)
    assert out.noise_static_pubkey == base64.urlsafe_b64encode(raw_pub).decode()


def test_bundle_without_noise_key_still_parses():
    b = PairingBundle(fqid="x@y.z", fingerprint="b" * 64)
    out = parse_skp_uri(to_skp_uri(b))
    assert out.noise_static_pubkey is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_pairing_bundle.py -v`
Expected: FAIL with `pydantic ... unexpected keyword argument 'noise_static_pubkey'` (or AttributeError).

- [ ] **Step 3: Add the field to `PairingBundle`**

In `src/skcomms/pairing.py`, add to the `PairingBundle` class body (after the `pubkey` field):

```python
    noise_static_pubkey: Optional[str] = None  # urlsafe-b64 of 32-byte X25519 pub (SMP/BLE)
```

- [ ] **Step 4: Add the URI param in `to_skp_uri`**

In `to_skp_uri`, before the final `return`, add:

```python
    if b.noise_static_pubkey:
        params["ns"] = b.noise_static_pubkey
```

- [ ] **Step 5: Parse the URI param in `parse_skp_uri`**

In `parse_skp_uri`, change the `PairingBundle(...)` construction to also pass:

```python
                         noise_static_pubkey=q.get("ns"),
```

(Add it alongside the existing `https=q.get("https")` argument.)

- [ ] **Step 6: Run the test + the existing pairing tests**

Run: `~/.skenv/bin/python -m pytest tests/test_ble_pairing_bundle.py tests/test_pairing.py -v`
Expected: PASS (new tests green; existing pairing tests still green — no regression).

- [ ] **Step 7: Commit**

```bash
git add src/skcomms/pairing.py tests/test_ble_pairing_bundle.py
git commit -m "feat(ble): carry Noise static pubkey in skp:// pairing bundle"
```

---

## Final verification

- [ ] **Run the full skcomms suite to confirm no regressions**

Run: `~/.skenv/bin/python -m pytest tests/ -q`
Expected: all tests pass (the ~376 existing + the new BLE tests). If any pre-existing
test was already failing before this work, note it but do not block on it.

- [ ] **Lint the new package**

Run: `~/.skenv/bin/ruff check src/skcomms/transports/ble/ tests/test_ble_*.py`
Expected: no errors (E,W,F,I; E501 ignored per project config).

---

## What P1 delivers

The hardware-free SMP core: a packet codec, fragmentation, a TTL+bloom gossip
relay, Ed25519/X25519 identity bound to fqid, a Noise_XX session, and a
FakeRadio-driven `MeshNode` that **provably relays a message A→C through B with no
direct link** — the multi-hop "peer hopping" Chef asked for — all in CI with zero
Bluetooth. P2 swaps `FakeRadio` for `bleak` on real hardware; the protocol and
mesh logic proven here do not change.
```
