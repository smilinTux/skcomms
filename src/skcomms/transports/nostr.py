"""
Nostr transport — NIP-17 encrypted DMs over Nostr relays.

Uses NIP-59 gift wrapping for metadata protection. SKComms
envelopes are base64-encoded, encrypted with NIP-44 v2,
sealed (kind 13), and gift-wrapped (kind 1059) before
being published to relay servers.

Recipients poll relays for gift-wrapped events, unwrap to
recover the original SKComms envelope bytes.

Crypto stack:
    BIP-340 Schnorr signatures (secp256k1 via cryptography)
    NIP-44 v2: ECDH + HKDF-SHA256 + ChaCha20 + HMAC-SHA256
    NIP-17: kind 14 private DMs
    NIP-59: kind 13 seal + kind 1059 gift wrap
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import logging
import math
import os
import secrets
import struct
import time

from ..transport import (
    HealthStatus,
    SendResult,
    Transport,
    TransportCategory,
    TransportStatus,
)

logger = logging.getLogger("skcomms.transports.nostr")

_MISSING: list[str] = []

try:
    from websockets.sync.client import connect as _ws_connect
except ImportError:
    _ws_connect = None  # type: ignore[assignment]
    _MISSING.append("websockets>=12.0")

try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
except ImportError:
    _ec = None  # type: ignore[assignment]
    _Cipher = None  # type: ignore[assignment]
    _algorithms = None  # type: ignore[assignment]
    _MISSING.append("cryptography>=42.0")

NOSTR_AVAILABLE = len(_MISSING) == 0

DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]

# secp256k1 curve constants
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

KIND_DM = 14
KIND_SEAL = 13
KIND_GIFT_WRAP = 1059


# ---------------------------------------------------------------------------
# secp256k1 helpers (via cryptography)
# ---------------------------------------------------------------------------


def _int_from_bytes(b: bytes) -> int:
    """Interpret big-endian bytes as an unsigned integer."""
    return int.from_bytes(b, "big")


def _bytes_from_int(x: int) -> bytes:
    """Encode an integer as 32 big-endian bytes."""
    return x.to_bytes(32, "big")


def _scalar_to_pubkey(d: int) -> _ec.EllipticCurvePublicKey:
    """Derive a secp256k1 public key from a private scalar."""
    return _ec.derive_private_key(d, _ec.SECP256K1()).public_key()


def _x_only_to_pubkey(x_bytes: bytes) -> _ec.EllipticCurvePublicKey:
    """Recover a full EC public key from an x-only coordinate (even y).

    Args:
        x_bytes: 32-byte x-coordinate.

    Returns:
        EllipticCurvePublicKey with the even-y point.

    Raises:
        ValueError: If x is not a valid point on secp256k1.
    """
    x = _int_from_bytes(x_bytes)
    # Reason: secp256k1 has p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p
    y_sq = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if y % 2 != 0:
        y = SECP256K1_P - y
    return _ec.EllipticCurvePublicNumbers(x=x, y=y, curve=_ec.SECP256K1()).public_key()


def _pubkey_of(secret: bytes) -> tuple[bytes, bool]:
    """Derive x-only pubkey (32 bytes) and y-parity from a secret.

    Args:
        secret: 32-byte secp256k1 secret key.

    Returns:
        Tuple of (x_coordinate_bytes, y_is_even).
    """
    d = _int_from_bytes(secret)
    nums = _scalar_to_pubkey(d).public_numbers()
    return _bytes_from_int(nums.x), nums.y % 2 == 0


# ---------------------------------------------------------------------------
# BIP-340 Schnorr signatures
# ---------------------------------------------------------------------------


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


def _schnorr_sign(secret: bytes, msg: bytes, aux: bytes | None = None) -> bytes:
    """Produce a 64-byte BIP-340 deterministic Schnorr signature.

    Args:
        secret: 32-byte private key.
        msg: 32-byte message hash (typically the Nostr event id).
        aux: 32 random bytes for nonce derivation (random if omitted).

    Returns:
        64-byte Schnorr signature (R.x || s).
    """
    aux = aux or os.urandom(32)
    d_prime = _int_from_bytes(secret)
    x_P, even_y = _pubkey_of(secret)
    d = d_prime if even_y else SECP256K1_ORDER - d_prime

    t = bytes(a ^ b for a, b in zip(_bytes_from_int(d), _tagged_hash("BIP0340/aux", aux)))
    k_prime = _int_from_bytes(_tagged_hash("BIP0340/nonce", t + x_P + msg)) % SECP256K1_ORDER
    if k_prime == 0:
        raise ValueError("Derived nonce is zero")

    R_nums = _scalar_to_pubkey(k_prime).public_numbers()
    x_R = _bytes_from_int(R_nums.x)
    k = k_prime if R_nums.y % 2 == 0 else SECP256K1_ORDER - k_prime

    e = _int_from_bytes(_tagged_hash("BIP0340/challenge", x_R + x_P + msg)) % SECP256K1_ORDER
    return x_R + _bytes_from_int((k + e * d) % SECP256K1_ORDER)


# ---------------------------------------------------------------------------
# Nostr event helpers
# ---------------------------------------------------------------------------


def _make_event(
    pubkey_hex: str,
    kind: int,
    content: str,
    tags: list,
    created_at: int | None = None,
) -> dict:
    """Build a Nostr event dict with a computed id field.

    Args:
        pubkey_hex: 64-char hex x-only public key of the author.
        kind: Nostr event kind number.
        content: Event content string.
        tags: List of tag arrays (e.g. [["p", "<hex>"]]).
        created_at: Unix timestamp (defaults to now).

    Returns:
        Event dict ready for signing.
    """
    created_at = created_at or int(time.time())
    serialized = json.dumps(
        [0, pubkey_hex, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    event_id = hashlib.sha256(serialized.encode()).hexdigest()
    return {
        "id": event_id,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": "",
    }


def _sign_event(event: dict, secret: bytes) -> dict:
    """Sign a Nostr event in-place with a BIP-340 Schnorr signature.

    Args:
        event: Event dict (must have an "id" field).
        secret: 32-byte private key.

    Returns:
        The same event dict with the "sig" field populated.
    """
    event["sig"] = _schnorr_sign(secret, bytes.fromhex(event["id"])).hex()
    return event


# ---------------------------------------------------------------------------
# NIP-44 v2 encryption
# ---------------------------------------------------------------------------


def _ecdh_x(my_secret: bytes, peer_pubkey_x: bytes) -> bytes:
    """ECDH shared-point x-coordinate (32 bytes).

    Args:
        my_secret: Our 32-byte private key.
        peer_pubkey_x: Peer's 32-byte x-only public key.

    Returns:
        32-byte x-coordinate of the shared ECDH point.
    """
    d = _int_from_bytes(my_secret)
    priv = _ec.derive_private_key(d, _ec.SECP256K1())
    peer_pub = _x_only_to_pubkey(peer_pubkey_x)
    return priv.exchange(_ec.ECDH(), peer_pub)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) using SHA-256.

    Args:
        prk: Pseudorandom key (32 bytes from HKDF-Extract).
        info: Context/application info.
        length: Desired output length in bytes.

    Returns:
        Output keying material of the requested length.
    """
    n = math.ceil(length / 32)
    okm, prev = b"", b""
    for i in range(1, n + 1):
        prev = hmac_mod.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        okm += prev
    return okm[:length]


def _nip44_padded_len(unpadded: int) -> int:
    """NIP-44 v2 padding length calculation.

    Args:
        unpadded: Length of the plaintext in bytes.

    Returns:
        Padded length per NIP-44 v2 spec.

    Raises:
        ValueError: If length is out of the valid range [1, 65535].
    """
    if not 1 <= unpadded <= 65535:
        raise ValueError(f"Plaintext length out of range: {unpadded}")
    if unpadded <= 32:
        return 32
    next_pow = 1 << (math.floor(math.log2(unpadded - 1)) + 1)
    chunk = max(32, next_pow // 8)
    return chunk * (math.floor((unpadded - 1) / chunk) + 1)


def _nip44_pad(plaintext: bytes) -> bytes:
    """Apply NIP-44 v2 padding: 2-byte BE length prefix + zero-fill."""
    padded_len = _nip44_padded_len(len(plaintext))
    return struct.pack(">H", len(plaintext)) + plaintext + b"\x00" * (padded_len - len(plaintext))


def _nip44_unpad(padded: bytes) -> bytes:
    """Remove NIP-44 v2 padding and return the original plaintext bytes."""
    msg_len = struct.unpack(">H", padded[:2])[0]
    if msg_len < 1 or 2 + msg_len > len(padded):
        raise ValueError("Invalid NIP-44 padding")
    return padded[2 : 2 + msg_len]


def _chacha20(key: bytes, nonce_12: bytes, data: bytes) -> bytes:
    """ChaCha20 stream cipher encrypt/decrypt (symmetric).

    Args:
        key: 32-byte ChaCha20 key.
        nonce_12: 12-byte nonce.
        data: Plaintext or ciphertext bytes.

    Returns:
        Encrypted or decrypted bytes.
    """
    # Reason: cryptography's ChaCha20 expects 16-byte nonce =
    # 4-byte LE initial counter (0) + 12-byte nonce
    nonce_16 = b"\x00\x00\x00\x00" + nonce_12
    cipher = _Cipher(_algorithms.ChaCha20(key, nonce_16), mode=None)
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def nip44_conversation_key(my_secret: bytes, peer_pubkey_x: bytes) -> bytes:
    """Derive NIP-44 conversation key: HKDF-extract(ECDH_x, "nip44-v2").

    Args:
        my_secret: Our 32-byte private key.
        peer_pubkey_x: Peer's 32-byte x-only public key.

    Returns:
        32-byte conversation key.
    """
    shared_x = _ecdh_x(my_secret, peer_pubkey_x)
    return hmac_mod.new(b"nip44-v2", shared_x, hashlib.sha256).digest()


def nip44_encrypt(conversation_key: bytes, plaintext: str) -> str:
    """NIP-44 v2 encrypt: returns base64 payload string.

    Args:
        conversation_key: 32-byte key from nip44_conversation_key().
        plaintext: UTF-8 string to encrypt.

    Returns:
        Base64-encoded encrypted payload.
    """
    nonce = os.urandom(32)
    keys = _hkdf_expand(conversation_key, nonce, 76)
    ck, cn, hk = keys[:32], keys[32:44], keys[44:]

    padded = _nip44_pad(plaintext.encode("utf-8"))
    ciphertext = _chacha20(ck, cn, padded)
    mac = hmac_mod.new(hk, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ciphertext + mac).decode()


def nip44_decrypt(conversation_key: bytes, payload_b64: str) -> str:
    """NIP-44 v2 decrypt: returns plaintext string.

    Args:
        conversation_key: 32-byte key from nip44_conversation_key().
        payload_b64: Base64-encoded payload from nip44_encrypt().

    Returns:
        Decrypted UTF-8 string.

    Raises:
        ValueError: On version mismatch or HMAC verification failure.
    """
    raw = base64.b64decode(payload_b64)
    if raw[0] != 0x02:
        raise ValueError(f"Unsupported NIP-44 version: {raw[0]}")
    nonce, mac_received, ciphertext = raw[1:33], raw[-32:], raw[33:-32]

    keys = _hkdf_expand(conversation_key, nonce, 76)
    ck, cn, hk = keys[:32], keys[32:44], keys[44:]

    mac_computed = hmac_mod.new(hk, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(mac_received, mac_computed):
        raise ValueError("NIP-44 HMAC verification failed")

    padded = _chacha20(ck, cn, ciphertext)
    return _nip44_unpad(padded).decode("utf-8")


# ---------------------------------------------------------------------------
# NIP-17 / NIP-59 wrapping
# ---------------------------------------------------------------------------


def _random_secret() -> bytes:
    """Generate a valid random secp256k1 secret key."""
    secret = os.urandom(32)
    while _int_from_bytes(secret) == 0 or _int_from_bytes(secret) >= SECP256K1_ORDER:
        secret = os.urandom(32)
    return secret


def wrap_dm(
    sender_secret: bytes,
    sender_pubkey_hex: str,
    recipient_pubkey_hex: str,
    content: str,
) -> dict:
    """Create a NIP-17 DM wrapped in NIP-59 gift wrap.

    Flow: kind 14 (DM) -> kind 13 (seal) -> kind 1059 (gift wrap).

    Args:
        sender_secret: Sender's 32-byte private key.
        sender_pubkey_hex: Sender's 64-char hex x-only pubkey.
        recipient_pubkey_hex: Recipient's 64-char hex x-only pubkey.
        content: DM content string.

    Returns:
        Kind 1059 gift-wrap event dict ready to publish.
    """
    recipient_x = bytes.fromhex(recipient_pubkey_hex)

    dm = _make_event(sender_pubkey_hex, KIND_DM, content, [["p", recipient_pubkey_hex]])
    _sign_event(dm, sender_secret)

    conv_key = nip44_conversation_key(sender_secret, recipient_x)
    sealed_content = nip44_encrypt(conv_key, json.dumps(dm, separators=(",", ":")))
    seal = _make_event(sender_pubkey_hex, KIND_SEAL, sealed_content, [])
    _sign_event(seal, sender_secret)

    eph_secret = _random_secret()
    eph_x, _ = _pubkey_of(eph_secret)
    eph_conv = nip44_conversation_key(eph_secret, recipient_x)
    wrapped = nip44_encrypt(eph_conv, json.dumps(seal, separators=(",", ":")))

    # Reason: NIP-59 randomizes created_at to prevent timing correlation
    random_ts = int(time.time()) - secrets.randbelow(172800)
    gift = _make_event(
        eph_x.hex(), KIND_GIFT_WRAP, wrapped, [["p", recipient_pubkey_hex]], random_ts
    )
    _sign_event(gift, eph_secret)
    return gift


def unwrap_dm(recipient_secret: bytes, gift_event: dict) -> tuple[str, str] | None:
    """Unwrap a NIP-59 gift wrap to extract the NIP-17 DM.

    Args:
        recipient_secret: Recipient's 32-byte private key.
        gift_event: Kind 1059 gift-wrap event dict from a relay.

    Returns:
        Tuple of (sender_pubkey_hex, content) or None on failure.
    """
    try:
        eph_x = bytes.fromhex(gift_event["pubkey"])
        conv_key = nip44_conversation_key(recipient_secret, eph_x)
        seal = json.loads(nip44_decrypt(conv_key, gift_event["content"]))
        if seal.get("kind") != KIND_SEAL:
            return None

        sender_x = bytes.fromhex(seal["pubkey"])
        seal_conv = nip44_conversation_key(recipient_secret, sender_x)
        dm = json.loads(nip44_decrypt(seal_conv, seal["content"]))
        if dm.get("kind") != KIND_DM:
            return None
        return dm["pubkey"], dm["content"]
    except Exception as exc:
        logger.debug("Failed to unwrap gift: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Relay I/O
# ---------------------------------------------------------------------------


def _publish_to_relay(relay_url: str, event: dict, timeout: float = 5.0) -> bool:
    """Publish a Nostr event to a single relay via WebSocket.

    Args:
        relay_url: Relay WebSocket URL (wss://...).
        event: Signed Nostr event dict.
        timeout: Connection and response timeout in seconds.

    Returns:
        True if the relay accepted the event.
    """
    try:
        with _ws_connect(relay_url, open_timeout=timeout, close_timeout=2) as ws:
            ws.send(json.dumps(["EVENT", event]))
            raw = ws.recv(timeout=timeout)
            msg = json.loads(raw)
            return len(msg) >= 3 and msg[0] == "OK" and msg[2] is True
    except Exception as exc:
        logger.debug("Relay %s publish failed: %s", relay_url, exc)
        return False


def _query_relay(relay_url: str, filters: dict, timeout: float = 5.0) -> list[dict]:
    """Query events from a single relay.

    Args:
        relay_url: Relay WebSocket URL.
        filters: Nostr filter dict (kinds, authors, #p, since, etc.).
        timeout: Connection and response timeout in seconds.

    Returns:
        List of matching event dicts.
    """
    sub_id = secrets.token_hex(8)
    events: list[dict] = []
    try:
        with _ws_connect(relay_url, open_timeout=timeout, close_timeout=2) as ws:
            ws.send(json.dumps(["REQ", sub_id, filters]))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = max(0.1, deadline - time.monotonic())
                raw = ws.recv(timeout=remaining)
                msg = json.loads(raw)
                if msg[0] == "EVENT" and msg[1] == sub_id:
                    events.append(msg[2])
                elif msg[0] == "EOSE":
                    break
            ws.send(json.dumps(["CLOSE", sub_id]))
    except Exception as exc:
        logger.debug("Relay %s query failed: %s", relay_url, exc)
    return events


# ---------------------------------------------------------------------------
# Transport class
# ---------------------------------------------------------------------------


class NostrTransport(Transport):
    """NIP-17 encrypted DM transport over Nostr relays.

    Sends SKComms envelopes as gift-wrapped encrypted DMs
    and polls relays for inbound messages. Uses ephemeral
    keys for gift wrapping to hide sender metadata.

    The recipient identifier should be a 64-char hex Nostr
    x-only public key. Map agent names to Nostr pubkeys
    in the SKComms config.

    Attributes:
        name: Always "nostr".
        priority: Default 3 (after syncthing=1, file=2).
        category: STEALTH — encrypted relay transport with metadata hiding.
    """

    name: str = "nostr"
    priority: int = 3
    category: TransportCategory = TransportCategory.STEALTH

    def __init__(
        self,
        private_key_hex: str | None = None,
        relays: list[str] | None = None,
        priority: int = 3,
        relay_timeout: float = 5.0,
        since_window: int = 86400,
        **kwargs,
    ):
        """Initialize the Nostr transport.

        Args:
            private_key_hex: 64-char hex Nostr private key. Generated if omitted.
            relays: List of relay WebSocket URLs.
            priority: Transport priority (lower = higher).
            relay_timeout: Timeout in seconds for relay operations.
            since_window: How far back (seconds) to query for messages.
        """
        self.priority = priority
        self._relays = relays or list(DEFAULT_RELAYS)
        self._timeout = relay_timeout
        self._since_window = since_window
        self._seen_ids: set[str] = set()

        if private_key_hex:
            self._secret = bytes.fromhex(private_key_hex)
        elif NOSTR_AVAILABLE:
            self._secret = _random_secret()
        else:
            self._secret = b""

        if NOSTR_AVAILABLE and self._secret:
            x, _ = _pubkey_of(self._secret)
            self._pubkey_hex = x.hex()
        else:
            self._pubkey_hex = ""

    def configure(self, config: dict) -> None:
        """Load transport-specific configuration.

        Args:
            config: Dict with optional keys: private_key_hex, relays,
                    relay_timeout, since_window.
        """
        if "relays" in config:
            self._relays = config["relays"]
        if "relay_timeout" in config:
            self._timeout = config["relay_timeout"]
        if "since_window" in config:
            self._since_window = config["since_window"]
        if "private_key_hex" in config:
            self._secret = bytes.fromhex(config["private_key_hex"])
            if NOSTR_AVAILABLE:
                x, _ = _pubkey_of(self._secret)
                self._pubkey_hex = x.hex()

    @property
    def pubkey(self) -> str:
        """This transport's Nostr public key (x-only hex, 64 chars)."""
        return self._pubkey_hex

    def is_available(self) -> bool:
        """Check if Nostr dependencies are installed and a key is configured.

        Returns:
            True if all crypto dependencies are present and a valid key exists.
        """
        if not NOSTR_AVAILABLE:
            logger.debug("Nostr unavailable — missing: %s", ", ".join(_MISSING))
            return False
        return bool(self._secret and self._pubkey_hex)

    def send(self, envelope_bytes: bytes, recipient: str) -> SendResult:
        """Send envelope bytes as a NIP-17 gift-wrapped DM.

        Args:
            envelope_bytes: Serialized MessageEnvelope bytes.
            recipient: 64-char hex Nostr x-only pubkey of the recipient.

        Returns:
            SendResult with success/failure and timing.
        """
        start = time.monotonic()
        envelope_id = self._extract_id(envelope_bytes)

        if not self.is_available():
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                error="Nostr transport not available",
            )

        try:
            content_b64 = base64.b64encode(envelope_bytes).decode()
            gift = wrap_dm(self._secret, self._pubkey_hex, recipient, content_b64)

            published = False
            for relay_url in self._relays:
                if _publish_to_relay(relay_url, gift, timeout=self._timeout):
                    published = True
                    logger.info("Published %s to %s", envelope_id[:8], relay_url)
                    break

            elapsed = (time.monotonic() - start) * 1000
            if published:
                return SendResult(
                    success=True,
                    transport_name=self.name,
                    envelope_id=envelope_id,
                    latency_ms=elapsed,
                )
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error="No relay accepted the event",
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            logger.error("Nostr send failed: %s", exc)
            return SendResult(
                success=False,
                transport_name=self.name,
                envelope_id=envelope_id,
                latency_ms=elapsed,
                error=str(exc),
            )

    def receive(self) -> list[bytes]:
        """Poll configured relays for incoming gift-wrapped DMs.

        Returns:
            List of raw SKComms envelope bytes extracted from DMs.
        """
        if not self.is_available():
            return []

        since = int(time.time()) - self._since_window
        filters = {"kinds": [KIND_GIFT_WRAP], "#p": [self._pubkey_hex], "since": since}
        received: list[bytes] = []

        for relay_url in self._relays:
            events = _query_relay(relay_url, filters, timeout=self._timeout)
            for event in events:
                eid = event.get("id", "")
                if eid in self._seen_ids:
                    continue
                self._seen_ids.add(eid)

                result = unwrap_dm(self._secret, event)
                if result is None:
                    continue
                sender_pub, content = result
                try:
                    received.append(base64.b64decode(content))
                    logger.debug("Received DM from %s via %s", sender_pub[:8], relay_url)
                except Exception:
                    logger.debug("Bad base64 in DM from %s", sender_pub[:8])

        return received

    def health_check(self) -> HealthStatus:
        """Check relay connectivity and report transport health.

        Returns:
            HealthStatus with relay reachability details.
        """
        start = time.monotonic()
        details: dict = {"relays": self._relays, "pubkey": self._pubkey_hex}

        if not NOSTR_AVAILABLE:
            return HealthStatus(
                transport_name=self.name,
                status=TransportStatus.UNAVAILABLE,
                error=f"Missing: {', '.join(_MISSING)}",
                details=details,
            )

        reachable = 0
        for relay_url in self._relays:
            try:
                with _ws_connect(relay_url, open_timeout=self._timeout, close_timeout=1) as ws:
                    ws.close()
                reachable += 1
            except Exception as e:
                logger.warning("nostr.py: %s", e)
                pass

        latency = (time.monotonic() - start) * 1000
        details["reachable_relays"] = reachable
        details["total_relays"] = len(self._relays)

        if reachable == 0:
            st, err = TransportStatus.UNAVAILABLE, "No relays reachable"
        elif reachable < len(self._relays):
            st, err = TransportStatus.DEGRADED, f"{reachable}/{len(self._relays)} relays"
        else:
            st, err = TransportStatus.AVAILABLE, None

        return HealthStatus(
            transport_name=self.name,
            status=st,
            latency_ms=latency,
            error=err,
            details=details,
        )

    def publish_identity(self, fingerprint: str) -> bool:
        """Publish a PGP fingerprint to Nostr profile metadata (kind 0).

        Args:
            fingerprint: CapAuth PGP fingerprint string.

        Returns:
            True if published to at least one relay.
        """
        if not self.is_available():
            return False
        metadata = json.dumps(
            {
                "name": f"skcomms-{self._pubkey_hex[:8]}",
                "about": "SKComms sovereign agent",
                "skcomms_pgp": fingerprint,
            }
        )
        event = _make_event(self._pubkey_hex, 0, metadata, [])
        _sign_event(event, self._secret)
        for relay_url in self._relays:
            if _publish_to_relay(relay_url, event, timeout=self._timeout):
                return True
        return False

    @staticmethod
    def _extract_id(envelope_bytes: bytes) -> str:
        """Best-effort envelope_id extraction from raw bytes."""
        try:
            return json.loads(envelope_bytes).get("envelope_id", f"unknown-{int(time.time())}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return f"unknown-{int(time.time())}"


def create_transport(
    priority: int = 3,
    private_key_hex: str | None = None,
    relays: list[str] | None = None,
    relay_timeout: float = 5.0,
    since_window: int = 86400,
    **kwargs,
) -> NostrTransport:
    """Factory function for the router's transport loader.

    Args:
        priority: Transport priority (lower = higher).
        private_key_hex: 64-char hex Nostr private key.
        relays: List of relay WebSocket URLs.
        relay_timeout: Timeout for relay operations.
        since_window: How far back to query for messages.

    Returns:
        Configured NostrTransport instance.
    """
    return NostrTransport(
        private_key_hex=private_key_hex,
        relays=relays,
        priority=priority,
        relay_timeout=relay_timeout,
        since_window=since_window,
    )
