"""
SKComm rate limiter — token bucket throttling per transport and per peer.

Prevents transport abuse, respects relay API limits, and protects
the mesh from runaway send loops. Each transport and peer combination
gets its own token bucket that refills at a configurable rate.

Usage:
    from skcomm.ratelimit import RateLimiter

    rl = RateLimiter()
    if rl.allow("nostr", "lumina"):
        # send the message
    else:
        # throttled — wait or queue
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger("skcomm.ratelimit")

DEFAULT_CAPACITY = 30
DEFAULT_REFILL_RATE = 1.0
DEFAULT_PEER_CAPACITY = 10
DEFAULT_PEER_REFILL_RATE = 0.5


class TokenBucket:
    """Classic token bucket rate limiter.

    Tokens accumulate at a fixed rate up to a maximum capacity.
    Each allowed operation consumes one token. When empty,
    operations are denied until tokens refill.

    Args:
        capacity: Maximum number of tokens (burst size).
        refill_rate: Tokens added per second.
    """

    def __init__(
        self, capacity: float = DEFAULT_CAPACITY, refill_rate: float = DEFAULT_REFILL_RATE
    ):
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._tokens = capacity
        self._last_refill = time.monotonic()

    @property
    def capacity(self) -> float:
        """Maximum token count."""
        return self._capacity

    @property
    def refill_rate(self) -> float:
        """Tokens per second."""
        return self._refill_rate

    @property
    def tokens(self) -> float:
        """Current token count (after refill)."""
        self._refill()
        return self._tokens

    def allow(self, cost: float = 1.0) -> bool:
        """Try to consume tokens for one operation.

        Args:
            cost: Number of tokens to consume (default 1).

        Returns:
            True if the operation is allowed, False if throttled.
        """
        self._refill()
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False

    def wait_time(self, cost: float = 1.0) -> float:
        """Seconds until enough tokens are available.

        Args:
            cost: Tokens needed.

        Returns:
            Seconds to wait (0 if tokens are available now).
        """
        self._refill()
        if self._tokens >= cost:
            return 0.0
        deficit = cost - self._tokens
        return deficit / self._refill_rate if self._refill_rate > 0 else float("inf")

    def _refill(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now


class RateLimitConfig(BaseModel):
    """Rate limit configuration for a transport.

    Attributes:
        transport_capacity: Max burst per transport.
        transport_refill: Tokens/sec per transport.
        peer_capacity: Max burst per peer within a transport.
        peer_refill: Tokens/sec per peer.
        enabled: Whether rate limiting is active.
    """

    transport_capacity: float = DEFAULT_CAPACITY
    transport_refill: float = DEFAULT_REFILL_RATE
    peer_capacity: float = DEFAULT_PEER_CAPACITY
    peer_refill: float = DEFAULT_PEER_REFILL_RATE
    enabled: bool = True


class RateLimiter:
    """Two-tier rate limiter: per-transport and per-peer.

    Each transport gets a global bucket (protects the transport
    from overload). Within each transport, each peer also gets
    a bucket (prevents flooding a single recipient).

    Args:
        default_config: Default limits for all transports.
        overrides: Per-transport config overrides.
    """

    def __init__(
        self,
        default_config: Optional[RateLimitConfig] = None,
        overrides: Optional[dict[str, RateLimitConfig]] = None,
    ):
        self._default = default_config or RateLimitConfig()
        self._overrides = overrides or {}
        self._transport_buckets: dict[str, TokenBucket] = {}
        self._peer_buckets: dict[str, TokenBucket] = {}

    def allow(self, transport: str, peer: str = "") -> bool:
        """Check if a send operation is allowed under rate limits.

        Args:
            transport: Transport name (e.g. "nostr", "syncthing").
            peer: Recipient identifier (optional).

        Returns:
            True if the operation is allowed.
        """
        config = self._config_for(transport)
        if not config.enabled:
            return True

        t_bucket = self._get_transport_bucket(transport, config)
        if not t_bucket.allow():
            logger.debug("Rate limited: transport %s at capacity", transport)
            return False

        if peer:
            p_bucket = self._get_peer_bucket(transport, peer, config)
            if not p_bucket.allow():
                logger.debug("Rate limited: peer %s on %s", peer, transport)
                t_bucket._tokens += 1  # Refund the transport token
                return False

        return True

    def wait_time(self, transport: str, peer: str = "") -> float:
        """Seconds until the next send would be allowed.

        Args:
            transport: Transport name.
            peer: Recipient identifier.

        Returns:
            Seconds to wait (0 if allowed now).
        """
        config = self._config_for(transport)
        if not config.enabled:
            return 0.0

        t_bucket = self._get_transport_bucket(transport, config)
        t_wait = t_bucket.wait_time()

        if peer:
            p_bucket = self._get_peer_bucket(transport, peer, config)
            p_wait = p_bucket.wait_time()
            return max(t_wait, p_wait)

        return t_wait

    def status(self) -> dict[str, dict]:
        """Get current token levels for all buckets.

        Returns:
            Dict mapping bucket keys to token info.
        """
        result: dict[str, dict] = {}
        for key, bucket in self._transport_buckets.items():
            result[f"transport:{key}"] = {
                "tokens": round(bucket.tokens, 1),
                "capacity": bucket.capacity,
                "refill_rate": bucket.refill_rate,
            }
        for key, bucket in self._peer_buckets.items():
            result[f"peer:{key}"] = {
                "tokens": round(bucket.tokens, 1),
                "capacity": bucket.capacity,
                "refill_rate": bucket.refill_rate,
            }
        return result

    def _config_for(self, transport: str) -> RateLimitConfig:
        """Get config for a transport (override or default)."""
        return self._overrides.get(transport, self._default)

    def _get_transport_bucket(self, transport: str, config: RateLimitConfig) -> TokenBucket:
        """Get or create the transport-level bucket."""
        if transport not in self._transport_buckets:
            self._transport_buckets[transport] = TokenBucket(
                config.transport_capacity,
                config.transport_refill,
            )
        return self._transport_buckets[transport]

    def _get_peer_bucket(self, transport: str, peer: str, config: RateLimitConfig) -> TokenBucket:
        """Get or create a peer-level bucket within a transport."""
        key = f"{transport}:{peer}"
        if key not in self._peer_buckets:
            self._peer_buckets[key] = TokenBucket(
                config.peer_capacity,
                config.peer_refill,
            )
        return self._peer_buckets[key]
