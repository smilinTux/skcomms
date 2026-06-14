"""
SKComms envelope compression — reduce payload size before transport.

Supports gzip (stdlib, always available) and zstd (optional, faster).
Compression is transparent: the `compressed` flag on MessagePayload
signals the receiver to decompress before processing.

The content string is compressed to base64-encoded binary, then
decompressed back to the original string on the receive side.

Usage:
    from skcomms.compression import compress_payload, decompress_payload

    envelope = compress_payload(envelope, min_size=256)
    envelope = decompress_payload(envelope)
"""

from __future__ import annotations

import base64
import gzip
import logging
from enum import Enum
from typing import Optional

from .models import MessageEnvelope, MessagePayload

logger = logging.getLogger("skcomms.compression")

try:
    import zstandard as _zstd

    HAS_ZSTD = True
except ImportError:
    _zstd = None  # type: ignore[assignment]
    HAS_ZSTD = False

COMPRESSION_HEADER_GZIP = "gz:"
COMPRESSION_HEADER_ZSTD = "zstd:"
DEFAULT_MIN_SIZE = 256
DEFAULT_GZIP_LEVEL = 6
DEFAULT_ZSTD_LEVEL = 3


class CompressionAlgo(str, Enum):
    """Supported compression algorithms."""

    GZIP = "gzip"
    ZSTD = "zstd"
    NONE = "none"


def compress_payload(
    envelope: MessageEnvelope,
    *,
    min_size: int = DEFAULT_MIN_SIZE,
    algorithm: CompressionAlgo = CompressionAlgo.GZIP,
    level: Optional[int] = None,
) -> MessageEnvelope:
    """Compress an envelope's payload content if above the size threshold.

    The content is compressed, base64-encoded, and prefixed with a
    header indicating the algorithm used. The `compressed` flag on
    the payload is set to True.

    Envelopes already compressed or below the threshold are returned
    unchanged.

    Args:
        envelope: The envelope to compress.
        min_size: Minimum content size in bytes to trigger compression.
        algorithm: Compression algorithm to use.
        level: Compression level (algorithm-specific, uses default if None).

    Returns:
        A new MessageEnvelope with compressed content, or the original
        if compression was skipped.
    """
    payload = envelope.payload

    if payload.compressed:
        return envelope

    content_bytes = payload.content.encode("utf-8")
    if len(content_bytes) < min_size:
        return envelope

    if algorithm == CompressionAlgo.ZSTD:
        if not HAS_ZSTD:
            logger.debug("zstd not installed, falling back to gzip")
            algorithm = CompressionAlgo.GZIP

    if algorithm == CompressionAlgo.ZSTD:
        compressed = _compress_zstd(content_bytes, level or DEFAULT_ZSTD_LEVEL)
        header = COMPRESSION_HEADER_ZSTD
    else:
        compressed = _compress_gzip(content_bytes, level or DEFAULT_GZIP_LEVEL)
        header = COMPRESSION_HEADER_GZIP

    ratio = len(compressed) / len(content_bytes)
    if ratio >= 0.95:
        logger.debug("Compression ratio %.2f too poor, skipping", ratio)
        return envelope

    encoded = header + base64.b64encode(compressed).decode("ascii")

    logger.debug(
        "Compressed %d -> %d bytes (%.0f%% reduction, %s)",
        len(content_bytes),
        len(compressed),
        (1 - ratio) * 100,
        algorithm.value,
    )

    new_payload = MessagePayload(
        content=encoded,
        content_type=payload.content_type,
        encrypted=payload.encrypted,
        compressed=True,
        signature=payload.signature,
    )

    return envelope.model_copy(update={"payload": new_payload})


def decompress_payload(envelope: MessageEnvelope) -> MessageEnvelope:
    """Decompress an envelope's payload content if compressed.

    Detects the compression algorithm from the content header,
    base64-decodes, decompresses, and restores the original content.
    The `compressed` flag is set to False.

    Envelopes that are not compressed are returned unchanged.

    Args:
        envelope: The envelope to decompress.

    Returns:
        A new MessageEnvelope with decompressed content, or the
        original if not compressed.
    """
    payload = envelope.payload

    if not payload.compressed:
        return envelope

    content = payload.content

    if content.startswith(COMPRESSION_HEADER_ZSTD):
        b64_data = content[len(COMPRESSION_HEADER_ZSTD) :]
        compressed = base64.b64decode(b64_data)
        decompressed = _decompress_zstd(compressed)
    elif content.startswith(COMPRESSION_HEADER_GZIP):
        b64_data = content[len(COMPRESSION_HEADER_GZIP) :]
        compressed = base64.b64decode(b64_data)
        decompressed = _decompress_gzip(compressed)
    else:
        logger.warning("Unknown compression format, returning as-is")
        return envelope

    original = decompressed.decode("utf-8")

    new_payload = MessagePayload(
        content=original,
        content_type=payload.content_type,
        encrypted=payload.encrypted,
        compressed=False,
        signature=payload.signature,
    )

    return envelope.model_copy(update={"payload": new_payload})


def _compress_gzip(data: bytes, level: int = DEFAULT_GZIP_LEVEL) -> bytes:
    """Compress bytes with gzip.

    Args:
        data: Raw bytes to compress.
        level: Compression level (1-9).

    Returns:
        Gzip-compressed bytes.
    """
    return gzip.compress(data, compresslevel=level)


def _decompress_gzip(data: bytes) -> bytes:
    """Decompress gzip bytes.

    Args:
        data: Gzip-compressed bytes.

    Returns:
        Decompressed bytes.
    """
    return gzip.decompress(data)


def _compress_zstd(data: bytes, level: int = DEFAULT_ZSTD_LEVEL) -> bytes:
    """Compress bytes with zstandard.

    Args:
        data: Raw bytes to compress.
        level: Compression level (1-22).

    Returns:
        Zstd-compressed bytes.

    Raises:
        RuntimeError: If zstd is not installed.
    """
    if not HAS_ZSTD:
        raise RuntimeError("zstandard not installed")
    cctx = _zstd.ZstdCompressor(level=level)
    return cctx.compress(data)


def _decompress_zstd(data: bytes) -> bytes:
    """Decompress zstandard bytes.

    Args:
        data: Zstd-compressed bytes.

    Returns:
        Decompressed bytes.

    Raises:
        RuntimeError: If zstd is not installed.
    """
    if not HAS_ZSTD:
        raise RuntimeError("zstandard not installed")
    dctx = _zstd.ZstdDecompressor()
    return dctx.decompress(data)
