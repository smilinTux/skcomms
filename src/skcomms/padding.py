"""Content padding (length hiding) — the size-class bucketing for DM/envelope.

This is **RFC-0001 P2** of the metadata-privacy work: a small, honest length-
hiding wrapper applied to a *plaintext body before it is sealed*. It does not
encrypt anything — it only normalizes the on-wire *length* of a payload to one
of a few coarse buckets so a passive observer learns a size *class*, not the
exact byte count (a classic traffic-analysis leak: an encrypted body still
reveals its length, which fingerprints the content).

Why a ladder, not SimpleX's single bucket
------------------------------------------
SimpleX pads every message to one fixed ~16 KB block. That perfectly hides
size *within* the block, but (a) wastes ~16 KB of bandwidth on a one-line DM and
(b) cannot represent anything larger without a separate mechanism. We instead
use a short **bucket ladder** (:data:`PAD_LADDER`). The trade-off is explicit:
the ladder leaks only a coarse size class (which of four buckets), while keeping
small messages cheap. Payloads larger than the top bucket grow to the next
*multiple* of the top bucket — so even oversize bodies pad to a coarse multiple
rather than leaking their exact length.

Wire format
-----------
::

    padded = len(4, big-endian) || body || random_pad

The 4-byte big-endian prefix is the true body length; the trailing random pad
fills out to the chosen bucket. :func:`unpad` reads the prefix and returns
exactly that many body bytes. The pad is :func:`os.urandom` (not zeros) so the
filler is indistinguishable from ciphertext once this wrapper is itself sealed —
nothing about the pad region hints at where the real body ended.

Honesty / scope
---------------
This is length hiding ONLY. It is not confidentiality, not authentication, and
not a defence against an observer who can *count messages* or time them. It is
the size-normalization layer that runs *under* the AEAD seal
(:mod:`skcomms.pqdm`). The self-report advertises it via :data:`PAD_SUITE`.
"""

from __future__ import annotations

import os

#: A small bucket ladder (bytes). NOT SimpleX's single 16 KB bucket: a ladder
#: leaks only a coarse size class while keeping small DMs cheap (a one-line
#: message pads to 4 KB, not 16 KB), and still covers large payloads via
#: coarse-multiple growth past the top bucket.
PAD_LADDER = (4096, 16384, 65536, 262144)

#: Suite-flag constant for the self-report (mirrors ``crypto_suites`` ids).
PAD_SUITE = "pad-ladder-v1"

#: Width of the big-endian length prefix that precedes the body.
_LEN_PREFIX_LEN = 4

#: Largest value the 4-byte prefix can encode (a sanity bound on body length).
_MAX_BODY_LEN = (1 << (8 * _LEN_PREFIX_LEN)) - 1


class PaddingError(ValueError):
    """Malformed / truncated padded blob (never a crash)."""


def _bucket_for(total: int, ladder: tuple[int, ...]) -> int:
    """Smallest ladder bucket >= ``total``.

    If ``total`` exceeds the largest bucket, grow to the next multiple of the
    largest bucket (documented coarse-multiple growth) so oversize payloads
    still pad to a coarse size class rather than leaking their exact length.
    """
    for bucket in ladder:
        if total <= bucket:
            return bucket
    top = ladder[-1]
    return ((total + top - 1) // top) * top


def pad_to_bucket(data: bytes, ladder: tuple[int, ...] = PAD_LADDER) -> bytes:
    """Length-prefix ``data`` and random-pad it up to a bucket boundary.

    Prepends a 4-byte big-endian length, then appends :func:`os.urandom` filler
    so the result length is the smallest bucket in ``ladder`` that is >= the
    prefixed total. Payloads whose prefixed total exceeds the largest bucket
    grow to the next multiple of the largest bucket.

    Two distinct body lengths that land in the same bucket produce an IDENTICAL
    output length — that is the size-hiding property.

    Args:
        data: The body bytes to pad (any length up to ~4 GiB).
        ladder: The bucket ladder (ascending, bytes). Defaults to
            :data:`PAD_LADDER`.

    Returns:
        ``len(4) || data || random_pad`` sized to a bucket boundary.

    Raises:
        PaddingError: if ``data`` is not bytes-like or too large to length-prefix.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise PaddingError(f"data must be bytes, got {type(data).__name__}")
    body = bytes(data)
    if len(body) > _MAX_BODY_LEN:
        raise PaddingError(
            f"body too large to length-prefix: {len(body)} > {_MAX_BODY_LEN}"
        )
    prefix = len(body).to_bytes(_LEN_PREFIX_LEN, "big")
    total = len(prefix) + len(body)
    target = _bucket_for(total, ladder)
    pad_len = target - total
    return prefix + body + os.urandom(pad_len)


def unpad(padded: bytes) -> bytes:
    """Recover the original body from a :func:`pad_to_bucket` blob.

    Reads the 4-byte big-endian length prefix and returns exactly that many body
    bytes (discarding the random pad).

    Args:
        padded: A blob produced by :func:`pad_to_bucket`.

    Returns:
        The original body bytes.

    Raises:
        PaddingError: on non-bytes input, a missing/short prefix, or a declared
            length that exceeds the available payload (truncated/malformed).
    """
    if not isinstance(padded, (bytes, bytearray)):
        raise PaddingError(f"padded must be bytes, got {type(padded).__name__}")
    blob = bytes(padded)
    if len(blob) < _LEN_PREFIX_LEN:
        raise PaddingError(
            f"padded blob shorter than {_LEN_PREFIX_LEN}-byte length prefix: "
            f"{len(blob)} bytes"
        )
    body_len = int.from_bytes(blob[:_LEN_PREFIX_LEN], "big")
    body_end = _LEN_PREFIX_LEN + body_len
    if body_end > len(blob):
        raise PaddingError(
            f"declared body length {body_len} exceeds available payload "
            f"({len(blob) - _LEN_PREFIX_LEN} bytes) — truncated or malformed"
        )
    return blob[_LEN_PREFIX_LEN:body_end]
