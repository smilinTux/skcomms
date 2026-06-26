"""RFC-0001 P2 — content padding (metadata privacy) tests (skcomms.padding).

Covers the size-hiding pad/unpad construction (plan RFC-0001 §P2):
    * length-prefixed pad to the smallest ladder bucket >= total
    * SIZE-HIDING: two distinct plaintext lengths in the same bucket pad to an
      IDENTICAL on-wire length (the whole point — a coarse size class leaks, the
      exact size does not)
    * correct bucket selection per size + coarse-multiple growth past the top
    * round-trip across a spread of sizes (0 .. 300k)
    * unpad rejects truncated/malformed input (never crashes)
    * the random pad is actually random (differs run-to-run, not all-zeros)
"""

from __future__ import annotations

import pytest

from skcomms.padding import (
    PAD_LADDER,
    PAD_SUITE,
    PaddingError,
    pad_to_bucket,
    unpad,
)

_LEN_PREFIX = 4  # 4-byte big-endian length prefix


def _expected_bucket(total: int) -> int:
    """Smallest ladder bucket >= total, else next multiple of the largest."""
    for bucket in PAD_LADDER:
        if total <= bucket:
            return bucket
    top = PAD_LADDER[-1]
    return ((total + top - 1) // top) * top


@pytest.mark.parametrize("size", [0, 1, 100, 5000, 20000, 300000])
def test_roundtrip(size):
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    assert len(data) == size
    padded = pad_to_bucket(data)
    assert unpad(padded) == data


@pytest.mark.parametrize("size", [0, 1, 100, 5000, 20000, 300000])
def test_correct_bucket_selection(size):
    padded = pad_to_bucket(data=bytes(size))
    assert len(padded) == _expected_bucket(size + _LEN_PREFIX)


def test_size_hiding_same_bucket_identical_length():
    # Two very different plaintext lengths that both fall in the 4096 bucket
    a = pad_to_bucket(bytes(10))
    b = pad_to_bucket(bytes(4000))
    assert len(a) == len(b) == PAD_LADDER[0]
    # And a larger pair sharing the 65536 bucket
    c = pad_to_bucket(bytes(20000))
    d = pad_to_bucket(bytes(60000))
    assert len(c) == len(d) == PAD_LADDER[2]


def test_buckets_climb_the_ladder():
    assert len(pad_to_bucket(bytes(100))) == 4096
    assert len(pad_to_bucket(bytes(5000))) == 16384
    assert len(pad_to_bucket(bytes(20000))) == 65536
    assert len(pad_to_bucket(bytes(100000))) == 262144


def test_oversize_grows_to_coarse_multiple_of_top():
    top = PAD_LADDER[-1]
    # 300000 + 4 prefix > 262144 -> next multiple of top (2 * top)
    padded = pad_to_bucket(bytes(300000))
    assert len(padded) == 2 * top
    assert len(padded) % top == 0
    assert unpad(padded) == bytes(300000)


def test_unpad_rejects_truncated_prefix():
    with pytest.raises(PaddingError):
        unpad(b"\x00\x00")  # fewer than 4 prefix bytes


def test_unpad_rejects_length_exceeding_payload():
    # claims 1000 bytes of body but supplies far fewer
    bad = (1000).to_bytes(4, "big") + b"short"
    with pytest.raises(PaddingError):
        unpad(bad)


def test_unpad_rejects_non_bytes():
    with pytest.raises(PaddingError):
        unpad("not-bytes")  # type: ignore[arg-type]


def test_random_pad_differs_run_to_run():
    data = b"hello"
    a = pad_to_bucket(data)
    b = pad_to_bucket(data)
    assert len(a) == len(b)
    # padding region (after prefix+body) must not be identical run-to-run...
    assert a != b
    # ...and must not be all zeros
    pad_region = a[_LEN_PREFIX + len(data):]
    assert pad_region != bytes(len(pad_region))


def test_pad_suite_constant():
    assert PAD_SUITE == "pad-ladder-v1"
