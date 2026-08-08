"""Reverse interop gate: a pqdm2 token sealed by the Dart codec MUST open here.

Closes the version-skew risk in both directions (the forward direction, Python
seal -> Dart open, is proven by the Dart suite reading the fixture this repo's
``tests/gen_pqdm2_fixture.py`` emits). The fixture below is produced by the Dart
``pq_dm_codec_pqdm2_test.dart`` emit test (``buildPqdm2``) and committed here so
this test is self-contained.

If the pqdm2 wire format drifts between the Python and Dart implementations,
this test fails: the Dart-sealed bytes will not authenticate under the Python
``open_multi`` AAD / slot / wrap layout.

Requires the liboqs backend, same as ``test_pqdm2.py``. Without it
:func:`pqdm.open_multi` cannot decapsulate and returns ``None`` for every slot
(it swallows :class:`pqkem.PqKemUnavailable` along with tamper/wrong-key), which
would read as a wire-format regression rather than a missing optional backend.
So the module skips instead. The ``pqc`` CI job installs liboqs and DOES run it,
which is where the Dart<->Python gate is actually enforced.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skcomms import pqdm, pqkem

pytestmark = pytest.mark.skipif(
    not pqkem.is_available(),
    reason="liboqs / oqs backend unavailable",
)

_FIXTURE = Path(__file__).parent / "fixtures" / "pqdm2_from_dart.json"


def _load() -> dict:
    if not _FIXTURE.exists():
        pytest.skip("pqdm2_from_dart.json not generated (run the Dart emit test)")
    return json.loads(_FIXTURE.read_text())


def test_python_opens_dart_sealed_pqdm2_every_slot():
    f = _load()
    body = f["body"].encode("utf-8")
    for slot in f["slots"]:
        opened = pqdm.open_multi(
            f["token"],
            my_key_id=slot["key_id"],
            my_private_hex=slot["private_hex"],
            sender=f["sender"],
            recipient_id=f["recipient"],
        )
        assert opened == body, f"slot {slot['key_id']} failed to open"


def test_python_open_dart_top_level_slot():
    f = _load()
    opened = pqdm.open_multi(
        f["token"],
        my_key_id=f["key_id"],
        my_private_hex=f["private_hex"],
        sender=f["sender"],
        recipient_id=f["recipient"],
    )
    assert opened == f["body"].encode("utf-8")


def test_python_rejects_dart_token_for_non_recipient():
    f = _load()
    # A device whose key_id is not in the header has no slot -> None.
    opened = pqdm.open_multi(
        f["token"],
        my_key_id="0000000000000000",
        my_private_hex=f["slots"][0]["private_hex"],
        sender=f["sender"],
        recipient_id=f["recipient"],
    )
    assert opened is None
