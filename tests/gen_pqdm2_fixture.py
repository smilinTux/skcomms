"""Generate the Python->Dart pqdm2 interop fixture.

Seals a known body to two Python-generated hybrid keypairs (the keypair wire
format is byte-identical across sk_pqc / sk-pqc-dart / this vendored copy) and
dumps everything a Dart test needs to open each slot. Run:

    PYTHONPATH=$PWD/src ~/.skenv/bin/python tests/gen_pqdm2_fixture.py <out.json>

The emitted JSON is committed as
``skchat-app/test/fixtures/pqdm2_from_python.json`` and opened by the Dart
``pq_dm_codec_pqdm2_test.dart`` (Python seal -> Dart open). Deterministic field
names match the plan's Task 2 Step 2 test snippet.
"""

from __future__ import annotations

import json
import sys

from skcomms import pqdm

SENDER = "lumina"
RECIPIENT = "chef"
BODY = "hello"


def build_fixture() -> dict:
    a_pub, a_priv = pqdm.generate_hybrid_keypair()
    b_pub, b_priv = pqdm.generate_hybrid_keypair()
    recips = [
        {"key_id": a_pub[:16], "hybrid_public_hex": a_pub},
        {"key_id": b_pub[:16], "hybrid_public_hex": b_pub},
    ]
    token = pqdm.seal_multi(
        BODY.encode("utf-8"), recips, sender=SENDER, recipient_id=RECIPIENT
    )
    # Sanity: both slots must open on the Python side before we commit.
    assert (
        pqdm.open_multi(
            token,
            my_key_id=a_pub[:16],
            my_private_hex=a_priv,
            sender=SENDER,
            recipient_id=RECIPIENT,
        )
        == BODY.encode("utf-8")
    )
    assert (
        pqdm.open_multi(
            token,
            my_key_id=b_pub[:16],
            my_private_hex=b_priv,
            sender=SENDER,
            recipient_id=RECIPIENT,
        )
        == BODY.encode("utf-8")
    )
    return {
        "token": token,
        "sender": SENDER,
        "recipient": RECIPIENT,
        "body": BODY,
        # Top-level fields for the plan's primary test snippet (first slot).
        "key_id": a_pub[:16],
        "private_hex": a_priv,
        # Full slot list so the Dart test can prove every slot opens.
        "slots": [
            {"key_id": a_pub[:16], "private_hex": a_priv},
            {"key_id": b_pub[:16], "private_hex": b_priv},
        ],
    }


def main() -> None:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "pqdm2_from_python.json"
    fixture = build_fixture()
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(fixture, fh, indent=2)
    print(f"wrote {out_path} (token {fixture['token'][:24]}..., 2 slots)")


if __name__ == "__main__":
    main()
