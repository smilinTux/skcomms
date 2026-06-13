"""SKGlossa codec ladder (spec §2, §3). encode/decode the Message IR per level.

L0 = structured-but-parseable English (the readable floor). L1 = compact CBOR.
L2 = codebook-compressed. Density climbs L0 -> L1 -> L2.
"""

from __future__ import annotations

import json

import cbor2

from skcomms.glossa.codebook import Codebook
from skcomms.glossa.message import Message

L0_ENGLISH = 0
L1_SCHEMA = 1
L2_CODEBOOK = 2


def _l0_encode(m: Message) -> bytes:
    # readable AND parseable: "intent :: <json of {a,r,t}>"
    body = json.dumps({"a": m.args, "r": m.refs, "t": m.text},
                      sort_keys=True, separators=(",", ":"))
    return f"{m.intent} :: {body}".encode()


def _l0_decode(raw: bytes) -> Message:
    s = raw.decode()
    intent, _, body = s.partition(" :: ")
    d = json.loads(body) if body else {}
    return Message(intent=intent, args=dict(d.get("a", {})),
                   refs=list(d.get("r", [])), text=d.get("t", ""))


def encode(m: Message, level: int, codebook: Codebook | None = None) -> bytes:
    if level == L0_ENGLISH:
        return _l0_encode(m)
    if level == L1_SCHEMA:
        return cbor2.dumps(m.to_dict())
    raise ValueError(f"unsupported level {level}")


def decode(raw: bytes, level: int, codebook: Codebook | None = None) -> Message:
    if level == L0_ENGLISH:
        return _l0_decode(raw)
    if level == L1_SCHEMA:
        return Message.from_dict(cbor2.loads(raw))
    raise ValueError(f"unsupported level {level}")
