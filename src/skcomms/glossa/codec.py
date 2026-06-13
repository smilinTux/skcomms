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
    if level == L2_CODEBOOK:
        if codebook is None:
            raise ValueError("L2 codebook level requires a codebook")
        code = codebook.code_for(m.intent)
        # intent slot: int code if known, else the raw string
        head = code if code is not None else m.intent
        return cbor2.dumps([head, m.args, m.refs, m.text])
    raise ValueError(f"unsupported level {level}")


def decode(raw: bytes, level: int, codebook: Codebook | None = None) -> Message:
    if level == L0_ENGLISH:
        return _l0_decode(raw)
    if level == L1_SCHEMA:
        return Message.from_dict(cbor2.loads(raw))
    if level == L2_CODEBOOK:
        if codebook is None:
            raise ValueError("L2 codebook level requires a codebook")
        decoded = cbor2.loads(raw)
        if not isinstance(decoded, list) or len(decoded) != 4:
            raise ValueError("malformed L2 frame — expected [head, args, refs, text]")
        head, args, refs, text = decoded
        if isinstance(head, int):
            intent = codebook.concept_for(head)
            if intent is None:
                raise ValueError(f"unknown codebook code {head} — codebook version skew")
        else:
            intent = head
        return Message(intent=intent or "", args=dict(args),
                       refs=list(refs), text=text)
    raise ValueError(f"unsupported level {level}")
