"""Typed-message contract tests (coord 209ff941, [comms][P1] hardened 1:1 chat).

The contract: ``content_type`` is extensible. Known kinds normalize to the
:class:`MessageType` enum; an UNKNOWN kind introduced by a newer client
deserializes without error, round-trips losslessly, and degrades to a
plain-body view so an older client never breaks on a new message kind.

Covered at both layers:
    - ``skcomms.models.MessagePayload`` / ``MessageEnvelope`` (transport).
    - ``skcomms.envelope.Envelope`` v1 (canonical FQID layer).
"""

from __future__ import annotations

from skcomms.envelope import KNOWN_CONTENT_TYPES, Envelope
from skcomms.models import MessageEnvelope, MessagePayload, MessageType


# ---------------------------------------------------------------------------
# MessagePayload — known types
# ---------------------------------------------------------------------------


def test_known_type_normalizes_to_enum():
    p = MessagePayload(content="hi", content_type="text")
    assert p.content_type is MessageType.TEXT
    assert p.is_known_type is True
    assert p.content_type_str == "text"


def test_known_type_enum_input_accepted():
    p = MessagePayload(content="hi", content_type=MessageType.ACK)
    assert p.content_type is MessageType.ACK
    assert p.is_known_type is True


def test_default_content_type_is_text():
    p = MessagePayload(content="hi")
    assert p.content_type is MessageType.TEXT
    assert p.is_known_type is True


def test_known_type_json_roundtrip_stable():
    p = MessagePayload(content="hi", content_type="ack")
    dumped = p.model_dump_json()
    # wire format is the enum *value*, not "MessageType.ACK"
    assert '"content_type":"ack"' in dumped
    p2 = MessagePayload.model_validate_json(dumped)
    assert p2.content_type is MessageType.ACK
    assert p2.model_dump_json() == dumped


# ---------------------------------------------------------------------------
# MessagePayload — unknown types (the forward-compat core)
# ---------------------------------------------------------------------------


def test_unknown_type_deserializes_without_error():
    p = MessagePayload(content="poll body", content_type="poll/v2")
    assert p.content_type == "poll/v2"
    assert isinstance(p.content_type, str)
    assert p.is_known_type is False


def test_unknown_type_falls_back_to_plain_body():
    p = MessagePayload(content="the raw text", content_type="mystery/kind")
    # unknown kinds render as the plain body — never raise
    assert p.render() == "the raw text"
    assert p.content_type_str == "mystery/kind"


def test_unknown_type_is_preserved_through_json_roundtrip():
    p = MessagePayload(content="x", content_type="widget/experimental")
    raw = p.model_dump_json()
    assert '"content_type":"widget/experimental"' in raw
    p2 = MessagePayload.model_validate_json(raw)
    assert p2.content_type == "widget/experimental"
    # serialization is stable across a round-trip
    assert p2.model_dump_json() == raw


def test_unknown_type_not_mistaken_for_ack():
    env = MessageEnvelope(
        sender="a",
        recipient="b",
        payload=MessagePayload(content="x", content_type="ack/v2"),
    )
    assert env.is_ack is False


# ---------------------------------------------------------------------------
# MessageEnvelope — known helpers keep working with the relaxed field
# ---------------------------------------------------------------------------


def test_envelope_ack_helper_still_typed():
    env = MessageEnvelope(
        sender="a", recipient="b", payload=MessagePayload(content="hi")
    )
    ack = env.make_ack("b")
    assert ack.payload.content_type is MessageType.ACK
    assert ack.is_ack is True


def test_envelope_roundtrip_preserves_unknown_type():
    env = MessageEnvelope(
        sender="a",
        recipient="b",
        payload=MessagePayload(content="body", content_type="future/kind"),
    )
    blob = env.to_bytes()
    env2 = MessageEnvelope.from_bytes(blob)
    assert env2.payload.content_type == "future/kind"
    assert env2.payload.render() == "body"
    # byte-stable re-serialization
    assert env2.to_bytes() == blob


# ---------------------------------------------------------------------------
# Envelope v1 (canonical layer) — same contract over ``body``
# ---------------------------------------------------------------------------


def test_envelope_v1_known_content_type():
    e = Envelope(from_fqid="a@c.r", to_fqid="b@c.r", body="hi")
    assert e.content_type == "text/plain"
    assert e.is_known_content_type() is True
    assert e.render() == "hi"


def test_envelope_v1_unknown_content_type_falls_back_to_body():
    e = Envelope(
        from_fqid="a@c.r", to_fqid="b@c.r", body="raw", content_type="x/unknown"
    )
    assert e.is_known_content_type() is False
    assert e.render() == "raw"


def test_envelope_v1_unknown_type_roundtrip_and_canonical_stable():
    e = Envelope(
        from_fqid="a@c.r", to_fqid="b@c.r", body="raw", content_type="x/unknown"
    )
    canon = e.canonical_bytes()
    e2 = Envelope.from_bytes(e.to_bytes())
    assert e2.content_type == "x/unknown"
    assert e2.canonical_bytes() == canon


def test_known_content_types_registry_nonempty():
    assert "text/plain" in KNOWN_CONTENT_TYPES
    assert isinstance(KNOWN_CONTENT_TYPES, frozenset)
