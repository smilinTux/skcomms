"""Tests for the federation outbox migration + SignedEnvelope handling (SKFed S7).

Covers:
    - outbox_migrate.migrate_outbox: leaves SignedEnvelope entries, converts
      legacy MessageEnvelope entries, archives corrupt + file:// dead-end
      entries, returns the right summary, and is idempotent.
    - outbox.PersistentOutbox._attempt_delivery: routes a SignedEnvelope entry
      via a federation-aware router, and stays tolerant of corrupt entries.
"""

from __future__ import annotations

import json

from skcomms.envelope import Envelope, SignedEnvelope
from skcomms.models import MessageEnvelope, MessagePayload, MessageType
from skcomms.outbox import OutboxEntry, PersistentOutbox, classify_envelope_json
from skcomms.outbox_migrate import (
    NEEDS_SIGN_FLAG,
    migrate_outbox,
    migrate_retry_queue_jsonl,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _signed_entry(to_fqid: str = "jarvis@chef.skworld") -> OutboxEntry:
    """Build an OutboxEntry carrying a (unsigned) SignedEnvelope."""
    env = Envelope(from_fqid="lumina@chef.skworld", to_fqid=to_fqid, body="hi")
    signed = SignedEnvelope(envelope=env, signature="-----FAKE SIG-----")
    return OutboxEntry(
        envelope_id=env.id,
        recipient=to_fqid,
        envelope_json=signed.to_bytes().decode("utf-8"),
    )


def _legacy_entry(recipient: str = "jarvis") -> OutboxEntry:
    """Build an OutboxEntry carrying a legacy MessageEnvelope."""
    legacy = MessageEnvelope(
        sender="lumina",
        recipient=recipient,
        payload=MessagePayload(content="legacy body", content_type=MessageType.TEXT),
    )
    return OutboxEntry(
        envelope_id=legacy.envelope_id,
        recipient=recipient,
        envelope_json=legacy.model_dump_json(),
    )


def _write_entry(outbox: PersistentOutbox, entry: OutboxEntry) -> None:
    path = outbox.pending_dir / f"{entry.envelope_id}.json"
    path.write_text(entry.model_dump_json(indent=2), encoding="utf-8")


def _write_corrupt(outbox: PersistentOutbox, name: str = "corrupt") -> None:
    path = outbox.pending_dir / f"{name}.json"
    path.write_text("{ this is not valid json ", encoding="utf-8")


# ---------------------------------------------------------------------------
# classify_envelope_json
# ---------------------------------------------------------------------------


def test_classify_signed():
    env = Envelope(from_fqid="a@x.y", to_fqid="b@x.y", body="hi")
    signed = SignedEnvelope(envelope=env)
    assert classify_envelope_json(signed.to_bytes().decode("utf-8")) == "signed"


def test_classify_envelope_v1():
    env = Envelope(from_fqid="a@x.y", to_fqid="b@x.y", body="hi")
    assert classify_envelope_json(env.to_bytes().decode("utf-8")) == "envelope_v1"


def test_classify_legacy():
    legacy = MessageEnvelope(
        sender="a", recipient="b", payload=MessagePayload(content="hi")
    )
    assert classify_envelope_json(legacy.model_dump_json()) == "legacy"


def test_classify_corrupt():
    assert classify_envelope_json("{ not json") == "corrupt"
    assert classify_envelope_json("[]") == "corrupt"


# ---------------------------------------------------------------------------
# migrate_outbox
# ---------------------------------------------------------------------------


def test_migrate_outbox_mixed_backlog(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path)

    # (a) valid SignedEnvelope -> left
    signed = _signed_entry()
    _write_entry(outbox, signed)
    # (b) legacy MessageEnvelope -> converted
    legacy = _legacy_entry()
    _write_entry(outbox, legacy)
    # (c) corrupt JSON -> archived
    _write_corrupt(outbox)

    summary = migrate_outbox(outbox)

    assert summary == {"converted": 1, "archived": 1, "skipped": 1}

    # (a) untouched + still classified as signed
    a_path = outbox.pending_dir / f"{signed.envelope_id}.json"
    assert a_path.exists()
    a_entry = OutboxEntry.model_validate_json(a_path.read_text())
    assert classify_envelope_json(a_entry.envelope_json) == "signed"

    # (b) converted in place -> now a SignedEnvelope, flagged needs_sign
    b_path = outbox.pending_dir / f"{legacy.envelope_id}.json"
    assert b_path.exists()
    b_entry = OutboxEntry.model_validate_json(b_path.read_text())
    assert classify_envelope_json(b_entry.envelope_json) == "signed"
    assert b_entry.last_error == NEEDS_SIGN_FLAG
    # field mapping: legacy sender/recipient/content -> from_fqid/to_fqid/body
    converted = SignedEnvelope.from_bytes(b_entry.envelope_json.encode("utf-8"))
    assert converted.envelope.from_fqid == "lumina"
    assert converted.envelope.to_fqid == "jarvis"
    assert converted.envelope.body == "legacy body"
    assert not converted.is_signed  # unsigned: signing happens at send

    # (c) corrupt moved to archive with a reason sidecar
    assert outbox.archive_count == 1
    archived = list(outbox.archive_dir.glob("*.json"))
    assert len(archived) == 1
    reason = archived[0].with_suffix(".reason").read_text()
    assert "corrupt" in reason.lower()


def test_migrate_outbox_file_dead_end_archived(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path)
    legacy = _legacy_entry(recipient="file:///home/x/inbox/jarvis")
    _write_entry(outbox, legacy)

    summary = migrate_outbox(outbox)

    assert summary == {"converted": 0, "archived": 1, "skipped": 0}
    assert not (outbox.pending_dir / f"{legacy.envelope_id}.json").exists()
    archived = list(outbox.archive_dir.glob("*.json"))
    assert len(archived) == 1
    reason = archived[0].with_suffix(".reason").read_text()
    assert "file://" in reason


def test_migrate_outbox_idempotent(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path)
    _write_entry(outbox, _signed_entry())
    _write_entry(outbox, _legacy_entry())
    _write_corrupt(outbox)

    first = migrate_outbox(outbox)
    assert first == {"converted": 1, "archived": 1, "skipped": 1}

    # Second run: nothing left to convert/archive; both remaining are skipped.
    second = migrate_outbox(outbox)
    assert second == {"converted": 0, "archived": 0, "skipped": 2}
    # archive not re-grown
    assert outbox.archive_count == 1


def test_migrate_outbox_accepts_path(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path)
    _write_entry(outbox, _legacy_entry())
    summary = migrate_outbox(str(tmp_path))
    assert summary == {"converted": 1, "archived": 0, "skipped": 0}


# ---------------------------------------------------------------------------
# migrate_retry_queue_jsonl: drain the retired JSONL retry queue
# ---------------------------------------------------------------------------


def _core_schema_line(recipient: str = "jarvis") -> str:
    """A legacy core.RetryQueue JSONL line (envelope_json string field)."""
    legacy = MessageEnvelope(
        sender="lumina",
        recipient=recipient,
        payload=MessagePayload(content="core body", content_type=MessageType.TEXT),
    )
    return json.dumps(
        {
            "envelope_id": legacy.envelope_id,
            "recipient": recipient,
            "envelope_json": legacy.model_dump_json(),
            "attempt": 1,
            "max_attempts": 10,
            "next_retry_at": "2020-01-01T00:00:00+00:00",
            "last_error": "core boom",
            "queued_at": "2020-01-01T00:00:00+00:00",
        }
    )


def _router_schema_line(recipient: str = "friday") -> str:
    """A legacy router JSONL line (envelope_b64 base64 field)."""
    import base64

    legacy = MessageEnvelope(
        sender="lumina",
        recipient=recipient,
        payload=MessagePayload(content="router body", content_type=MessageType.TEXT),
    )
    envelope_b64 = base64.b64encode(legacy.to_bytes()).decode()
    return json.dumps(
        {
            "envelope_id": legacy.envelope_id,
            "recipient": recipient,
            "routing_mode": "failover",
            "envelope_b64": envelope_b64,
            "attempt": 0,
            "next_retry_at": 1.0,
            "queued_at": 1.0,
        }
    )


def test_migrate_retry_queue_jsonl_drains_both_schemas(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox")
    jsonl = tmp_path / "retry_queue.jsonl"
    jsonl.write_text(
        _core_schema_line() + "\n" + _router_schema_line() + "\n",
        encoding="utf-8",
    )

    summary = migrate_retry_queue_jsonl(path=jsonl, outbox=outbox)

    assert summary == {"migrated": 2, "skipped": 0}
    # Both entries landed on the outbox (single queue of record), no loss.
    assert outbox.pending_count == 2
    bodies = {
        json.loads(e.envelope_json)["payload"]["content"]
        for e in outbox.list_pending()
    }
    assert bodies == {"core body", "router body"}
    # The drained JSONL file is removed once fully migrated.
    assert not jsonl.exists()


def test_migrate_retry_queue_jsonl_missing_file_is_noop(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox")
    summary = migrate_retry_queue_jsonl(path=tmp_path / "nope.jsonl", outbox=outbox)
    assert summary == {"migrated": 0, "skipped": 0}
    assert outbox.pending_count == 0


def test_migrate_retry_queue_jsonl_preserves_file_on_corrupt_line(tmp_path):
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox")
    jsonl = tmp_path / "retry_queue.jsonl"
    jsonl.write_text(
        _core_schema_line() + "\n" + "{ not json\n",
        encoding="utf-8",
    )

    summary = migrate_retry_queue_jsonl(path=jsonl, outbox=outbox)

    # The good line is drained; the corrupt one is counted skipped and the file
    # is preserved for inspection (no silent loss).
    assert summary == {"migrated": 1, "skipped": 1}
    assert outbox.pending_count == 1
    assert jsonl.exists()


def test_migrate_retry_queue_jsonl_then_migrate_outbox_signs(tmp_path):
    """End-to-end: drain legacy JSONL, then migrate_outbox converts to signed."""
    outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox")
    jsonl = tmp_path / "retry_queue.jsonl"
    jsonl.write_text(_router_schema_line() + "\n", encoding="utf-8")

    migrate_retry_queue_jsonl(path=jsonl, outbox=outbox)
    # Drained entry is a legacy MessageEnvelope; migrate_outbox converts it.
    assert classify_envelope_json(outbox.list_pending()[0].envelope_json) == "legacy"

    summary = migrate_outbox(outbox)
    assert summary == {"converted": 1, "archived": 0, "skipped": 0}
    assert classify_envelope_json(outbox.list_pending()[0].envelope_json) == "signed"


# ---------------------------------------------------------------------------
# _attempt_delivery: SignedEnvelope routing + corruption tolerance
# ---------------------------------------------------------------------------


class _FakeReport:
    def __init__(self, delivered: bool):
        self.delivered = delivered


class _FederationRouter:
    """Router exposing the forward federation route path (route_signed)."""

    def __init__(self):
        self.routed_signed: list[SignedEnvelope] = []

    def route_signed(self, signed: SignedEnvelope) -> _FakeReport:
        self.routed_signed.append(signed)
        return _FakeReport(delivered=True)


class _BytesRouter:
    """Router exposing only the bytes federation route path (route_bytes)."""

    def __init__(self):
        self.routed_bytes: list[tuple[bytes, str]] = []

    def route_bytes(self, data: bytes, recipient: str) -> _FakeReport:
        self.routed_bytes.append((data, recipient))
        return _FakeReport(delivered=True)


class _LegacyOnlyRouter:
    """Router with only the legacy route(MessageEnvelope) path."""

    def __init__(self):
        self.calls = 0

    def route(self, envelope) -> _FakeReport:  # noqa: ANN001
        self.calls += 1
        return _FakeReport(delivered=True)


def test_attempt_delivery_routes_signed_envelope(tmp_path):
    router = _FederationRouter()
    outbox = PersistentOutbox(outbox_dir=tmp_path, router=router)
    entry = _signed_entry()

    delivered = outbox._attempt_delivery(entry)

    assert delivered is True
    assert len(router.routed_signed) == 1
    assert router.routed_signed[0].envelope.to_fqid == "jarvis@chef.skworld"


def test_attempt_delivery_routes_signed_via_bytes_router(tmp_path):
    router = _BytesRouter()
    outbox = PersistentOutbox(outbox_dir=tmp_path, router=router)
    entry = _signed_entry()

    delivered = outbox._attempt_delivery(entry)

    assert delivered is True
    assert len(router.routed_bytes) == 1
    data, recipient = router.routed_bytes[0]
    assert recipient == "jarvis@chef.skworld"
    # bytes are a serialized SignedEnvelope
    assert classify_envelope_json(data.decode("utf-8")) == "signed"


def test_attempt_delivery_signed_held_when_no_federation_path(tmp_path):
    router = _LegacyOnlyRouter()
    outbox = PersistentOutbox(outbox_dir=tmp_path, router=router)
    entry = _signed_entry()

    delivered = outbox._attempt_delivery(entry)

    # No crash; entry held (not delivered) and legacy route() NOT used for a
    # SignedEnvelope.
    assert delivered is False
    assert router.calls == 0
    assert "federation route path" in entry.last_error


def test_attempt_delivery_legacy_uses_legacy_route(tmp_path):
    router = _LegacyOnlyRouter()
    outbox = PersistentOutbox(outbox_dir=tmp_path, router=router)
    entry = _legacy_entry()

    delivered = outbox._attempt_delivery(entry)

    assert delivered is True
    assert router.calls == 1


def test_attempt_delivery_corrupt_does_not_crash(tmp_path):
    router = _FederationRouter()
    outbox = PersistentOutbox(outbox_dir=tmp_path, router=router)
    entry = OutboxEntry(
        envelope_id="corrupt-1",
        recipient="jarvis@chef.skworld",
        envelope_json="{ not json ",
    )

    delivered = outbox._attempt_delivery(entry)

    assert delivered is False
    assert router.routed_signed == []
    assert "corrupt" in entry.last_error.lower()
