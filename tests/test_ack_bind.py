"""Security tests for ACK binding + replay protection.

The bug (MED — ACK forgery / replay): ``AckTracker.process_ack`` accepted any
ACK envelope referencing a known pending envelope id, with:
  * NO binding proving the ACK came from the party the original message was
    delivered to (anyone could forge a confirmation);
  * NO replay/dedupe (a captured ACK could be replayed to re-confirm).

These tests prove both holes, then guard the fix.
"""

from __future__ import annotations

import pytest

from skcomms.ack import AckStatus, AckTracker
from skcomms.models import MessageEnvelope, MessagePayload, RoutingConfig


def _make_tracked_message(sender: str, recipient: str) -> MessageEnvelope:
    """Build an ack-requested outbound envelope from ``sender`` to ``recipient``."""
    return MessageEnvelope(
        sender=sender,
        recipient=recipient,
        payload=MessagePayload(content="hello"),
        routing=RoutingConfig(ack_requested=True),
    )


@pytest.fixture()
def tracker(tmp_path):
    return AckTracker(acks_dir=tmp_path / "acks")


def test_ack_from_intended_recipient_is_accepted(tracker):
    """Baseline: a legitimate ACK from the real recipient confirms delivery."""
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob")  # bob is who the message went to
    resolved = tracker.process_ack(ack)

    assert resolved is not None
    assert resolved.status == AckStatus.CONFIRMED


def test_forged_ack_from_wrong_sender_is_rejected(tracker):
    """An ACK whose sender is NOT the intended recipient must be rejected."""
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    # Mallory forges an ACK for alice->bob, claiming to be the acker.
    forged = msg.make_ack(sender="mallory")
    resolved = tracker.process_ack(forged)

    assert resolved is None, "forged ACK from wrong sender must NOT confirm"
    entry = tracker.get(msg.envelope_id)
    assert entry is not None
    assert entry.status == AckStatus.PENDING, "forged ACK must not confirm delivery"


def test_replayed_ack_does_not_reconfirm(tracker):
    """A replayed ACK for an already-confirmed envelope must be rejected."""
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob")
    first = tracker.process_ack(ack)
    assert first is not None and first.status == AckStatus.CONFIRMED
    first_confirmed_at = first.confirmed_at

    # Attacker replays the exact same captured ACK.
    replay = tracker.process_ack(ack)
    assert replay is None, "replayed ACK must not re-confirm"

    entry = tracker.get(msg.envelope_id)
    assert entry.status == AckStatus.CONFIRMED
    assert entry.confirmed_at == first_confirmed_at, "replay must not mutate the entry"


def test_ack_for_unknown_envelope_is_rejected(tracker):
    """An ACK referencing an envelope we never tracked is ignored."""
    stray = MessageEnvelope(
        sender="bob",
        recipient="alice",
        payload=MessagePayload(content="does-not-exist"),
    )
    ack = stray.make_ack(sender="alice")
    assert tracker.process_ack(ack) is None


# --- identity normalization (PGP fingerprints cross transports differently) --


def test_ack_with_fingerprint_spacing_and_case_is_accepted(tracker):
    """A spaced/lowercased fingerprint still matches the tracked recipient."""
    msg = _make_tracked_message("alice", "ABCD 1234 EF56 7890")
    tracker.track(msg)

    ack = msg.make_ack(sender="abcd1234ef567890")
    resolved = tracker.process_ack(ack)

    assert resolved is not None
    assert resolved.status == AckStatus.CONFIRMED


def test_identity_matches_fails_closed_on_empty():
    """Empty identities never match, even against each other."""
    assert AckTracker._identity_matches("", "") is False
    assert AckTracker._identity_matches("bob", "") is False
    assert AckTracker._identity_matches("", "bob") is False
    assert AckTracker._identity_matches("bob", "bob") is True


def test_ack_with_empty_sender_is_rejected(tracker):
    """An ACK with an empty sender must never confirm (fail closed)."""
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob").model_copy(update={"sender": ""})
    assert tracker.process_ack(ack) is None
    assert tracker.get(msg.envelope_id).status == AckStatus.PENDING


# --- stale ACKs ---------------------------------------------------------------


def test_stale_ack_after_timeout_is_rejected(tmp_path):
    """An ACK arriving after the entry timed out must not resurrect it."""
    tracker = AckTracker(acks_dir=tmp_path / "acks", default_timeout=0)
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    timed_out = tracker.check_timeouts()
    assert [p.envelope_id for p in timed_out] == [msg.envelope_id]

    late_ack = msg.make_ack(sender="bob")
    assert tracker.process_ack(late_ack) is None
    assert tracker.get(msg.envelope_id).status == AckStatus.TIMED_OUT


# --- cryptographic sender verification (sender_verifier hook) ------------------


def test_verifier_accepting_ack_confirms(tmp_path):
    """A wired-in verifier that authenticates the sender allows confirmation."""
    seen = []

    def verifier(env):
        seen.append(env)
        return True

    tracker = AckTracker(acks_dir=tmp_path / "acks", sender_verifier=verifier)
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob")
    resolved = tracker.process_ack(ack)

    assert resolved is not None and resolved.status == AckStatus.CONFIRMED
    assert seen == [ack]


def test_verifier_rejecting_ack_blocks_confirmation(tmp_path):
    """A verifier returning False rejects the ACK even from the right sender."""
    tracker = AckTracker(acks_dir=tmp_path / "acks", sender_verifier=lambda env: False)
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob")
    assert tracker.process_ack(ack) is None
    assert tracker.get(msg.envelope_id).status == AckStatus.PENDING


def test_verifier_exception_fails_closed(tmp_path):
    """A verifier that raises must reject the ACK, not confirm it."""

    def broken(env):
        raise RuntimeError("keystore exploded")

    tracker = AckTracker(acks_dir=tmp_path / "acks", sender_verifier=broken)
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    ack = msg.make_ack(sender="bob")
    assert tracker.process_ack(ack) is None
    assert tracker.get(msg.envelope_id).status == AckStatus.PENDING


def test_verifier_not_consulted_for_forged_sender(tmp_path):
    """Sender binding rejects first; the verifier never sees a forged ACK."""
    calls = []

    def verifier(env):
        calls.append(env)
        return True

    tracker = AckTracker(acks_dir=tmp_path / "acks", sender_verifier=verifier)
    msg = _make_tracked_message("alice", "bob")
    tracker.track(msg)

    forged = msg.make_ack(sender="mallory")
    assert tracker.process_ack(forged) is None
    assert calls == []


# --- SKComms wiring (config gate + auto-ACK signing) ---------------------------


class _StubRouter:
    """Minimal router double: records routed envelopes."""

    def __init__(self):
        self.routed = []

    def route(self, envelope):
        self.routed.append(envelope)
        return type("R", (), {"delivered": True, "transport_used": "stub"})()


class _StubKeystore:
    def __init__(self, keys=None):
        self._keys = keys or {}

    def has_key(self, peer):
        return peer in self._keys

    def get_public_key(self, peer):
        return self._keys.get(peer)


def _make_comm(config, crypto=None, keystore=None, tmp_path=None):
    from skcomms.core import SKComms
    from skcomms.outbox import PersistentOutbox

    router = _StubRouter()
    comm = SKComms(config=config, router=router, crypto=crypto, keystore=keystore)
    if tmp_path is not None:
        comm._outbox = PersistentOutbox(outbox_dir=tmp_path / "outbox", router=router)
    return comm, router


def test_core_gate_off_builds_tracker_without_verifier(tmp_path):
    """Default config (gate off) keeps the identity-binding-only tracker."""
    from skcomms.config import SKCommsConfig

    comm, _ = _make_comm(SKCommsConfig(), tmp_path=tmp_path)
    assert comm._ack_tracker is not None
    assert comm._ack_tracker._sender_verifier is None


def test_core_gate_on_without_crypto_fails_closed(tmp_path):
    """Gate on but no crypto/keystore: every ACK is rejected by the verifier."""
    from skcomms.config import SKCommsConfig

    comm, _ = _make_comm(SKCommsConfig(ack_verify_signature=True), tmp_path=tmp_path)
    verifier = comm._ack_tracker._sender_verifier
    assert verifier is not None

    msg = _make_tracked_message("alice", "bob")
    ack = msg.make_ack(sender="bob")
    assert verifier(ack) is False


def test_core_verifier_rejects_unsigned_and_unknown_key(tmp_path):
    """Gate on: unsigned ACKs and ACKs from unknown keys are rejected."""
    from skcomms.config import SKCommsConfig

    class _StubCrypto:
        def verify_signature(self, envelope, pub_armor):
            return True

    keystore = _StubKeystore({"bob": "PUBKEY-ARMOR"})
    comm, _ = _make_comm(
        SKCommsConfig(ack_verify_signature=True),
        crypto=_StubCrypto(),
        keystore=keystore,
        tmp_path=tmp_path,
    )
    verifier = comm._ack_tracker._sender_verifier

    msg = _make_tracked_message("alice", "bob")

    unsigned = msg.make_ack(sender="bob")
    assert verifier(unsigned) is False

    signed_unknown = msg.make_ack(sender="mallory")
    signed_unknown = signed_unknown.model_copy(
        update={"payload": signed_unknown.payload.model_copy(update={"signature": "SIG"})}
    )
    assert verifier(signed_unknown) is False

    signed_known = msg.make_ack(sender="bob")
    signed_known = signed_known.model_copy(
        update={"payload": signed_known.payload.model_copy(update={"signature": "SIG"})}
    )
    assert verifier(signed_known) is True


def test_auto_ack_is_signed_when_crypto_present(tmp_path):
    """_send_auto_ack runs the ACK through outbound crypto so peers can verify."""
    from skcomms.config import SKCommsConfig

    class _SigningCrypto:
        def sign_payload(self, envelope):
            new_payload = envelope.payload.model_copy(update={"signature": "SIGNED"})
            return envelope.model_copy(update={"payload": new_payload})

    config = SKCommsConfig(sign=True, encrypt=False)
    comm, router = _make_comm(config, crypto=_SigningCrypto(), tmp_path=tmp_path)

    inbound = _make_tracked_message("alice", comm._identity)
    comm._send_auto_ack(inbound)

    assert len(router.routed) == 1
    ack = router.routed[0]
    assert ack.is_ack
    assert ack.payload.signature == "SIGNED"


def test_end_to_end_signed_ack_verifies_with_real_pgp(tmp_path):
    """Receiver signs the auto-ACK; sender's gated verifier accepts it,
    and a forged unsigned ACK from the same identity is rejected."""
    pgpy = pytest.importorskip("pgpy")
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    from skcomms.config import SKCommsConfig, IdentityConfig
    from skcomms.crypto import EnvelopeCrypto

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new("bob <bob@chef.skworld>"),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    priv, pub = str(key), str(key.pubkey)
    fp = str(key.fingerprint).replace(" ", "")

    # Receiver bob: signs its auto-ACK.
    bob_cfg = SKCommsConfig(identity=IdentityConfig(name="bob"), sign=True, encrypt=False)
    bob, bob_router = _make_comm(bob_cfg, crypto=EnvelopeCrypto(priv, "", fp), tmp_path=tmp_path)

    inbound = _make_tracked_message("alice", "bob")
    bob._send_auto_ack(inbound)
    assert len(bob_router.routed) == 1
    signed_ack = bob_router.routed[0]
    assert signed_ack.payload.signature

    # Sender alice: gate on, knows bob's public key.
    alice_cfg = SKCommsConfig(
        identity=IdentityConfig(name="alice"), ack_verify_signature=True
    )
    alice, _ = _make_comm(
        alice_cfg,
        crypto=EnvelopeCrypto(priv, "", fp),
        keystore=_StubKeystore({"bob": pub}),
        tmp_path=tmp_path,
    )
    alice._ack_tracker = __import__("skcomms.ack", fromlist=["AckTracker"]).AckTracker(
        acks_dir=tmp_path / "alice-acks",
        sender_verifier=alice._make_ack_sender_verifier(),
    )
    alice._ack_tracker.track(inbound)

    resolved = alice._ack_tracker.process_ack(signed_ack)
    assert resolved is not None and resolved.status == AckStatus.CONFIRMED

    # A forged unsigned ACK from "bob" must NOT confirm a fresh pending entry.
    second = _make_tracked_message("alice", "bob")
    alice._ack_tracker.track(second)
    forged = second.make_ack(sender="bob")
    assert alice._ack_tracker.process_ack(forged) is None
