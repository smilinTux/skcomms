"""Security regression: the mailbox must NOT write message bodies to the
recipient's Syncthing-replicated inbox in plaintext (HIGH — plaintext at rest).

Before the fix, ``send_message`` signed the Envelope v1 but wrote the signed
JSON *unencrypted* to ``<peer>/inbox/`` — a directory Syncthing replicates to
the peer. So every message body sat in cleartext on disk and in transit-at-rest.

These tests:

* prove the peer inbox drop is ciphertext (the body string is NOT recoverable
  by reading the raw bytes),
* prove ``read_inbox`` decrypts symmetrically so the signed round-trip still
  verifies,
* prove fail-closed: no recipient key ⇒ ``send_message`` raises, never a
  plaintext fallback,
* prove idempotency: an already-sealed body (skchat ratchet / ``pqdm1:`` /
  PGP-armored) is NOT double-encrypted at rest.

Everything runs against a tmp ``SKCOMMS_HOME`` with in-process PGP keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


def _gen_key(uid: str):
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey)


@pytest.fixture(scope="module")
def lumina_keys():
    return _gen_key("lumina <lumina@chef.skworld>")


@pytest.fixture
def cluster_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    cluster_file = tmp_path / "cluster.json"
    cluster_file.write_text(json.dumps({"realm": "skworld", "operator": "chef"}))
    from skcomms import cluster as cm

    original = cm._CLUSTER_LOOKUP
    cm._CLUSTER_LOOKUP = [cluster_file]
    yield tmp_path
    cm._CLUSTER_LOOKUP = original


@pytest.fixture
def signing_patch(lumina_keys):
    """Sender identity + signer patched; every recipient resolves to lumina's
    keypair (so send-to-self round-trips: encrypt-to-lumina, decrypt-as-lumina,
    verify-lumina's-sig)."""
    priv, pub = lumina_keys
    from skcomms.signing import EnvelopeSigner

    ident = {
        "agent": "lumina",
        "fqid": "lumina@chef.skworld",
        "fingerprint": EnvelopeSigner(priv, "").fingerprint,
    }
    with patch("skcomms.mailbox.resolve_self_identity", return_value=ident), patch(
        "skcomms.mailbox._load_signer", return_value=EnvelopeSigner(priv, "")
    ), patch("skcomms.mailbox._load_verifier_key", return_value=pub), patch(
        "skcomms.mailbox._load_recipient_key", return_value=pub
    ), patch("skcomms.mailbox._load_private_armor", return_value=priv):
        yield priv, pub


@pytest.fixture
def signing_patch_real_recipient_lookup(lumina_keys):
    """Like signing_patch but _load_recipient_key is NOT patched, so the real
    fail-closed recipient-key resolution runs against the tmp environment."""
    priv, pub = lumina_keys
    from skcomms.signing import EnvelopeSigner

    ident = {
        "agent": "lumina",
        "fqid": "lumina@chef.skworld",
        "fingerprint": EnvelopeSigner(priv, "").fingerprint,
    }
    with patch("skcomms.mailbox.resolve_self_identity", return_value=ident), patch(
        "skcomms.mailbox._load_signer", return_value=EnvelopeSigner(priv, "")
    ), patch("skcomms.mailbox._load_verifier_key", return_value=pub), patch(
        "skcomms.mailbox._load_private_armor", return_value=priv
    ):
        yield priv, pub


SECRET = "the eagle lands at midnight"


class TestNotPlaintextAtRest:
    def test_peer_inbox_drop_is_not_plaintext(self, cluster_env, signing_patch):
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message

        scaffold(agent="lumina")
        result = send_message("opus@chef.skworld", SECRET)

        peer_path = Path(result["peer_inbox_path"])
        raw = peer_path.read_bytes()
        # The body must NOT appear in cleartext anywhere in the on-disk file.
        assert SECRET.encode("utf-8") not in raw, "message body written in plaintext!"
        # And it must not be a bare readable SignedEnvelope either.
        from skcomms.envelope import SignedEnvelope

        with pytest.raises(Exception):
            SignedEnvelope.from_bytes(raw)


class TestRoundTrip:
    def test_send_to_self_decrypts_and_verifies(self, cluster_env, signing_patch):
        from skcomms.home import scaffold
        from skcomms.mailbox import read_inbox, send_message

        scaffold(agent="lumina")
        send_message("lumina@chef.skworld", SECRET)

        # On-disk inbox file is ciphertext...
        inbox = scaffold(agent="lumina")["inbox"]
        files = list(Path(inbox).glob("*"))
        assert files
        assert SECRET.encode("utf-8") not in files[0].read_bytes()

        # ...but read_inbox recovers the body and verifies the signature.
        items = read_inbox(agent="lumina")
        assert len(items) == 1
        env, verification = items[0]
        assert env.body == SECRET
        assert verification.valid, verification.reason


class TestFailClosed:
    def test_no_recipient_key_raises_not_plaintext(self, cluster_env, signing_patch):
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message

        scaffold(agent="lumina")
        # Override the recipient-key lookup to report NO key for the recipient.
        with patch("skcomms.mailbox._load_recipient_key", return_value=None):
            with pytest.raises(Exception):
                send_message("opus@chef.skworld", SECRET)

        # No plaintext leaked into the peer inbox on the failed send.
        home = scaffold(agent="lumina")  # re-scaffold is idempotent
        skhome = Path(home["inbox"]).parents[2]
        for p in skhome.rglob("*"):
            if p.is_file():
                assert SECRET.encode("utf-8") not in p.read_bytes()


class TestIdempotency:
    def test_already_sealed_pqdm_body_not_double_encrypted(
        self, cluster_env, signing_patch
    ):
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message
        from skcomms.mailbox import _is_already_sealed  # noqa: F401 (must exist)

        scaffold(agent="lumina")
        sealed_body = "pqdm1:x25519-mlkem768:QUJDRA=="
        result = send_message("opus@chef.skworld", sealed_body)

        peer_path = Path(result["peer_inbox_path"])
        raw = peer_path.read_bytes()
        # An already-sealed body is confidential on its own; the mailbox must NOT
        # wrap-encrypt it again at rest — the signed envelope stays readable.
        from skcomms.envelope import SignedEnvelope

        signed = SignedEnvelope.from_bytes(raw)
        assert signed.envelope.body == sealed_body

        # Same for the sender's outbox record: the body is already ciphertext,
        # so the record is kept as a plain SignedEnvelope (no double wrap).
        out_signed = SignedEnvelope.from_bytes(Path(result["outbox_path"]).read_bytes())
        assert out_signed.envelope.body == sealed_body


class TestOutboxSealedAtRest:
    """The sender's outbox record lives in the Syncthing-published operator
    subtree (SYNCTHING_TOPOLOGY.md section 2), so it must be sealed too."""

    def test_outbox_record_is_not_plaintext(self, cluster_env, signing_patch):
        from skcomms.envelope import SignedEnvelope
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message

        scaffold(agent="lumina")
        result = send_message("opus@chef.skworld", SECRET)

        raw = Path(result["outbox_path"]).read_bytes()
        assert SECRET.encode("utf-8") not in raw, "outbox record written in plaintext!"
        with pytest.raises(Exception):
            SignedEnvelope.from_bytes(raw)

    def test_read_outbox_recovers_and_verifies(self, cluster_env, signing_patch):
        from skcomms.home import scaffold
        from skcomms.mailbox import read_outbox, send_message

        scaffold(agent="lumina")
        send_message("opus@chef.skworld", SECRET)

        records = read_outbox(agent="lumina")
        assert len(records) == 1
        env, verification = records[0]
        assert env.body == SECRET
        assert env.to_fqid == "opus@chef.skworld"
        assert verification.valid, verification.reason

    def test_plaintext_opt_out_env_var(self, cluster_env, signing_patch, monkeypatch):
        """SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT=1 keeps the legacy readable outbox
        record (debug escape hatch); the PEER inbox drop stays sealed."""
        from skcomms.envelope import SignedEnvelope
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message

        monkeypatch.setenv("SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT", "1")
        scaffold(agent="lumina")
        result = send_message("opus@chef.skworld", SECRET)

        out_signed = SignedEnvelope.from_bytes(Path(result["outbox_path"]).read_bytes())
        assert out_signed.envelope.body == SECRET
        # Opt-out must never weaken the peer inbox drop.
        peer_raw = Path(result["peer_inbox_path"]).read_bytes()
        assert SECRET.encode("utf-8") not in peer_raw


class TestRecipientKeyResolution:
    """The at-rest seal must be to a key the RECIPIENT actually holds.

    The old code sealed with _load_verifier_key, whose unconditional fallback
    to the LOCAL operator key (~/.capauth/identity/public.asc) meant a send to
    a remote operator's agent was silently encrypted to the wrong key. These
    tests prove that behavior is dead."""

    def test_remote_operator_without_pinned_key_fails_closed(
        self, cluster_env, signing_patch_real_recipient_lookup, monkeypatch, tmp_path
    ):
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message

        # Plant a DECOY local operator key in a fake HOME. The old fallback
        # would have sealed to it; the new resolution must refuse instead.
        fake_home = tmp_path / "fakehome"
        ident_dir = fake_home / ".capauth" / "identity"
        ident_dir.mkdir(parents=True)
        _, decoy_pub = signing_patch_real_recipient_lookup
        (ident_dir / "public.asc").write_text(decoy_pub)
        monkeypatch.setenv("HOME", str(fake_home))

        scaffold(agent="lumina")
        with pytest.raises(Exception):
            send_message("zz-no-such-agent@stranger.otherrealm", SECRET)

        # And nothing was written anywhere in the tree.
        from skcomms.home import skcomms_home

        for p in skcomms_home().rglob("*"):
            if p.is_file():
                assert SECRET.encode("utf-8") not in p.read_bytes()

    def test_remote_operator_uses_pinned_peer_store_key(
        self, cluster_env, signing_patch_real_recipient_lookup
    ):
        from skcomms.home import scaffold, skcomms_home
        from skcomms.mailbox import send_message

        priv, pub = signing_patch_real_recipient_lookup
        peers_dir = skcomms_home() / "peers"
        peers_dir.mkdir(parents=True, exist_ok=True)
        (peers_dir / "zz-no-such-agent@stranger.otherrealm.asc").write_text(pub)

        scaffold(agent="lumina")
        result = send_message("zz-no-such-agent@stranger.otherrealm", SECRET)

        raw = Path(result["peer_inbox_path"]).read_bytes()
        assert SECRET.encode("utf-8") not in raw

        # Sealed to the pinned key: the holder of that key can open it.
        from skcomms.crypto import EnvelopeCrypto
        from skcomms.mailbox import _unseal_at_rest

        crypto = EnvelopeCrypto(private_key_armor=priv, passphrase="")
        signed = _unseal_at_rest(raw, crypto)
        assert signed.envelope.body == SECRET

    def test_same_operator_may_use_operator_key_fallback(
        self, cluster_env, signing_patch_real_recipient_lookup, monkeypatch, tmp_path
    ):
        """Legacy same-operator layouts (agents sharing the operator keypair)
        still work: the fallback applies ONLY when operator.realm matches."""
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message

        fake_home = tmp_path / "fakehome"
        ident_dir = fake_home / ".capauth" / "identity"
        ident_dir.mkdir(parents=True)
        _, pub = signing_patch_real_recipient_lookup
        (ident_dir / "public.asc").write_text(pub)
        monkeypatch.setenv("HOME", str(fake_home))

        scaffold(agent="lumina")
        # cluster fixture is operator=chef realm=skworld, so this matches.
        result = send_message("zz-no-such-agent@chef.skworld", SECRET)
        raw = Path(result["peer_inbox_path"]).read_bytes()
        assert SECRET.encode("utf-8") not in raw
