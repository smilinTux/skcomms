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
        # Override the verifier-key lookup to report NO key for the recipient.
        with patch("skcomms.mailbox._load_verifier_key", return_value=None):
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
