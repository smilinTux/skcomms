"""Tests for the FQID-aware mailbox: send / inbox / peers (T6, ``ff0b2c15``).

Covers:
    - send_message builds + signs an Envelope v1 and drops it in the
      sender's outbox AND the peer's inbox.
    - read_inbox reads + verifies SignedEnvelopes from the inbox.
    - a tampered inbox envelope is flagged (verified=False).
    - list_peers enumerates known peers in the ~/.skcapstone/skcomms tree.

No live transports — everything operates on a tmp SKCOMMS_HOME with
in-process PGP keys.
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
    """Tmp SKCOMMS_HOME + fixture cluster.json (realm=skworld, operator=chef)."""
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
    """Patch the mailbox signer/identity so no real CapAuth keys are needed."""
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


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------


class TestSend:
    def test_writes_signed_envelope_to_outbox_and_peer_inbox(
        self, cluster_env, signing_patch
    ):
        from skcomms.home import scaffold
        from skcomms.mailbox import send_message

        scaffold(agent="lumina")
        result = send_message("opus@chef.skworld", "hello opus")

        # sender outbox record exists; it is sealed at rest (the operator
        # subtree, including outbox/, is Syncthing-published to peers) and is
        # read back via read_outbox below.
        out_path = Path(result["outbox_path"])
        assert out_path.exists()
        # peer inbox drop
        peer_path = Path(result["peer_inbox_path"])
        assert peer_path.exists()
        assert peer_path.parent.name == "inbox"
        assert "opus" in str(peer_path)

        from skcomms.envelope import SignedEnvelope
        from skcomms.mailbox import read_outbox

        # SECURITY: BOTH drops live in the Syncthing-replicated tree, so BOTH
        # must be sealed at rest: never a plaintext body, never a bare
        # readable SignedEnvelope.
        for path in (out_path, peer_path):
            raw = path.read_bytes()
            assert b"hello opus" not in raw
            with pytest.raises(Exception):
                SignedEnvelope.from_bytes(raw)

        # The sender reads its own record back through read_outbox.
        records = read_outbox(agent="lumina")
        assert len(records) == 1
        env, verification = records[0]
        assert env.from_fqid == "lumina@chef.skworld"
        assert env.to_fqid == "opus@chef.skworld"
        assert env.body == "hello opus"
        assert verification.valid, verification.reason

    def test_invalid_fqid_rejected(self, cluster_env, signing_patch):
        from skcomms.mailbox import send_message

        with pytest.raises(ValueError):
            send_message("not-an-fqid", "oops")


# ---------------------------------------------------------------------------
# inbox
# ---------------------------------------------------------------------------


class TestInbox:
    def test_reads_and_verifies(self, cluster_env, signing_patch):
        from skcomms.home import scaffold
        from skcomms.mailbox import read_inbox, send_message

        scaffold(agent="lumina")
        # send to self so it lands in lumina's own inbox (same key verifies)
        send_message("lumina@chef.skworld", "note to self")

        items = read_inbox(agent="lumina")
        assert len(items) == 1
        env, verification = items[0]
        assert env.body == "note to self"
        assert verification.valid, verification.reason

    def test_tampered_inbox_flagged(self, cluster_env, signing_patch):
        from skcomms.home import scaffold
        from skcomms.mailbox import read_inbox, send_message

        info = scaffold(agent="lumina")
        send_message("lumina@chef.skworld", "original")

        # The inbox file is now SEALED at rest. Unseal it, tamper the signed
        # envelope body, then re-seal so read_inbox decrypts a tampered-but-
        # signed envelope and the signature check flags it.
        inbox_files = list(Path(info["inbox"]).glob("*.json"))
        assert inbox_files
        from skcomms.mailbox import _seal_for_recipient, _unseal_at_rest
        from skcomms.crypto import EnvelopeCrypto

        priv, pub = signing_patch
        reader_crypto = EnvelopeCrypto(private_key_armor=priv, passphrase="")
        signed = _unseal_at_rest(inbox_files[0].read_bytes(), reader_crypto)
        tampered_env = signed.envelope.model_copy(update={"body": "EVIL"})
        tampered = signed.model_copy(update={"envelope": tampered_env})
        inbox_files[0].write_bytes(_seal_for_recipient(tampered, pub))

        items = read_inbox(agent="lumina")
        assert len(items) == 1
        env, verification = items[0]
        assert env.body == "EVIL"
        assert not verification.valid


# ---------------------------------------------------------------------------
# peers
# ---------------------------------------------------------------------------


class TestPeers:
    def test_lists_known_peers(self, cluster_env, signing_patch):
        from skcomms.home import scaffold
        from skcomms.mailbox import list_peers, send_message

        scaffold(agent="lumina")
        send_message("opus@chef.skworld", "hi")
        send_message("jarvis@chef.skworld", "yo")

        peers = list_peers()
        fqids = {p["fqid"] for p in peers}
        # the two recipients now have inbox dirs in the tree
        assert "opus@chef.skworld" in fqids
        assert "jarvis@chef.skworld" in fqids
        # self should not be listed as a peer
        assert "lumina@chef.skworld" not in fqids
