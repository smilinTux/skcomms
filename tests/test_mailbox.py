"""Tests for the FQID-aware mailbox: send / inbox / peers (T6, ``ff0b2c15``).

Covers:
    - send_message builds + signs an Envelope v1 and drops it in the
      sender's outbox AND the peer's inbox.
    - read_inbox reads + verifies SignedEnvelopes from the inbox.
    - a tampered inbox envelope is flagged (verified=False).
    - list_peers enumerates known peers in the ~/.skcomms tree.

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
    ), patch("skcomms.mailbox._load_verifier_key", return_value=pub):
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

        # sender outbox copy
        out_path = Path(result["outbox_path"])
        assert out_path.exists()
        # peer inbox drop
        peer_path = Path(result["peer_inbox_path"])
        assert peer_path.exists()
        assert peer_path.parent.name == "inbox"
        assert "opus" in str(peer_path)

        from skcomms.envelope import SignedEnvelope

        signed = SignedEnvelope.from_bytes(peer_path.read_bytes())
        assert signed.envelope.from_fqid == "lumina@chef.skworld"
        assert signed.envelope.to_fqid == "opus@chef.skworld"
        assert signed.envelope.body == "hello opus"
        assert signed.is_signed

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

        # tamper with the persisted inbox envelope body
        inbox_files = list(Path(info["inbox"]).glob("*.json"))
        assert inbox_files
        from skcomms.envelope import SignedEnvelope

        signed = SignedEnvelope.from_bytes(inbox_files[0].read_bytes())
        tampered_env = signed.envelope.model_copy(update={"body": "EVIL"})
        tampered = signed.model_copy(update={"envelope": tampered_env})
        inbox_files[0].write_bytes(tampered.to_bytes())

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
