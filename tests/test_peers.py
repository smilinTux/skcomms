"""Tests for the peer-connectivity layer (T8, ``1314e0ff``).

``skcomms peers add <peer-fqid> --syncthing-device-id <id> --pubkey <path>``
wires a peer's Syncthing device id + PGP public key into the realm comms layer.

This suite verifies the :mod:`skcomms.peers` module + its CLI:

    - add_peer with a valid pubkey records device id + the derived PGP
      fingerprint (pure-pgpy, no real keyring) and TOFU-binds the fqid.
    - an invalid fqid shape is rejected.
    - re-adding the SAME fqid+device+fingerprint is an idempotent no-op.
    - re-adding with a CONFLICTING (different) fingerprint is REFUSED — the
      stored binding is never silently rebound.
    - peers.json lands in the documented schema under SKCOMMS_HOME.
    - the ``--via-registry`` flag is a clear "requires T11" stub (not wired).

Standalone: tmp SKCOMMS_HOME + in-process pgpy-generated pubkeys written to
tmp files. No real keyring / Syncthing.
"""

from __future__ import annotations

import json

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


def _fp(pub_armor: str) -> str:
    import pgpy

    key, _ = pgpy.PGPKey.from_blob(pub_armor)
    return str(key.fingerprint).replace(" ", "").upper()


@pytest.fixture(scope="module")
def opus_keys():
    return _gen_key("opus <opus@casey.douno>")


@pytest.fixture(scope="module")
def other_keys():
    """A second, distinct key — used to force a fingerprint CONFLICT."""
    return _gen_key("imposter <opus@casey.douno>")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def _write_pub(tmp_path, name: str, armor: str):
    p = tmp_path / name
    p.write_text(armor, encoding="utf-8")
    return p


PEER_FQID = "opus@casey.douno"
DEVICE_ID = "ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678"


# ---------------------------------------------------------------------------
# add_peer (happy path)
# ---------------------------------------------------------------------------


class TestAddPeer:
    def test_add_records_device_and_fingerprint(self, home, tmp_path, opus_keys):
        from skcomms.peers import add_peer

        _, pub = opus_keys
        pub_path = _write_pub(tmp_path, "opus.asc", pub)

        rec = add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=pub_path)

        assert rec["fqid"] == PEER_FQID
        assert rec["syncthing_device_id"] == DEVICE_ID
        assert rec["fingerprint"] == _fp(pub)
        assert rec["added_at"]
        assert rec["status"] in ("trust_new", "trust_match")

    def test_add_tofu_binds_fqid_to_fingerprint(self, home, tmp_path, opus_keys):
        from skcomms.peers import add_peer
        from skcomms.tofu import fingerprint_for

        _, pub = opus_keys
        pub_path = _write_pub(tmp_path, "opus.asc", pub)
        add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=pub_path)

        assert fingerprint_for(PEER_FQID) == _fp(pub)

    def test_peers_json_schema(self, home, tmp_path, opus_keys):
        from skcomms.peers import add_peer, peers_path

        _, pub = opus_keys
        pub_path = _write_pub(tmp_path, "opus.asc", pub)
        add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=pub_path)

        assert peers_path() == home / "peers.json"
        data = json.loads(peers_path().read_text())
        assert set(data.keys()) == {"peers"}
        assert PEER_FQID in data["peers"]
        entry = data["peers"][PEER_FQID]
        assert set(entry.keys()) == {"syncthing_device_id", "fingerprint", "added_at"}
        assert entry["syncthing_device_id"] == DEVICE_ID
        assert entry["fingerprint"] == _fp(pub)


# ---------------------------------------------------------------------------
# edge / failure modes
# ---------------------------------------------------------------------------


class TestAddPeerFailures:
    def test_invalid_fqid_rejected(self, home, tmp_path, opus_keys):
        from skcomms.peers import add_peer

        _, pub = opus_keys
        pub_path = _write_pub(tmp_path, "opus.asc", pub)

        with pytest.raises(ValueError):
            add_peer("not-an-fqid", syncthing_device_id=DEVICE_ID, pubkey_path=pub_path)

    def test_idempotent_same_add(self, home, tmp_path, opus_keys):
        from skcomms.peers import add_peer, list_peers

        _, pub = opus_keys
        pub_path = _write_pub(tmp_path, "opus.asc", pub)

        first = add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=pub_path)
        second = add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=pub_path)

        # idempotent — same binding, single entry, added_at preserved
        assert second["fingerprint"] == first["fingerprint"]
        assert second["added_at"] == first["added_at"]
        peers = list_peers()
        assert len(peers) == 1

    def test_conflicting_fingerprint_refused(
        self, home, tmp_path, opus_keys, other_keys
    ):
        from skcomms.peers import add_peer, list_peers
        from skcomms.tofu import fingerprint_for

        _, pub = opus_keys
        _, other_pub = other_keys
        good = _write_pub(tmp_path, "opus.asc", pub)
        bad = _write_pub(tmp_path, "imposter.asc", other_pub)

        add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=good)

        with pytest.raises(ValueError) as exc:
            add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=bad)
        assert "conflict" in str(exc.value).lower()

        # the original binding MUST be untouched (no silent rebind)
        assert fingerprint_for(PEER_FQID) == _fp(pub)
        peers = list_peers()
        assert peers[PEER_FQID]["fingerprint"] == _fp(pub)

    def test_changing_device_id_same_key_updates(self, home, tmp_path, opus_keys):
        from skcomms.peers import add_peer

        _, pub = opus_keys
        pub_path = _write_pub(tmp_path, "opus.asc", pub)

        add_peer(PEER_FQID, syncthing_device_id=DEVICE_ID, pubkey_path=pub_path)
        new_dev = "ZZZZZZZ-2345678-ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678"
        rec = add_peer(PEER_FQID, syncthing_device_id=new_dev, pubkey_path=pub_path)
        assert rec["syncthing_device_id"] == new_dev


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestPeersCLI:
    def test_cli_add_and_show(self, home, tmp_path, opus_keys):
        from click.testing import CliRunner

        from skcomms.cli import main

        _, pub = opus_keys
        pub_path = _write_pub(tmp_path, "opus.asc", pub)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "peers",
                "add",
                PEER_FQID,
                "--syncthing-device-id",
                DEVICE_ID,
                "--pubkey",
                str(pub_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert PEER_FQID in result.output

        show = runner.invoke(main, ["peers", "show", PEER_FQID, "--json-out"])
        assert show.exit_code == 0, show.output
        entry = json.loads(show.output)
        assert entry["fingerprint"] == _fp(pub)
        assert entry["syncthing_device_id"] == DEVICE_ID

    def test_cli_conflict_exits_nonzero(
        self, home, tmp_path, opus_keys, other_keys
    ):
        from click.testing import CliRunner

        from skcomms.cli import main

        _, pub = opus_keys
        _, other_pub = other_keys
        good = _write_pub(tmp_path, "opus.asc", pub)
        bad = _write_pub(tmp_path, "imposter.asc", other_pub)

        runner = CliRunner()
        runner.invoke(
            main,
            ["peers", "add", PEER_FQID, "--syncthing-device-id", DEVICE_ID,
             "--pubkey", str(good)],
        )
        conflict = runner.invoke(
            main,
            ["peers", "add", PEER_FQID, "--syncthing-device-id", DEVICE_ID,
             "--pubkey", str(bad)],
        )
        assert conflict.exit_code != 0
        assert "conflict" in conflict.output.lower()

    def test_cli_via_registry_is_t11_stub(self, home):
        from click.testing import CliRunner

        from skcomms.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main, ["peers", "add", PEER_FQID, "--via-registry"]
        )
        assert result.exit_code != 0
        assert "t11" in result.output.lower() or "registry" in result.output.lower()
