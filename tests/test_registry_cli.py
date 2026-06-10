"""CLI tests for the T11 realm peer registry wiring (``e1dea61f``).

Covers:
    - ``skcomms registry list`` / ``registry resolve <fqid>`` inspect the
      resolver (default: the sovereign syncthing-shared backend).
    - ``skcomms peers add <fqid> --via-registry`` resolves the peer via the
      registry, then wires it through the T8 ``add_peer`` path (TOFU + device
      id), instead of the old "requires T11" stub.
    - ``skcomms peers add <fqid> --tailscale <node>`` stores the tailscale hint.
    - a registry that can't resolve errors clearly + non-zero exit.

Standalone: tmp SKCOMMS_HOME + a tmp ``_realm/peers.json`` carrying an
in-process pgpy pubkey so the TOFU bind is real but keyring-free.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner


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


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


PEER_FQID = "opus@casey.douno"
DEVICE_ID = "ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678-ABCDEF1-2345678"


def _write_realm(home, pub_armor):
    realm_dir = home / "_realm"
    realm_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "peers": {
            PEER_FQID: {
                "fqid": PEER_FQID,
                "operator": "casey",
                "pgp_fingerprint": _fp(pub_armor),
                "syncthing_device_id": DEVICE_ID,
                "pubkey": pub_armor,
            }
        }
    }
    (realm_dir / "peers.json").write_text(json.dumps(data), encoding="utf-8")


class TestRegistryInspectCLI:
    def test_registry_list(self, home, opus_keys):
        _, pub = opus_keys
        _write_realm(home, pub)
        from skcomms.cli import main

        result = CliRunner().invoke(main, ["registry", "list", "--json-out"])
        assert result.exit_code == 0, result.output
        recs = json.loads(result.output)
        assert any(r["fqid"] == PEER_FQID for r in recs)

    def test_registry_resolve(self, home, opus_keys):
        _, pub = opus_keys
        _write_realm(home, pub)
        from skcomms.cli import main

        result = CliRunner().invoke(
            main, ["registry", "resolve", PEER_FQID, "--json-out"]
        )
        assert result.exit_code == 0, result.output
        rec = json.loads(result.output)
        assert rec["fqid"] == PEER_FQID
        assert rec["syncthing_device_id"] == DEVICE_ID

    def test_registry_resolve_miss(self, home, opus_keys):
        _, pub = opus_keys
        _write_realm(home, pub)
        from skcomms.cli import main

        result = CliRunner().invoke(main, ["registry", "resolve", "ghost@nowhere.void"])
        assert result.exit_code != 0
        assert "could not resolve" in result.output.lower() or "no " in result.output.lower()


class TestPeersAddViaRegistryCLI:
    def test_via_registry_resolves_and_adds(self, home, opus_keys):
        _, pub = opus_keys
        _write_realm(home, pub)
        from skcomms.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["peers", "add", PEER_FQID, "--via-registry"])
        assert result.exit_code == 0, result.output
        assert PEER_FQID in result.output

        # it actually wired peers.json via the T8 add_peer path
        show = runner.invoke(main, ["peers", "show", PEER_FQID, "--json-out"])
        assert show.exit_code == 0, show.output
        entry = json.loads(show.output)
        assert entry["syncthing_device_id"] == DEVICE_ID
        assert entry["fingerprint"] == _fp(pub)

    def test_via_registry_unresolvable_errors(self, home, opus_keys):
        _, pub = opus_keys
        _write_realm(home, pub)  # only opus is in the realm file
        from skcomms.cli import main

        result = CliRunner().invoke(
            main, ["peers", "add", "ghost@nowhere.void", "--via-registry"]
        )
        assert result.exit_code != 0
        assert "resolve" in result.output.lower()


class TestPeersAddTailscaleCLI:
    def test_tailscale_node_stores_hint(self, home, opus_keys):
        _, pub = opus_keys
        # realm file gives us the pubkey+device so TOFU + add_peer succeed;
        # --tailscale just records the connectivity hint on top.
        _write_realm(home, pub)
        from skcomms.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["peers", "add", PEER_FQID, "--tailscale", "skcomms-opus-casey", "--via-registry"],
        )
        assert result.exit_code == 0, result.output
        assert "skcomms-opus-casey" in result.output
