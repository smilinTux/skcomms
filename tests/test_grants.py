"""Tests for cross-operator collection consent tokens (T10, ``a68c54ce``).

skcomms is the PRODUCER of recall-consent tokens; skmemory T9 is the consumer
that reads ``${SKCOMMS_HOME:-~/.skcomms}/recall_collections_consent.json``.
This test suite verifies:

    - mint_grant produces a token whose PGP signature over canonical_bytes
      verifies against the granter's key.
    - verify_grant rejects a tampered token, a wrong-key signature, and an
      expired token.
    - accept_grant writes the consent file in the EXACT schema T9 reads, is
      idempotent (dedup by collection+granted_to+granted_by), and list_grants
      reports held grants.

Standalone: tmp SKCOMMS_HOME + in-process pgpy keys, no live transports.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
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
def chef_keys():
    return _gen_key("chef <lumina@chef.skworld>")


@pytest.fixture(scope="module")
def casey_keys():
    return _gen_key("casey <opus@casey.douno>")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture
def granter_patch(chef_keys):
    """Patch identity + signer so 'self' is lumina@chef.skworld with chef's key."""
    priv, pub = chef_keys
    from skcomms.signing import EnvelopeSigner

    ident = {
        "agent": "lumina",
        "fqid": "lumina@chef.skworld",
        "fingerprint": EnvelopeSigner(priv, "").fingerprint,
    }
    with patch("skcomms.grants.resolve_self_identity", return_value=ident), patch(
        "skcomms.grants._load_signer", return_value=EnvelopeSigner(priv, "")
    ):
        yield priv, pub


def _iso_in(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# mint + verify (happy path)
# ---------------------------------------------------------------------------


class TestMintVerify:
    def test_mint_produces_verifiable_token(self, home, granter_patch):
        from skcomms.grants import mint_grant, verify_grant

        priv, pub = granter_patch
        token = mint_grant(
            collection="chef.skworld/journal",
            to_fqid="opus@casey.douno",
            expires="30d",
        )
        assert token["collection"] == "chef.skworld/journal"
        assert token["granted_to"] == "opus@casey.douno"
        assert token["granted_by"] == "lumina@chef.skworld"
        assert token["signature"]
        # expires resolved to an iso8601 string in the future
        exp = datetime.fromisoformat(token["expires"])
        assert exp > datetime.now(timezone.utc)

        result = verify_grant(token, pubkey=pub)
        assert result.valid, result.reason

    def test_canonical_bytes_excludes_signature(self, home, granter_patch):
        from skcomms.grants import ConsentToken

        tok = ConsentToken(
            collection="chef.skworld/journal",
            granted_to="opus@casey.douno",
            granted_by="lumina@chef.skworld",
            expires=_iso_in(30),
            signature="THIS-SHOULD-NOT-AFFECT-CANONICAL",
        )
        cb1 = tok.canonical_bytes()
        tok2 = tok.model_copy(update={"signature": "different"})
        assert tok2.canonical_bytes() == cb1


# ---------------------------------------------------------------------------
# verify failure modes
# ---------------------------------------------------------------------------


class TestVerifyFailures:
    def test_tampered_token_rejected(self, home, granter_patch):
        from skcomms.grants import mint_grant, verify_grant

        _, pub = granter_patch
        token = mint_grant("chef.skworld/journal", "opus@casey.douno", "30d")
        # tamper: widen the collection after signing
        token["collection"] = "chef.skworld/secrets"
        result = verify_grant(token, pubkey=pub)
        assert not result.valid

    def test_wrong_key_rejected(self, home, granter_patch, casey_keys):
        from skcomms.grants import mint_grant, verify_grant

        token = mint_grant("chef.skworld/journal", "opus@casey.douno", "30d")
        _, casey_pub = casey_keys  # not the signer's key
        result = verify_grant(token, pubkey=casey_pub)
        assert not result.valid

    def test_expired_token_rejected(self, home, granter_patch):
        from skcomms.grants import mint_grant, verify_grant

        _, pub = granter_patch
        # expires in the past
        token = mint_grant(
            "chef.skworld/journal", "opus@casey.douno", _iso_in(-1)
        )
        result = verify_grant(token, pubkey=pub)
        assert not result.valid
        assert "expired" in result.reason.lower()


# ---------------------------------------------------------------------------
# accept + list (T9-shaped consent file)
# ---------------------------------------------------------------------------


class TestAcceptAndList:
    def test_accept_writes_t9_schema(self, home, granter_patch):
        from skcomms.grants import accept_grant, mint_grant

        _, pub = granter_patch
        token = mint_grant("chef.skworld/journal", "opus@casey.douno", "30d")
        accept_grant(token, pubkey=pub)

        consent_file = home / "recall_collections_consent.json"
        assert consent_file.exists()
        data = json.loads(consent_file.read_text())
        # EXACT T9 schema: top-level {"tokens": [ {...} ]}
        assert set(data.keys()) == {"tokens"}
        assert isinstance(data["tokens"], list)
        assert len(data["tokens"]) == 1
        landed = data["tokens"][0]
        assert set(landed.keys()) == {
            "collection",
            "granted_to",
            "granted_by",
            "expires",
            "signature",
        }
        assert landed["collection"] == "chef.skworld/journal"
        assert landed["granted_to"] == "opus@casey.douno"
        assert landed["granted_by"] == "lumina@chef.skworld"
        assert landed["signature"]

    def test_accept_is_idempotent(self, home, granter_patch):
        from skcomms.grants import accept_grant, list_grants, mint_grant

        _, pub = granter_patch
        token = mint_grant("chef.skworld/journal", "opus@casey.douno", "30d")
        accept_grant(token, pubkey=pub)
        accept_grant(token, pubkey=pub)  # same collection+to+by -> dedup

        grants = list_grants()
        assert len(grants) == 1

    def test_accept_rejects_invalid(self, home, granter_patch, casey_keys):
        from skcomms.grants import accept_grant, list_grants, mint_grant

        token = mint_grant("chef.skworld/journal", "opus@casey.douno", "30d")
        _, casey_pub = casey_keys
        with pytest.raises(ValueError):
            accept_grant(token, pubkey=casey_pub)  # wrong key
        assert list_grants() == []

    def test_list_shows_distinct_grants(self, home, granter_patch):
        from skcomms.grants import accept_grant, list_grants, mint_grant

        _, pub = granter_patch
        accept_grant(
            mint_grant("chef.skworld/journal", "opus@casey.douno", "30d"), pubkey=pub
        )
        accept_grant(
            mint_grant("chef.skworld/notes", "opus@casey.douno", "30d"), pubkey=pub
        )
        grants = list_grants()
        collections = {g["collection"] for g in grants}
        assert collections == {"chef.skworld/journal", "chef.skworld/notes"}


# ---------------------------------------------------------------------------
# CLI (producer end-to-end: grant -> accept -> list)
# ---------------------------------------------------------------------------


class TestGrantCLI:
    def test_mint_accept_list_roundtrip(self, home, granter_patch):
        from click.testing import CliRunner

        from skcomms.cli import main

        priv, pub = granter_patch
        # TOFU-record the granter's pubkey so accept (which resolves the key
        # from the store) can verify — mirrors importing a peer before accept.
        from skcomms.signing import EnvelopeSigner
        from skcomms.tofu import record_fingerprint

        record_fingerprint(
            "lumina@chef.skworld", EnvelopeSigner(priv, "").fingerprint, pubkey=pub
        )

        runner = CliRunner()
        # mint to stdout
        mint = runner.invoke(
            main,
            [
                "grant",
                "collection-read",
                "--collection",
                "chef.skworld/journal",
                "--to",
                "opus@casey.douno",
                "--expires",
                "30d",
            ],
        )
        assert mint.exit_code == 0, mint.output
        token = json.loads(mint.output)
        assert token["granted_by"] == "lumina@chef.skworld"

        # accept from stdin
        accept = runner.invoke(
            main, ["grants", "accept", "-"], input=json.dumps(token)
        )
        assert accept.exit_code == 0, accept.output

        # the consent file lands in T9 schema
        data = json.loads((home / "recall_collections_consent.json").read_text())
        assert data["tokens"][0]["collection"] == "chef.skworld/journal"

        # list (json) reports the held grant
        listed = runner.invoke(main, ["grants", "list", "--json-out"])
        assert listed.exit_code == 0, listed.output
        assert json.loads(listed.output)[0]["collection"] == "chef.skworld/journal"
