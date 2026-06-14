"""The WebRTC CapAuth key lookup must also find per-agent capauth/identity keys.

Reconciles the SDP-verify key path with the mailbox/TOFU layer (2026-06-11) so a
local agent's signed SDP (opus↔lumina) verifies — those keys live under
capauth/identity, which the legacy ~/.skcomms/keys + gpg lookup never searched.
"""
import pgpy
import pytest
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from skcomms.capauth_validator import _find_pubkey_by_fingerprint


def _make_key(name: str):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = pgpy.PGPUID.new(name, email=f"{name}@x.y")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return key


def test_finds_agent_pubkey_by_fingerprint(tmp_path):
    key = _make_key("opus")
    ident = tmp_path / "opus" / "capauth" / "identity"
    ident.mkdir(parents=True)
    (ident / "public.asc").write_text(str(key.pubkey), encoding="utf-8")

    armor = _find_pubkey_by_fingerprint(str(key.fingerprint), agents_root=tmp_path)
    assert armor is not None
    loaded, _ = pgpy.PGPKey.from_blob(armor)
    assert str(loaded.fingerprint) == str(key.fingerprint)


def test_returns_none_for_unknown_fingerprint(tmp_path):
    key = _make_key("opus")
    ident = tmp_path / "opus" / "capauth" / "identity"
    ident.mkdir(parents=True)
    (ident / "public.asc").write_text(str(key.pubkey), encoding="utf-8")

    assert _find_pubkey_by_fingerprint("0" * 40, agents_root=tmp_path) is None


def test_extra_globs_searched(tmp_path):
    key = _make_key("peer")
    peers = tmp_path / "peers"
    peers.mkdir()
    (peers / "peer@x.y.asc").write_text(str(key.pubkey), encoding="utf-8")

    armor = _find_pubkey_by_fingerprint(
        str(key.fingerprint),
        agents_root=tmp_path / "noexist",
        extra_globs=[str(peers / "*.asc")],
    )
    assert armor is not None
