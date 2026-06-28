"""Realm-operator key pin → verifier (so any node verifies a realm's directory)."""
from pathlib import Path
from skcomms.skfed_resolve import operator_pin_path, realm_verifier, default_http_get


def test_operator_pin_path_under_skfed(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    p = operator_pin_path("skworld")
    assert p.name == "skworld.asc"
    assert "operators" in str(p)


def test_realm_verifier_none_when_unpinned(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    assert realm_verifier("skworld") is None


def test_realm_verifier_loads_pinned_pubkey(monkeypatch, tmp_path):
    # When a realm's operator pubkey is pinned, realm_verifier builds a verifier
    # from it. (The sign/verify roundtrip is covered by test_skfed_directory and
    # the live directory proof; here we assert the pin is loaded.)
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    import pgpy
    from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                                PubKeyAlgorithm, SymmetricKeyAlgorithm)
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("op")
    key.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256], compression=[CompressionAlgorithm.ZLIB])
    pin = operator_pin_path("skworld"); pin.parent.mkdir(parents=True, exist_ok=True)
    pin.write_text(str(key.pubkey))
    v = realm_verifier("skworld")
    assert v is not None
