"""Tests for the sovereign per-realm SKFed discovery directory (skfed_directory).

A ``SignedDirectory`` maps ``<agent>@<operator>.<realm>`` FQIDs to live
endpoints (inbox/prekey URLs, DID, caps). It is capauth-signed by the realm
operator (via :class:`skcomms.signing.EnvelopeSigner`) so anyone can fetch it,
verify it, and resolve an agent with NO local peer config — and anyone can run
their own realm directory.

PGP keys are generated in-process via pgpy (no live CapAuth).
"""

from __future__ import annotations

import pytest


# --- in-process key fixtures (mirror tests/test_api_federation_inbox.py) ----


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
def operator_keys():
    """The realm operator's signing key (signs the directory)."""
    return _gen_key("chef <chef@chef.skworld>")


@pytest.fixture(scope="module")
def attacker_keys():
    return _gen_key("evil <evil@attacker.realm>")


REALM = "skworld"
OPERATOR = "chef"
JARVIS_FQID = "jarvis@chef.skworld"
LUMINA_FQID = "lumina@chef.skworld"


def _entry(fqid, inbox="https://node.ts.net/api/v1/inbox", prekey="https://node.ts.net/api/v1/prekey"):
    from skcomms.skfed_directory import DirectoryEntry

    return DirectoryEntry(
        fqid=fqid,
        inbox_url=inbox,
        prekey_url=prekey,
        did=f"did:skfed:{fqid}",
        caps=["dm", "files"],
    )


def _build_signed(operator_priv, entries):
    from skcomms.signing import EnvelopeSigner
    from skcomms.skfed_directory import SignedDirectory

    signer = EnvelopeSigner(operator_priv)
    return SignedDirectory.build(
        realm=REALM, operator=OPERATOR, entries=entries, signer=signer
    )


# --- model: build / sign / verify -----------------------------------------


def test_build_and_verify_roundtrip(operator_keys):
    priv, pub = operator_keys
    from skcomms.signing import EnvelopeVerifier

    sd = _build_signed(priv, [_entry(JARVIS_FQID), _entry(LUMINA_FQID)])
    assert sd.sig
    assert sd.signer_fingerprint

    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub)
    assert sd.verify(verifier) is True


def test_verify_fails_for_wrong_key(operator_keys, attacker_keys):
    priv, _pub = operator_keys
    _apriv, apub = attacker_keys
    from skcomms.signing import EnvelopeVerifier

    sd = _build_signed(priv, [_entry(JARVIS_FQID)])
    verifier = EnvelopeVerifier()
    # Register the WRONG (attacker) key under the operator identity.
    verifier.add_key(OPERATOR, apub)
    assert sd.verify(verifier) is False


def test_verify_detects_tamper(operator_keys):
    priv, pub = operator_keys
    from skcomms.signing import EnvelopeVerifier
    from skcomms.skfed_directory import DirectoryEntry

    sd = _build_signed(priv, [_entry(JARVIS_FQID)])
    # Tamper: point jarvis at an attacker inbox after signing.
    sd.entries[0] = DirectoryEntry(
        fqid=JARVIS_FQID,
        inbox_url="https://attacker.example/api/v1/inbox",
        prekey_url=sd.entries[0].prekey_url,
    )
    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub)
    assert sd.verify(verifier) is False


def test_to_bytes_from_bytes_roundtrip(operator_keys):
    priv, pub = operator_keys
    from skcomms.signing import EnvelopeVerifier
    from skcomms.skfed_directory import SignedDirectory

    sd = _build_signed(priv, [_entry(JARVIS_FQID)])
    raw = sd.to_bytes()
    again = SignedDirectory.from_bytes(raw)
    assert again.realm == REALM
    assert again.operator == OPERATOR
    assert again.entries[0].fqid == JARVIS_FQID

    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub)
    # Signature survives serialization.
    assert again.verify(verifier) is True


def test_upsert_adds_then_replaces(operator_keys):
    priv, _pub = operator_keys
    from skcomms.skfed_directory import SignedDirectory

    sd = SignedDirectory(realm=REALM, operator=OPERATOR, entries=[])
    sd.upsert(_entry(JARVIS_FQID, inbox="https://a/api/v1/inbox"))
    assert len(sd.entries) == 1
    sd.upsert(_entry(LUMINA_FQID))
    assert len(sd.entries) == 2
    # Re-announce jarvis with a new inbox -> replace in place, no dup.
    sd.upsert(_entry(JARVIS_FQID, inbox="https://b/api/v1/inbox"))
    assert len(sd.entries) == 2
    jarvis = [e for e in sd.entries if e.fqid == JARVIS_FQID][0]
    assert jarvis.inbox_url == "https://b/api/v1/inbox"


# --- persistence -----------------------------------------------------------


def test_persist_and_load(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms import skfed_directory as sfd
    from skcomms.signing import EnvelopeVerifier

    sd = _build_signed(priv, [_entry(JARVIS_FQID)])
    sfd.save_directory(sd)
    assert sfd.directory_path().exists()
    assert sfd.directory_path() == tmp_path / "skfed" / "directory.json"

    loaded = sfd.load_directory()
    assert loaded is not None
    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub)
    assert loaded.verify(verifier) is True


def test_load_directory_absent_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms import skfed_directory as sfd

    assert sfd.load_directory() is None


def test_upsert_entry_signs_and_persists(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms import skfed_directory as sfd
    from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

    signer = EnvelopeSigner(priv)
    sfd.upsert_entry(_entry(JARVIS_FQID), signer=signer)
    sfd.upsert_entry(_entry(LUMINA_FQID), signer=signer)

    loaded = sfd.load_directory()
    assert {e.fqid for e in loaded.entries} == {JARVIS_FQID, LUMINA_FQID}
    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub)
    assert loaded.verify(verifier) is True


def test_publish_self_to_realm_directory(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms import skfed_directory as sfd
    from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

    signer = EnvelopeSigner(priv)
    # Inject the node signer so we don't touch the real on-disk key.
    monkeypatch.setattr(sfd, "load_node_signer", lambda agent=None: signer)

    sd = sfd.publish_self_to_realm_directory(
        JARVIS_FQID,
        inbox_url="https://jarvis.ts.net/api/v1/inbox",
        prekey_url="https://jarvis.ts.net/api/v1/prekey",
    )
    assert any(e.fqid == JARVIS_FQID for e in sd.entries)

    loaded = sfd.load_directory()
    jarvis = [e for e in loaded.entries if e.fqid == JARVIS_FQID][0]
    assert jarvis.inbox_url == "https://jarvis.ts.net/api/v1/inbox"
    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub)
    assert loaded.verify(verifier) is True
