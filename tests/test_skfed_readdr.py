"""Tests for skfed_readdr — re-seed the realm directory with NEUTRAL addresses.

The live SKFed directory advertises funnel FQDNs like
``https://cbrd21-laptop12thgenintelcore.tail204f0c.ts.net/api/v1/inbox`` —
which **leak the machine's hostname**. ``skfed_readdr`` loads the signed
directory, rewrites every leaky ``*.ts.net`` ``inbox_url`` / ``prekey_url`` to a
neutral custom domain (``fed-<agent>.skworld.io``), re-signs with the node key,
and persists — idempotently, with a dry-run that changes nothing.

PGP keys are generated in-process via pgpy (no live CapAuth), mirroring
``tests/test_skfed_directory.py``.
"""

from __future__ import annotations

import pytest


# --- in-process key fixtures (mirror tests/test_skfed_directory.py) ---------


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
    return _gen_key("chef <chef@chef.skworld>")


REALM = "skworld"
OPERATOR = "chef"
LUMINA_FQID = "lumina@chef.skworld"
JARVIS_FQID = "jarvis@chef.skworld"

# The leaky funnel host that leaks the machine hostname.
LEAKY_HOST = "cbrd21-laptop12thgenintelcore.tail204f0c.ts.net"


def _leaky_entry(fqid):
    from skcomms.skfed_directory import DirectoryEntry

    return DirectoryEntry(
        fqid=fqid,
        inbox_url=f"https://{LEAKY_HOST}/api/v1/inbox",
        prekey_url=f"https://{LEAKY_HOST}/api/v1/prekey",
        did=f"did:skfed:{fqid}",
        caps=["dm", "files"],
    )


def _signer(operator_priv):
    from skcomms.signing import EnvelopeSigner

    return EnvelopeSigner(operator_priv)


def _seed_directory(operator_priv, entries):
    from skcomms.skfed_directory import SignedDirectory

    return SignedDirectory.build(
        realm=REALM, operator=OPERATOR, entries=entries, signer=_signer(operator_priv)
    )


# --- pure helpers ----------------------------------------------------------


def test_agent_label_from_fqid():
    from skcomms.skfed_readdr import agent_label

    assert agent_label("lumina@chef.skworld") == "lumina"
    assert agent_label("Jarvis@chef.skworld") == "jarvis"


def test_neutral_host_for():
    from skcomms.skfed_readdr import neutral_host_for

    assert neutral_host_for(LUMINA_FQID) == "fed-lumina.skworld.io"
    assert (
        neutral_host_for(JARVIS_FQID, base_domain="example.org", prefix="node-")
        == "node-jarvis.example.org"
    )


def test_is_leaky_host():
    from skcomms.skfed_readdr import is_leaky_host

    assert is_leaky_host(LEAKY_HOST) is True
    assert is_leaky_host("node.tail204f0c.ts.net") is True
    assert is_leaky_host("fed-lumina.skworld.io") is False
    assert is_leaky_host("dir.skworld.io") is False


def test_rewrite_url_preserves_scheme_and_path():
    from skcomms.skfed_readdr import rewrite_url

    out = rewrite_url(
        "https://cbrd21-laptop.tail204f0c.ts.net:8443/api/v1/inbox?x=1",
        "fed-lumina.skworld.io",
    )
    # Host replaced; scheme + path + query preserved; leaky port dropped.
    assert out == "https://fed-lumina.skworld.io/api/v1/inbox?x=1"


# --- rewrite + re-sign -----------------------------------------------------


def test_reseed_rewrites_leaky_urls_and_resigns(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms import skfed_directory as sfd
    from skcomms import skfed_readdr as rd
    from skcomms.signing import EnvelopeVerifier

    sfd.save_directory(_seed_directory(priv, [_leaky_entry(LUMINA_FQID), _leaky_entry(JARVIS_FQID)]))

    result = rd.reseed_neutral_addresses(signer=_signer(priv), dry_run=False)

    # 2 entries x 2 url fields = 4 rewrites.
    assert len(result.changes) == 4
    assert result.signed is not None

    loaded = sfd.load_directory()
    lumina = loaded.get(LUMINA_FQID)
    jarvis = loaded.get(JARVIS_FQID)
    assert lumina.inbox_url == "https://fed-lumina.skworld.io/api/v1/inbox"
    assert lumina.prekey_url == "https://fed-lumina.skworld.io/api/v1/prekey"
    assert jarvis.inbox_url == "https://fed-jarvis.skworld.io/api/v1/inbox"
    # No leaky host survives anywhere.
    assert "ts.net" not in loaded.to_bytes().decode()

    # Re-signed directory still verifies under the operator key.
    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub)
    assert loaded.verify(verifier) is True


def test_dry_run_changes_nothing_on_disk(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, _pub = operator_keys
    from skcomms import skfed_directory as sfd
    from skcomms import skfed_readdr as rd

    sfd.save_directory(_seed_directory(priv, [_leaky_entry(LUMINA_FQID)]))
    before = sfd.directory_path().read_bytes()

    result = rd.reseed_neutral_addresses(signer=_signer(priv), dry_run=True)

    # Reports the would-be changes...
    assert len(result.changes) == 2
    assert result.signed is None
    # ...but the on-disk file is byte-for-byte unchanged.
    assert sfd.directory_path().read_bytes() == before


def test_reseed_is_idempotent(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, _pub = operator_keys
    from skcomms import skfed_directory as sfd
    from skcomms import skfed_readdr as rd

    sfd.save_directory(_seed_directory(priv, [_leaky_entry(LUMINA_FQID)]))

    first = rd.reseed_neutral_addresses(signer=_signer(priv), dry_run=False)
    assert len(first.changes) == 2

    # Second run: already neutral -> nothing to rewrite.
    second = rd.reseed_neutral_addresses(signer=_signer(priv), dry_run=False)
    assert second.changes == []


def test_only_leaky_hosts_are_rewritten(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, _pub = operator_keys
    from skcomms.skfed_directory import DirectoryEntry, SignedDirectory
    from skcomms import skfed_directory as sfd
    from skcomms import skfed_readdr as rd

    already_neutral = DirectoryEntry(
        fqid=LUMINA_FQID,
        inbox_url="https://fed-lumina.skworld.io/api/v1/inbox",
        prekey_url="https://fed-lumina.skworld.io/api/v1/prekey",
    )
    sd = SignedDirectory.build(
        realm=REALM,
        operator=OPERATOR,
        entries=[already_neutral, _leaky_entry(JARVIS_FQID)],
        signer=_signer(priv),
    )
    sfd.save_directory(sd)

    result = rd.reseed_neutral_addresses(signer=_signer(priv), dry_run=False)

    # Only jarvis (leaky) is rewritten; lumina (already neutral) untouched.
    assert {c.fqid for c in result.changes} == {JARVIS_FQID}


def test_reseed_no_directory_returns_empty(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, _pub = operator_keys
    from skcomms import skfed_readdr as rd

    result = rd.reseed_neutral_addresses(signer=_signer(priv), dry_run=False)
    assert result.changes == []
    assert result.signed is None


def test_fqid_filter_limits_scope(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, _pub = operator_keys
    from skcomms import skfed_directory as sfd
    from skcomms import skfed_readdr as rd

    sfd.save_directory(_seed_directory(priv, [_leaky_entry(LUMINA_FQID), _leaky_entry(JARVIS_FQID)]))

    result = rd.reseed_neutral_addresses(
        signer=_signer(priv), dry_run=False, fqids=[LUMINA_FQID]
    )
    assert {c.fqid for c in result.changes} == {LUMINA_FQID}
    # jarvis still leaky (out of scope of the filter).
    loaded = sfd.load_directory()
    assert "ts.net" in loaded.get(JARVIS_FQID).inbox_url
