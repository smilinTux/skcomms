"""Tests for skfed_announce — daemon-startup self-announce into the realm directory.

``announce_self`` resolves the running node's *live* federation endpoints (inbox /
prekey) from a passed ``base`` (or ``SKFED_BASE_URL`` / ``SKFED_INBOX_URL`` env, or
an injectable resolver) and hands them to a publisher (default
:func:`skcomms.skfed_directory.publish_self_to_realm_directory`) so the on-disk
signed directory auto-refreshes. It is designed to be called on daemon startup.

The publisher + signer + base-resolver are all injectable so the whole path is
testable offline against a tmp ``SKCOMMS_HOME``.
"""

from __future__ import annotations

import pytest

JARVIS_FQID = "jarvis@chef.skworld"
LUMINA_FQID = "lumina@chef.skworld"
REALM = "skworld"
OPERATOR = "chef"


# --- in-process operator key (mirrors test_skfed_directory.py) --------------


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


class _CapturingPublisher:
    """A fake publisher recording exactly what announce_self forwarded."""

    def __init__(self):
        self.calls = []

    def __call__(self, fqid, inbox_url, prekey_url=None, **kw):
        self.calls.append(dict(fqid=fqid, inbox_url=inbox_url, prekey_url=prekey_url, **kw))
        return f"signed-directory-for:{fqid}"  # sentinel return


# --- base/url resolution ----------------------------------------------------


def test_announce_self_derives_inbox_and_prekey_from_base():
    from skcomms import skfed_announce as sa

    pub = _CapturingPublisher()
    sd = sa.announce_self(
        "jarvis",
        fqid=JARVIS_FQID,
        base="https://node.tailXYZ.ts.net",
        publisher=pub,
        signer="SIG",
        base_resolver=lambda: None,
    )
    assert sd == "signed-directory-for:jarvis@chef.skworld"
    call = pub.calls[0]
    assert call["fqid"] == JARVIS_FQID
    assert call["inbox_url"] == "https://node.tailXYZ.ts.net/api/v1/inbox"
    assert call["prekey_url"] == "https://node.tailXYZ.ts.net/api/v1/prekey"
    assert call["signer"] == "SIG"
    assert call["agent"] == "jarvis"


def test_explicit_urls_override_base():
    from skcomms import skfed_announce as sa

    pub = _CapturingPublisher()
    sa.announce_self(
        "jarvis",
        fqid=JARVIS_FQID,
        base="https://node.ts.net",
        inbox_url="https://explicit/api/v1/inbox",
        prekey_url="https://explicit/api/v1/prekey",
        publisher=pub,
        base_resolver=lambda: None,
    )
    call = pub.calls[0]
    assert call["inbox_url"] == "https://explicit/api/v1/inbox"
    assert call["prekey_url"] == "https://explicit/api/v1/prekey"


def test_base_from_env(monkeypatch):
    from skcomms import skfed_announce as sa

    monkeypatch.setenv("SKFED_BASE_URL", "https://envnode.ts.net/")
    pub = _CapturingPublisher()
    sa.announce_self("jarvis", fqid=JARVIS_FQID, publisher=pub, base_resolver=lambda: None)
    call = pub.calls[0]
    assert call["inbox_url"] == "https://envnode.ts.net/api/v1/inbox"
    assert call["prekey_url"] == "https://envnode.ts.net/api/v1/prekey"


def test_inbox_url_from_env_overrides_base(monkeypatch):
    from skcomms import skfed_announce as sa

    monkeypatch.setenv("SKFED_INBOX_URL", "https://envinbox/api/v1/inbox")
    pub = _CapturingPublisher()
    sa.announce_self(
        "jarvis", fqid=JARVIS_FQID, base="https://node.ts.net",
        publisher=pub, base_resolver=lambda: None,
    )
    call = pub.calls[0]
    assert call["inbox_url"] == "https://envinbox/api/v1/inbox"
    # prekey still derived from base
    assert call["prekey_url"] == "https://node.ts.net/api/v1/prekey"


def test_uses_injected_base_resolver_when_no_base():
    from skcomms import skfed_announce as sa

    pub = _CapturingPublisher()
    sa.announce_self(
        "jarvis", fqid=JARVIS_FQID, publisher=pub,
        base_resolver=lambda: "https://resolved.ts.net",
    )
    call = pub.calls[0]
    assert call["inbox_url"] == "https://resolved.ts.net/api/v1/inbox"


def test_raises_when_no_inbox_resolvable(monkeypatch):
    from skcomms import skfed_announce as sa

    monkeypatch.delenv("SKFED_BASE_URL", raising=False)
    monkeypatch.delenv("SKFED_INBOX_URL", raising=False)
    pub = _CapturingPublisher()
    with pytest.raises(ValueError):
        sa.announce_self("jarvis", fqid=JARVIS_FQID, publisher=pub, base_resolver=lambda: None)
    assert pub.calls == []


def test_raises_when_no_fqid(monkeypatch):
    from skcomms import skfed_announce as sa

    # No fqid passed + resolver yields no fqid -> nothing to announce.
    monkeypatch.setattr(sa, "resolve_self_identity", lambda agent=None: {"fqid": None})
    with pytest.raises(ValueError):
        sa.announce_self("ghost", base="https://x.ts.net", publisher=_CapturingPublisher())


def test_fqid_resolved_from_identity_when_not_passed(monkeypatch):
    from skcomms import skfed_announce as sa

    monkeypatch.setattr(sa, "resolve_self_identity", lambda agent=None: {"fqid": LUMINA_FQID})
    pub = _CapturingPublisher()
    sa.announce_self("lumina", base="https://l.ts.net", publisher=pub, base_resolver=lambda: None)
    assert pub.calls[0]["fqid"] == LUMINA_FQID


def test_caps_and_did_forwarded():
    from skcomms import skfed_announce as sa

    pub = _CapturingPublisher()
    sa.announce_self(
        "jarvis", fqid=JARVIS_FQID, base="https://n.ts.net",
        did="did:skfed:jarvis", caps=["dm", "files"],
        publisher=pub, base_resolver=lambda: None,
    )
    call = pub.calls[0]
    assert call["did"] == "did:skfed:jarvis"
    assert call["caps"] == ["dm", "files"]


# --- end-to-end against a real signed directory + tmp SKCOMMS_HOME ----------


def test_announce_self_end_to_end_persists_and_verifies(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub_armor = operator_keys
    from skcomms import skfed_announce as sa
    from skcomms import skfed_directory as sfd
    from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

    signer = EnvelopeSigner(priv)
    # Real publisher (default) + injected signer -> no on-disk key needed.
    sd = sa.announce_self(
        "jarvis",
        fqid=JARVIS_FQID,
        base="https://jarvis.ts.net",
        signer=signer,
        caps=["dm"],
        base_resolver=lambda: None,
    )
    assert any(e.fqid == JARVIS_FQID for e in sd.entries)

    loaded = sfd.load_directory()
    entry = [e for e in loaded.entries if e.fqid == JARVIS_FQID][0]
    assert entry.inbox_url == "https://jarvis.ts.net/api/v1/inbox"
    assert entry.prekey_url == "https://jarvis.ts.net/api/v1/prekey"

    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub_armor)
    assert loaded.verify(verifier) is True


def test_refresh_all_announces_each_agent(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub_armor = operator_keys
    from skcomms import skfed_announce as sa
    from skcomms import skfed_directory as sfd
    from skcomms.signing import EnvelopeSigner, EnvelopeVerifier

    signer = EnvelopeSigner(priv)
    results = sa.refresh_all(
        [
            {"agent": "jarvis", "fqid": JARVIS_FQID, "base": "https://jarvis.ts.net"},
            {"agent": "lumina", "fqid": LUMINA_FQID, "base": "https://lumina.ts.net"},
        ],
        signer=signer,
        base_resolver=lambda: None,
    )
    assert len(results) == 2

    loaded = sfd.load_directory()
    assert {e.fqid for e in loaded.entries} == {JARVIS_FQID, LUMINA_FQID}
    verifier = EnvelopeVerifier()
    verifier.add_key(OPERATOR, pub_armor)
    assert loaded.verify(verifier) is True


def test_refresh_all_accepts_plain_agent_names(monkeypatch):
    from skcomms import skfed_announce as sa

    monkeypatch.setattr(
        sa, "resolve_self_identity",
        lambda agent=None: {"fqid": f"{agent}@chef.skworld"},
    )
    pub = _CapturingPublisher()
    sa.refresh_all(
        ["jarvis", "lumina"],
        base="https://multi.ts.net",
        publisher=pub,
        base_resolver=lambda: None,
    )
    assert {c["fqid"] for c in pub.calls} == {JARVIS_FQID, LUMINA_FQID}
