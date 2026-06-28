"""Tests for the sovereign realm resolver (skfed_resolve).

``resolve_realm_directory(realm)`` finds a realm's directory base URL via DNS
(``_skfed._tcp.<realm>`` SRV, then TXT) THEN a config bootstrap
(``skcomms_home()/realms.yml``) THEN None.

``resolve_agent(fqid, *, http_get, dns)`` fetches the realm directory, VERIFIES
its operator signature, finds the agent entry, returns its live endpoints, and
caches the directory with a TTL. DNS + http_get + verifier are all injectable so
the path is fully testable offline.
"""

from __future__ import annotations

import pytest


# --- in-process keys -------------------------------------------------------


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
JARVIS_FQID = "jarvis@chef.skworld"
LUMINA_FQID = "lumina@chef.skworld"
DIR_BASE = "https://dir.chef.skworld"


# --- injectable DNS + HTTP stubs ------------------------------------------


class FakeDns:
    def __init__(self, srv=None, txt=None):
        self._srv = srv or {}
        self._txt = txt or {}

    def srv(self, name):
        return self._srv.get(name, [])

    def txt(self, name):
        return self._txt.get(name, [])


def _entry(fqid):
    from skcomms.skfed_directory import DirectoryEntry

    return DirectoryEntry(
        fqid=fqid,
        inbox_url=f"https://{fqid.split('@')[0]}.ts.net/api/v1/inbox",
        prekey_url=f"https://{fqid.split('@')[0]}.ts.net/api/v1/prekey",
        did=f"did:skfed:{fqid}",
        caps=["dm"],
    )


def _signed_directory(operator_priv):
    from skcomms.signing import EnvelopeSigner
    from skcomms.skfed_directory import SignedDirectory

    signer = EnvelopeSigner(operator_priv)
    return SignedDirectory.build(
        realm=REALM, operator=OPERATOR,
        entries=[_entry(JARVIS_FQID), _entry(LUMINA_FQID)], signer=signer,
    )


def _http_get_for(sd, *, counter=None):
    """Return an http_get(url)->bytes that serves the directory + counts hits."""
    raw = sd.to_bytes()

    def _get(url):
        if counter is not None:
            counter["n"] += 1
        if url.rstrip("/").endswith("/.well-known/skfed/directory"):
            return raw
        raise AssertionError(f"unexpected GET {url}")

    return _get


def _verifier_for(operator_pub):
    from skcomms.signing import EnvelopeVerifier

    v = EnvelopeVerifier()
    v.add_key(OPERATOR, operator_pub)
    return v


# --- resolve_realm_directory ----------------------------------------------


def test_resolve_realm_directory_srv():
    from skcomms.skfed_resolve import resolve_realm_directory

    dns = FakeDns(srv={f"_skfed._tcp.{REALM}": [("dir.chef.skworld", 443)]})
    base = resolve_realm_directory(REALM, dns=dns)
    assert base == "https://dir.chef.skworld"


def test_resolve_realm_directory_srv_nonstandard_port():
    from skcomms.skfed_resolve import resolve_realm_directory

    dns = FakeDns(srv={f"_skfed._tcp.{REALM}": [("dir.chef.skworld", 8443)]})
    base = resolve_realm_directory(REALM, dns=dns)
    assert base == "https://dir.chef.skworld:8443"


def test_resolve_realm_directory_txt_url():
    from skcomms.skfed_resolve import resolve_realm_directory

    dns = FakeDns(txt={f"_skfed.{REALM}": ["url=https://dir.chef.skworld/skfed"]})
    base = resolve_realm_directory(REALM, dns=dns)
    assert base == "https://dir.chef.skworld/skfed"


def test_resolve_realm_directory_config_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    (tmp_path).mkdir(parents=True, exist_ok=True)
    (tmp_path / "realms.yml").write_text(
        f"{REALM}: {DIR_BASE}\nother: https://dir.other.realm\n"
    )
    from skcomms.skfed_resolve import resolve_realm_directory

    # Empty DNS -> falls through to config bootstrap.
    assert resolve_realm_directory(REALM, dns=FakeDns()) == DIR_BASE


def test_resolve_realm_directory_none(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.skfed_resolve import resolve_realm_directory

    assert resolve_realm_directory("nowhere", dns=FakeDns()) is None


# --- resolve_agent ---------------------------------------------------------


def test_resolve_agent_happy_path(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms.skfed_resolve import DirectoryCache, resolve_agent

    sd = _signed_directory(priv)
    dns = FakeDns(srv={f"_skfed._tcp.{REALM}": [("dir.chef.skworld", 443)]})

    rec = resolve_agent(
        JARVIS_FQID,
        http_get=_http_get_for(sd),
        dns=dns,
        verifier=_verifier_for(pub),
        cache=DirectoryCache(),
    )
    assert rec is not None
    assert rec["inbox_url"] == "https://jarvis.ts.net/api/v1/inbox"
    assert rec["prekey_url"] == "https://jarvis.ts.net/api/v1/prekey"
    assert rec["fqid"] == JARVIS_FQID


def test_resolve_agent_unknown_agent_returns_none(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms.skfed_resolve import DirectoryCache, resolve_agent

    sd = _signed_directory(priv)
    dns = FakeDns(srv={f"_skfed._tcp.{REALM}": [("dir.chef.skworld", 443)]})

    rec = resolve_agent(
        "ghost@chef.skworld",
        http_get=_http_get_for(sd),
        dns=dns,
        verifier=_verifier_for(pub),
        cache=DirectoryCache(),
    )
    assert rec is None


def test_resolve_agent_bad_signature_fails_closed(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, _pub = operator_keys
    attacker_priv, attacker_pub = _gen_key("evil <evil@x.y>")
    from skcomms.skfed_resolve import DirectoryCache, resolve_agent

    sd = _signed_directory(priv)
    dns = FakeDns(srv={f"_skfed._tcp.{REALM}": [("dir.chef.skworld", 443)]})

    # Verifier trusts the WRONG key -> directory signature won't verify -> None.
    rec = resolve_agent(
        JARVIS_FQID,
        http_get=_http_get_for(sd),
        dns=dns,
        verifier=_verifier_for(attacker_pub),
        cache=DirectoryCache(),
    )
    assert rec is None


def test_resolve_agent_no_directory_returns_none(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    _priv, pub = operator_keys
    from skcomms.skfed_resolve import DirectoryCache, resolve_agent

    # No DNS, no config -> realm unresolvable.
    rec = resolve_agent(
        JARVIS_FQID,
        http_get=lambda url: (_ for _ in ()).throw(AssertionError("should not GET")),
        dns=FakeDns(),
        verifier=_verifier_for(pub),
        cache=DirectoryCache(),
    )
    assert rec is None


def test_resolve_agent_caches_directory_within_ttl(tmp_path, monkeypatch, operator_keys):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms.skfed_resolve import DirectoryCache, resolve_agent

    sd = _signed_directory(priv)
    dns = FakeDns(srv={f"_skfed._tcp.{REALM}": [("dir.chef.skworld", 443)]})
    counter = {"n": 0}
    http_get = _http_get_for(sd, counter=counter)

    clock = {"t": 1000.0}
    cache = DirectoryCache(ttl_s=300, clock=lambda: clock["t"])

    # First resolve fetches.
    r1 = resolve_agent(JARVIS_FQID, http_get=http_get, dns=dns,
                       verifier=_verifier_for(pub), cache=cache)
    assert r1 is not None
    assert counter["n"] == 1

    # Second resolve within TTL -> served from cache, no extra GET.
    clock["t"] = 1200.0
    r2 = resolve_agent(LUMINA_FQID, http_get=http_get, dns=dns,
                       verifier=_verifier_for(pub), cache=cache)
    assert r2["fqid"] == LUMINA_FQID
    assert counter["n"] == 1

    # After TTL -> re-fetch.
    clock["t"] = 1000.0 + 301
    r3 = resolve_agent(JARVIS_FQID, http_get=http_get, dns=dns,
                       verifier=_verifier_for(pub), cache=cache)
    assert r3 is not None
    assert counter["n"] == 2


# --- discovery.inbox_url_for fallback -------------------------------------


def test_inbox_url_for_skfed_fallback(tmp_path, monkeypatch, operator_keys):
    """No local peer record -> inbox_url_for falls back to the realm directory."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    priv, pub = operator_keys
    from skcomms.discovery import PeerStore, inbox_url_for
    from skcomms.skfed_resolve import DirectoryCache

    sd = _signed_directory(priv)
    dns = FakeDns(srv={f"_skfed._tcp.{REALM}": [("dir.chef.skworld", 443)]})

    # Empty local store + empty node registry -> must use the directory.
    store = PeerStore(peers_dir=tmp_path / "peers")
    url = inbox_url_for(
        JARVIS_FQID,
        store=store,
        http_get=_http_get_for(sd),
        dns=dns,
        verifier=_verifier_for(pub),
        cache=DirectoryCache(),
    )
    assert url == "https://jarvis.ts.net/api/v1/inbox"


def test_inbox_url_for_local_peer_still_wins(tmp_path, monkeypatch, operator_keys):
    """Existing local-peer resolution is unchanged (fallback is additive)."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.discovery import PeerInfo, PeerStore, PeerTransport, inbox_url_for

    store = PeerStore(peers_dir=tmp_path / "peers")
    local_url = "https://local.ts.net/api/v1/inbox"
    store.add(
        PeerInfo(
            name="jarvis",
            fqid=JARVIS_FQID,
            transports=[PeerTransport(transport="https-s2s", settings={"inbox_url": local_url})],
        )
    )

    def _boom(url):
        raise AssertionError("skfed fallback should not run when local peer matches")

    assert inbox_url_for(JARVIS_FQID, store=store, http_get=_boom) == local_url
