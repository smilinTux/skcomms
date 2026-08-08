"""Public P2P pairing over a Tailscale Funnel URL (card 2ab5aa6c).

All mocked: no live network, no funnel opened, no public port bound. The peer
bundle is imported through the EXISTING key exchange, so the crypto path is
unchanged; these tests only cover the Funnel bootstrap wrapper.
"""

from __future__ import annotations

import pytest

import skcomms.public_pairing as pp

# --- helpers ----------------------------------------------------------------


def _gen_pubkey():
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("Testpeer", email="peer@x")
    k.add_uid(
        uid,
        usage={KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(k.pubkey)


def _peer_bundle(fqid="opus@chef.skworld", name="Testpeer"):
    from skcomms.peers import fingerprint_from_pubkey

    pub = _gen_pubkey()
    return {
        "skcomms_peer_bundle": "1.0",
        "name": name,
        "fqid": fqid,
        "fingerprint": fingerprint_from_pubkey(pub),
        "public_key": pub,
        "transports": [],
    }


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(pp.FUNNEL_URL_ENV, raising=False)
    monkeypatch.delenv(pp.FUNNEL_TOKEN_ENV, raising=False)


# --- resolve / enabled (disabled by default) --------------------------------


def test_disabled_by_default_no_funnel_configured():
    # No env, and the tailscale probe is forced off -> feature is OFF.
    assert pp.resolve_funnel_base(resolver=lambda: None) is None
    assert pp.funnel_enabled(resolver=lambda: None) is False
    assert pp.mint_pairing_url(resolver=lambda: None) is None


def test_env_enables_and_sets_base(monkeypatch):
    monkeypatch.setenv(pp.FUNNEL_URL_ENV, "https://node.tailnet.ts.net/")
    assert pp.resolve_funnel_base() == "https://node.tailnet.ts.net"
    assert pp.funnel_enabled() is True


def test_explicit_base_overrides_env(monkeypatch):
    monkeypatch.setenv(pp.FUNNEL_URL_ENV, "https://env.ts.net")
    assert pp.resolve_funnel_base("https://explicit.ts.net") == "https://explicit.ts.net"


# --- minting URL / token ----------------------------------------------------


def test_mint_pairing_url_shape():
    url = pp.mint_pairing_url("https://node.tailnet.ts.net")
    assert url == "https://node.tailnet.ts.net/api/v1/pair/public"


def test_mint_pairing_url_with_token():
    tok = pp.mint_pairing_token()
    url = pp.mint_pairing_url("https://node.ts.net", token=tok)
    assert url.startswith("https://node.ts.net/api/v1/pair/public?")
    assert f"t={tok}" in url


def test_mint_token_is_random_and_urlsafe():
    a, b = pp.mint_pairing_token(), pp.mint_pairing_token()
    assert a != b and len(a) > 20


# --- inbound handler routes into key exchange -------------------------------


def test_inbound_request_routes_into_key_exchange(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    bundle = _peer_bundle()
    res = pp.handle_public_pairing_request(
        {"bundle": bundle},
        self_bundle_provider=lambda: {"name": "me"},
    )
    assert res["paired"]["fqid"] == "opus@chef.skworld"
    assert res["paired"]["fingerprint"] == bundle["fingerprint"]
    assert res["self_bundle"] == {"name": "me"}
    # It actually went through the real import path -> peer YAML landed.
    from skcomms.discovery import PeerStore

    assert PeerStore(tmp_path / "peers").get("Testpeer") is not None


def test_inbound_uses_import_peer_bundle(monkeypatch):
    """The handler routes into the EXISTING key exchange (import_peer_bundle)."""
    calls = {}

    class _Peer:
        name = "Testpeer"
        fingerprint = "AB" * 20

    def _fake_import(bundle, *, peers_dir=None, gpg_import=False):
        calls["bundle"] = bundle
        return _Peer()

    res = pp.handle_public_pairing_request(
        {"bundle": {"skcomms_peer_bundle": "1.0", "name": "Testpeer"}, "token": None},
        importer=_fake_import,
        self_bundle_provider=lambda: None,
    )
    assert calls["bundle"]["name"] == "Testpeer"
    assert res["paired"]["name"] == "Testpeer"


# --- fail-closed on bad input -----------------------------------------------


def test_empty_bundle_rejected():
    from skcomms.key_exchange import KeyExchangeError

    with pytest.raises(KeyExchangeError):
        pp.handle_public_pairing_request({"bundle": {}}, self_bundle_provider=lambda: None)


def test_malformed_bundle_rejected():
    from skcomms.key_exchange import KeyExchangeError

    # A bundle with no public_key is rejected by the real key exchange.
    with pytest.raises(KeyExchangeError):
        pp.handle_public_pairing_request(
            {"bundle": {"skcomms_peer_bundle": "1.0", "name": "x"}},
            self_bundle_provider=lambda: None,
        )


def test_token_required_and_mismatched_rejected():
    with pytest.raises(pp.PublicPairingError):
        pp.handle_public_pairing_request(
            {"bundle": {"skcomms_peer_bundle": "1.0", "name": "x"}, "token": "wrong"},
            expected_token="secret",
            importer=lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not import")),
        )


def test_token_required_and_missing_rejected():
    with pytest.raises(pp.PublicPairingError):
        pp.handle_public_pairing_request(
            {"bundle": {"skcomms_peer_bundle": "1.0", "name": "x"}},
            expected_token="secret",
            importer=lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not import")),
        )


def test_token_match_allows(monkeypatch):
    ok = {}

    def _imp(bundle, *, peers_dir=None, gpg_import=False):
        ok["called"] = True

        class _P:
            name = "x"
            fingerprint = "f"

        return _P()

    res = pp.handle_public_pairing_request(
        {"bundle": {"skcomms_peer_bundle": "1.0", "name": "x"}, "token": "secret"},
        expected_token="secret",
        importer=_imp,
        self_bundle_provider=lambda: None,
    )
    assert ok.get("called") and res["paired"]["name"] == "x"


# --- API route (in-process TestClient, no public port) ----------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    import importlib

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    import skcomms.api as api

    importlib.reload(api)
    from fastapi.testclient import TestClient

    return TestClient(api.app)


def test_route_404_when_disabled(client, monkeypatch):
    monkeypatch.delenv(pp.FUNNEL_URL_ENV, raising=False)
    # Force the tailscale-funnel probe off so the test never depends on the host
    # having a live funnel -> no base configured -> 404 (feature off).
    monkeypatch.setattr(pp, "_tailscale_funnel_base", lambda: None)
    r = client.post("/api/v1/pair/public", json={"bundle": _peer_bundle()})
    assert r.status_code == 404


def test_route_accepts_when_enabled(client, monkeypatch):
    monkeypatch.setenv(pp.FUNNEL_URL_ENV, "https://node.ts.net")
    r = client.post("/api/v1/pair/public", json={"bundle": _peer_bundle()})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["paired"]["fqid"] == "opus@chef.skworld"


def test_route_rejects_bad_token(client, monkeypatch):
    monkeypatch.setenv(pp.FUNNEL_URL_ENV, "https://node.ts.net")
    monkeypatch.setenv(pp.FUNNEL_TOKEN_ENV, "s3cret")
    r = client.post("/api/v1/pair/public", json={"bundle": _peer_bundle(), "token": "nope"})
    assert r.status_code == 401


def test_route_rejects_empty_bundle(client, monkeypatch):
    monkeypatch.setenv(pp.FUNNEL_URL_ENV, "https://node.ts.net")
    r = client.post("/api/v1/pair/public", json={"bundle": {}})
    assert r.status_code == 422
