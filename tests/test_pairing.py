from skcomms.pairing import PairingBundle, to_skp_uri, parse_skp_uri


def test_uri_round_trip_compact():
    b = PairingBundle(fqid="lumina@chef.skworld", fingerprint="AB"*20,
                      syncthing_device_id="DEV-1", tailscale="lumina.ts.net",
                      https="https://x/peers.json")
    uri = to_skp_uri(b)
    assert uri.startswith("skp://pair?")
    assert parse_skp_uri(uri) == b


def test_uri_round_trip_embedded_key():
    b = PairingBundle(fqid="opus@chef.skworld", fingerprint="CD"*20,
                      pubkey="-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END-----\n")
    assert parse_skp_uri(to_skp_uri(b)).pubkey == b.pubkey


def test_parse_rejects_non_skp():
    import pytest
    with pytest.raises(ValueError):
        parse_skp_uri("https://evil/pair?fqid=x")


def test_bundle_requires_fqid_and_fingerprint():
    import pytest
    with pytest.raises(Exception):
        PairingBundle(fqid="", fingerprint="")


def test_bundle_from_self(monkeypatch, tmp_path):
    import skcomms.pairing as P
    monkeypatch.setattr(P, "resolve_self_identity",
        lambda agent=None: {"fqid": "lumina@chef.skworld", "fingerprint": "AB"*20})
    monkeypatch.setattr(P, "_self_hints", lambda fqid: {"syncthing_device_id": "DEV-9"})
    b = P.bundle_from_self()
    assert b.fqid == "lumina@chef.skworld"
    assert b.syncthing_device_id == "DEV-9"
    assert b.pubkey is None


def test_bundle_from_self_embed_key(monkeypatch):
    import skcomms.pairing as P
    monkeypatch.setattr(P, "resolve_self_identity",
        lambda agent=None: {"fqid": "lumina@chef.skworld", "fingerprint": "AB"*20})
    monkeypatch.setattr(P, "_self_hints", lambda fqid: {})
    monkeypatch.setattr(P, "_self_pubkey_armor", lambda: "-----BEGIN PGP-----\nx\n-----END-----\n")
    b = P.bundle_from_self(embed_key=True)
    assert b.pubkey and "PGP" in b.pubkey


def test_make_qr_returns_uri_and_renders():
    import io
    from skcomms.pairing import PairingBundle, make_pairing_qr
    uri, qr = make_pairing_qr(PairingBundle(fqid="a@b.c", fingerprint="AB"*20))
    assert uri.startswith("skp://pair?")
    # segno QRCode renders ASCII to a stream without error (non-empty output)
    buf = io.StringIO()
    qr.terminal(out=buf)
    assert buf.getvalue()
