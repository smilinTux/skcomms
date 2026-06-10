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
