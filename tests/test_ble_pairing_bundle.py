import base64

from skcomms.pairing import PairingBundle, parse_skp_uri, to_skp_uri


def test_bundle_carries_noise_static_pubkey_through_uri():
    raw_pub = bytes(range(32))
    b = PairingBundle(
        fqid="lumina@chef.skworld",
        fingerprint="a" * 64,
        noise_static_pubkey=base64.urlsafe_b64encode(raw_pub).decode(),
    )
    uri = to_skp_uri(b)
    assert "ns=" in uri
    out = parse_skp_uri(uri)
    assert out.noise_static_pubkey == base64.urlsafe_b64encode(raw_pub).decode()


def test_bundle_without_noise_key_still_parses():
    b = PairingBundle(fqid="x@y.z", fingerprint="b" * 64)
    out = parse_skp_uri(to_skp_uri(b))
    assert out.noise_static_pubkey is None
