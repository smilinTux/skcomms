import hashlib

from skcomms.transports.ble.identity import (
    MeshIdentity,
    fingerprint_of,
    id_hash,
)


def test_id_hash_is_first_8_of_sha256_of_fqid():
    fqid = "lumina@chef.skworld"
    expected = hashlib.sha256(fqid.encode()).digest()[:8]
    assert id_hash(fqid) == expected
    assert len(id_hash(fqid)) == 8


def test_generate_yields_distinct_keypairs():
    a = MeshIdentity.generate("a@x.y")
    b = MeshIdentity.generate("b@x.y")
    assert a.noise_static_pub != b.noise_static_pub
    assert a.ed25519_pub != b.ed25519_pub
    assert len(a.noise_static_pub) == 32
    assert len(a.ed25519_pub) == 32


def test_fingerprint_is_sha256_of_noise_static_pub_hex():
    ident = MeshIdentity.generate("z@x.y")
    assert fingerprint_of(ident.noise_static_pub) == \
        hashlib.sha256(ident.noise_static_pub).hexdigest()
    assert ident.fingerprint == fingerprint_of(ident.noise_static_pub)


def test_sign_and_verify_roundtrip():
    ident = MeshIdentity.generate("s@x.y")
    msg = b"announce-me"
    sig = ident.sign(msg)
    assert len(sig) == 64
    assert MeshIdentity.verify(ident.ed25519_pub, msg, sig) is True
    assert MeshIdentity.verify(ident.ed25519_pub, b"tampered", sig) is False


def test_my_id_matches_id_hash():
    ident = MeshIdentity.generate("me@x.y")
    assert ident.my_id == id_hash("me@x.y")


def test_verify_returns_false_on_bad_length_pubkey():
    # from_public_bytes raises ValueError on a non-32-byte key; verify must
    # swallow it and return False, not propagate.
    assert MeshIdentity.verify(b"tooshort", b"msg", b"\x00" * 64) is False
