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
    monkeypatch.setattr(P, "_self_pubkey_armor", lambda *a, **k: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n")
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


def _gen_pubkey():
    import pgpy
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("t", email="t@x")
    k.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256],
              ciphers=[SymmetricKeyAlgorithm.AES256], compression=[CompressionAlgorithm.ZLIB])
    return str(k.pubkey)


def test_accept_embedded_key_adds_peer(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.pairing import PairingBundle, to_skp_uri, accept_pairing
    from skcomms.peers import fingerprint_from_pubkey
    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-2", pubkey=pub))
    rec = accept_pairing(uri)
    assert rec["fqid"] == "opus@chef.skworld"
    # appears in the peer store
    from skcomms.peers import list_peers
    peers = list_peers()
    assert "opus@chef.skworld" in peers


def test_accept_compact_fetches_then_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.pairing import PairingBundle, to_skp_uri, accept_pairing
    from skcomms.peers import fingerprint_from_pubkey
    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-3"))  # no embedded key
    rec = accept_pairing(uri, fetcher=lambda b: pub)   # injected: returns the pubkey
    assert rec["fqid"] == "opus@chef.skworld"


def test_accept_rejects_fingerprint_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    import pytest
    from skcomms.pairing import PairingBundle, to_skp_uri, accept_pairing
    other = _gen_pubkey()
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint="00"*20,
                                   syncthing_device_id="D", pubkey=other))
    with pytest.raises(ValueError):
        accept_pairing(uri)   # embedded key's fingerprint != claimed fingerprint


def test_self_pubkey_armor_returns_agent_key_matching_fingerprint(tmp_path, monkeypatch):
    """_self_pubkey_armor returns the agent's own key only when it matches the
    expected fingerprint (never the operator key)."""
    import skcomms.pairing as P
    from skcomms.peers import fingerprint_from_pubkey
    # build a fake agent home with a public.asc
    pub = _gen_pubkey()
    fp = fingerprint_from_pubkey(pub)
    agent_dir = tmp_path / ".skcapstone" / "agents" / "lumina" / "capauth" / "identity"
    agent_dir.mkdir(parents=True)
    (agent_dir / "public.asc").write_text(pub)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "lumina")
    # matching fingerprint -> returns the key
    assert P._self_pubkey_armor(fp, "lumina") == pub
    # non-matching expected fingerprint -> None (won't embed a wrong key)
    assert P._self_pubkey_armor("00" * 20, "lumina") is None


def test_embed_key_bundle_fingerprint_matches_embedded_key(tmp_path, monkeypatch):
    """The whole point: an embed-key bundle's claimed fingerprint == the
    embedded key's fingerprint, so accept_pairing won't reject it."""
    import skcomms.pairing as P
    from skcomms.peers import fingerprint_from_pubkey
    pub = _gen_pubkey()
    fp = fingerprint_from_pubkey(pub)
    agent_dir = tmp_path / ".skcapstone" / "agents" / "lumina" / "capauth" / "identity"
    agent_dir.mkdir(parents=True)
    (agent_dir / "public.asc").write_text(pub)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "lumina")
    monkeypatch.setattr(P, "resolve_self_identity",
                        lambda agent=None: {"fqid": "lumina@chef.skworld", "fingerprint": fp})
    monkeypatch.setattr(P, "_self_hints", lambda fqid: {})
    b = P.bundle_from_self(embed_key=True)
    assert b.pubkey == pub
    assert fingerprint_from_pubkey(b.pubkey).upper() == b.fingerprint.upper()
