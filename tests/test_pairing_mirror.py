"""M2 pairing fold: accept_pairing mirrors the accepted peer into capauth.pairing.

Best-effort dual-write. These tests confirm the mirror creates a capauth TOFU
device, is fail-safe (a capauth error can never break accept_pairing), and is
gated OFF by SKCOMMS_PAIRING_KERNEL=0.
"""

import pytest

from skcomms.peers import fingerprint_from_pubkey
from skcomms.pairing import PairingBundle, to_skp_uri, accept_pairing
import skcomms.pairing_mirror as PM


def _gen_pubkey():
    import pgpy
    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )

    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("t", email="t@x")
    k.add_uid(
        uid,
        usage={KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(k.pubkey)


def test_accept_mirrors_peer_into_capauth(tmp_path, monkeypatch):
    """A successful accept_pairing creates exactly one tofu capauth device whose
    subject is the peer's fqid."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))
    pub = _gen_pubkey()
    fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(
        PairingBundle(
            fqid="opus@chef.skworld.io", fingerprint=fp, syncthing_device_id="DEV-2", pubkey=pub
        )
    )
    rec = accept_pairing(uri)
    assert rec["fqid"] == "opus@chef.skworld.io"

    devs = list_devices(subject="opus@chef.skworld.io", base_dir=str(tmp_path / "capauth"))
    assert len(devs) == 1
    assert devs[0].subject == "opus@chef.skworld.io"
    assert str(getattr(devs[0].mode, "value", devs[0].mode)) == "tofu"


def test_mirror_pairing_direct(tmp_path, monkeypatch):
    """mirror_pairing on its own records a tofu device under the base override."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    pub = _gen_pubkey()
    PM.mirror_pairing("lumina@chef.skworld.io", pub)
    devs = list_devices(subject="lumina@chef.skworld.io", base_dir=str(tmp_path))
    assert len(devs) == 1
    assert str(getattr(devs[0].mode, "value", devs[0].mode)) == "tofu"


def test_mirror_is_fail_safe(tmp_path, monkeypatch):
    """A capauth failure never propagates out of mirror_pairing."""
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.enroll_device", _boom)
    # Must NOT raise.
    PM.mirror_pairing("opus@chef.skworld.io", _gen_pubkey())


def test_accept_still_succeeds_when_mirror_raises(tmp_path, monkeypatch):
    """End-to-end: even if capauth.enroll_device blows up, the pairing succeeds
    and the peer is TOFU-added locally (mirror is additive, best-effort)."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.enroll_device", _boom)
    pub = _gen_pubkey()
    fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(
        PairingBundle(
            fqid="opus@chef.skworld.io", fingerprint=fp, syncthing_device_id="DEV-2", pubkey=pub
        )
    )
    rec = accept_pairing(uri)
    assert rec["fqid"] == "opus@chef.skworld.io"
    from skcomms.peers import list_peers

    assert "opus@chef.skworld.io" in list_peers()


def test_kernel_disabled_writes_nothing(tmp_path, monkeypatch):
    """SKCOMMS_PAIRING_KERNEL=0 disables the mirror: no capauth device created."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL", "0")
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    PM.mirror_pairing("opus@chef.skworld.io", _gen_pubkey())
    assert list_devices(subject="opus@chef.skworld.io", base_dir=str(tmp_path)) == []


# ---------------------------------------------------------------------------
# M2 pairing fold, removal side: peer removal mirrors a capauth revocation.
# ---------------------------------------------------------------------------


def test_remove_mirrors_revocation_into_capauth(tmp_path, monkeypatch):
    """After mirroring an accept, remove_peer revokes the capauth device: the
    device still exists in the store but is marked revoked."""
    from capauth.pairing import list_devices
    from skcomms.peers import remove_peer

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))
    base = str(tmp_path / "capauth")

    pub = _gen_pubkey()
    fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(
        PairingBundle(
            fqid="opus@chef.skworld.io", fingerprint=fp, syncthing_device_id="DEV-2", pubkey=pub
        )
    )
    accept_pairing(uri)
    devs = list_devices(subject="opus@chef.skworld.io", base_dir=base)
    assert len(devs) == 1 and not devs[0].revoked

    assert remove_peer("opus@chef.skworld.io") is True

    devs = list_devices(subject="opus@chef.skworld.io", base_dir=base)
    assert len(devs) == 1
    assert devs[0].revoked


def test_mirror_revocation_direct(tmp_path, monkeypatch):
    """mirror_revocation on its own revokes a previously mirrored tofu device."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    pub = _gen_pubkey()
    PM.mirror_pairing("lumina@chef.skworld.io", pub)
    assert not list_devices(subject="lumina@chef.skworld.io", base_dir=str(tmp_path))[0].revoked

    PM.mirror_revocation("lumina@chef.skworld.io")
    devs = list_devices(subject="lumina@chef.skworld.io", base_dir=str(tmp_path))
    assert len(devs) == 1 and devs[0].revoked


def test_remove_still_succeeds_when_mirror_raises(tmp_path, monkeypatch):
    """End-to-end: even if capauth.revoke blows up, the local peer removal still
    succeeds (mirror is additive, best-effort) and does not raise."""
    from skcomms.peers import list_peers, remove_peer

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))

    pub = _gen_pubkey()
    fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(
        PairingBundle(
            fqid="opus@chef.skworld.io", fingerprint=fp, syncthing_device_id="DEV-2", pubkey=pub
        )
    )
    accept_pairing(uri)
    assert "opus@chef.skworld.io" in list_peers()

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.revoke", _boom)
    # Must NOT raise, and must still remove the peer locally.
    assert remove_peer("opus@chef.skworld.io") is True
    assert "opus@chef.skworld.io" not in list_peers()


def test_mirror_revocation_is_fail_safe(tmp_path, monkeypatch):
    """A capauth failure never propagates out of mirror_revocation."""
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.list_devices", _boom)
    # Must NOT raise.
    PM.mirror_revocation("opus@chef.skworld.io")


def test_remove_unknown_peer_is_noop(tmp_path, monkeypatch):
    """remove_peer on an unknown fqid returns False and writes no capauth record."""
    from capauth.pairing import list_devices
    from skcomms.peers import remove_peer

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))
    assert remove_peer("ghost@chef.skworld.io") is False
    assert list_devices(subject="ghost@chef.skworld.io", base_dir=str(tmp_path / "capauth")) == []


def test_revocation_kernel_disabled_writes_nothing(tmp_path, monkeypatch):
    """SKCOMMS_PAIRING_KERNEL=0 disables the revocation mirror too."""
    from capauth.pairing import list_devices

    # Seed a live device with the kernel ON, then flip it OFF for the revocation.
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    PM.mirror_pairing("opus@chef.skworld.io", _gen_pubkey())
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL", "0")
    PM.mirror_revocation("opus@chef.skworld.io")
    devs = list_devices(subject="opus@chef.skworld.io", base_dir=str(tmp_path))
    assert len(devs) == 1 and not devs[0].revoked


# ---------------------------------------------------------------------------
# M2 pairing fold, public-pairing surface: handle_public_pairing_request also
# mirrors the admitted peer into capauth.pairing (the SECOND pairing front door).
# Public pairing is also a TOFU add (import_peer_bundle persists the peer + its
# armored key), so the same mirror_pairing is correct.
# ---------------------------------------------------------------------------


def _peer_bundle(fqid="opus@chef.skworld.io", name="Testpeer"):
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


def test_public_pairing_mirrors_peer_into_capauth(tmp_path, monkeypatch):
    """A successful handle_public_pairing_request mirrors exactly one tofu
    capauth device whose subject is the peer's fqid."""
    from capauth.pairing import list_devices
    import skcomms.public_pairing as pp

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))
    bundle = _peer_bundle()
    res = pp.handle_public_pairing_request(
        {"bundle": bundle},
        peers_dir=tmp_path / "peers",
        self_bundle_provider=lambda: None,
    )
    assert res["paired"]["fqid"] == "opus@chef.skworld.io"

    devs = list_devices(subject="opus@chef.skworld.io", base_dir=str(tmp_path / "capauth"))
    assert len(devs) == 1
    assert devs[0].subject == "opus@chef.skworld.io"
    assert str(getattr(devs[0].mode, "value", devs[0].mode)) == "tofu"


def test_public_pairing_still_succeeds_when_mirror_raises(tmp_path, monkeypatch):
    """End-to-end: even if capauth.enroll_device blows up, the public pairing
    succeeds and returns its normal payload (mirror is additive, best-effort)."""
    import skcomms.public_pairing as pp

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.enroll_device", _boom)
    bundle = _peer_bundle()
    res = pp.handle_public_pairing_request(
        {"bundle": bundle},
        peers_dir=tmp_path / "peers",
        self_bundle_provider=lambda: None,
    )
    assert res["paired"]["fqid"] == "opus@chef.skworld.io"
    assert res["paired"]["fingerprint"] == bundle["fingerprint"]


def test_public_pairing_kernel_disabled_writes_nothing(tmp_path, monkeypatch):
    """SKCOMMS_PAIRING_KERNEL=0 disables the public-pairing mirror: the peer is
    still admitted locally but no capauth device is created."""
    from capauth.pairing import list_devices
    import skcomms.public_pairing as pp

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL", "0")
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))
    bundle = _peer_bundle()
    res = pp.handle_public_pairing_request(
        {"bundle": bundle},
        peers_dir=tmp_path / "peers",
        self_bundle_provider=lambda: None,
    )
    assert res["paired"]["fqid"] == "opus@chef.skworld.io"
    assert list_devices(subject="opus@chef.skworld.io", base_dir=str(tmp_path / "capauth")) == []


# ── idempotency (trust on FIRST use, not on every use) ───────────────────


# Deliberately NOT shaped like real base64 key material. mirror_pairing only
# needs two distinct opaque strings (it stores them and fingerprints them), and
# a realistic-looking prefix made the secret scanner flag these as a leaked
# key. Suppressing that with an allowlist entry would blunt a gate that only
# started working on 2026-08-14 (see the secret-scan workflow), so the fixture
# avoids tripping it in the first place.
_KEY_A = "not-a-real-key-fixture-alpha"
_KEY_B = "not-a-real-key-fixture-bravo"


def test_re_mirroring_the_same_key_does_not_mint_a_second_device(tmp_path, monkeypatch):
    """Repeated accepts of one peer+key must converge on ONE device record.

    Regression pin for the observed drift: opus@chef.skworld.io accumulated 22
    approved TOFU records in a single afternoon because every accept called
    enroll_device + approve unconditionally.
    """
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    from capauth.pairing.kernel import list_devices

    from skcomms.pairing_mirror import mirror_pairing

    for _ in range(5):
        mirror_pairing("peer@example.skworld.io", _KEY_A)

    devices = list_devices("peer@example.skworld.io", base_dir=tmp_path, include_revoked=True)
    assert len(devices) == 1


def test_a_genuinely_new_key_still_enrolls(tmp_path, monkeypatch):
    """The guard must not block a real second device for the same subject."""
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    from capauth.pairing.kernel import list_devices

    from skcomms.pairing_mirror import mirror_pairing

    mirror_pairing("peer@example.skworld.io", _KEY_A)
    mirror_pairing("peer@example.skworld.io", _KEY_B)

    devices = list_devices("peer@example.skworld.io", base_dir=tmp_path, include_revoked=True)
    assert len(devices) == 2

    # And re-presenting the first key still does not add a third.
    mirror_pairing("peer@example.skworld.io", _KEY_A)
    devices = list_devices("peer@example.skworld.io", base_dir=tmp_path, include_revoked=True)
    assert len(devices) == 2
