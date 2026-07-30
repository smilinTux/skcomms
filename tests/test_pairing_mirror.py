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
        PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm,
    )
    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("t", email="t@x")
    k.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256],
              ciphers=[SymmetricKeyAlgorithm.AES256], compression=[CompressionAlgorithm.ZLIB])
    return str(k.pubkey)


def test_accept_mirrors_peer_into_capauth(tmp_path, monkeypatch):
    """A successful accept_pairing creates exactly one tofu capauth device whose
    subject is the peer's fqid."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))
    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-2", pubkey=pub))
    rec = accept_pairing(uri)
    assert rec["fqid"] == "opus@chef.skworld"

    devs = list_devices(subject="opus@chef.skworld", base_dir=str(tmp_path / "capauth"))
    assert len(devs) == 1
    assert devs[0].subject == "opus@chef.skworld"
    assert str(getattr(devs[0].mode, "value", devs[0].mode)) == "tofu"


def test_mirror_pairing_direct(tmp_path, monkeypatch):
    """mirror_pairing on its own records a tofu device under the base override."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    pub = _gen_pubkey()
    PM.mirror_pairing("lumina@chef.skworld", pub)
    devs = list_devices(subject="lumina@chef.skworld", base_dir=str(tmp_path))
    assert len(devs) == 1
    assert str(getattr(devs[0].mode, "value", devs[0].mode)) == "tofu"


def test_mirror_is_fail_safe(tmp_path, monkeypatch):
    """A capauth failure never propagates out of mirror_pairing."""
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.enroll_device", _boom)
    # Must NOT raise.
    PM.mirror_pairing("opus@chef.skworld", _gen_pubkey())


def test_accept_still_succeeds_when_mirror_raises(tmp_path, monkeypatch):
    """End-to-end: even if capauth.enroll_device blows up, the pairing succeeds
    and the peer is TOFU-added locally (mirror is additive, best-effort)."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.enroll_device", _boom)
    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-2", pubkey=pub))
    rec = accept_pairing(uri)
    assert rec["fqid"] == "opus@chef.skworld"
    from skcomms.peers import list_peers
    assert "opus@chef.skworld" in list_peers()


def test_kernel_disabled_writes_nothing(tmp_path, monkeypatch):
    """SKCOMMS_PAIRING_KERNEL=0 disables the mirror: no capauth device created."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL", "0")
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    PM.mirror_pairing("opus@chef.skworld", _gen_pubkey())
    assert list_devices(subject="opus@chef.skworld", base_dir=str(tmp_path)) == []


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

    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-2", pubkey=pub))
    accept_pairing(uri)
    devs = list_devices(subject="opus@chef.skworld", base_dir=base)
    assert len(devs) == 1 and not devs[0].revoked

    assert remove_peer("opus@chef.skworld") is True

    devs = list_devices(subject="opus@chef.skworld", base_dir=base)
    assert len(devs) == 1
    assert devs[0].revoked


def test_mirror_revocation_direct(tmp_path, monkeypatch):
    """mirror_revocation on its own revokes a previously mirrored tofu device."""
    from capauth.pairing import list_devices

    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    pub = _gen_pubkey()
    PM.mirror_pairing("lumina@chef.skworld", pub)
    assert not list_devices(subject="lumina@chef.skworld", base_dir=str(tmp_path))[0].revoked

    PM.mirror_revocation("lumina@chef.skworld")
    devs = list_devices(subject="lumina@chef.skworld", base_dir=str(tmp_path))
    assert len(devs) == 1 and devs[0].revoked


def test_remove_still_succeeds_when_mirror_raises(tmp_path, monkeypatch):
    """End-to-end: even if capauth.revoke blows up, the local peer removal still
    succeeds (mirror is additive, best-effort) and does not raise."""
    from skcomms.peers import list_peers, remove_peer

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))

    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-2", pubkey=pub))
    accept_pairing(uri)
    assert "opus@chef.skworld" in list_peers()

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.revoke", _boom)
    # Must NOT raise, and must still remove the peer locally.
    assert remove_peer("opus@chef.skworld") is True
    assert "opus@chef.skworld" not in list_peers()


def test_mirror_revocation_is_fail_safe(tmp_path, monkeypatch):
    """A capauth failure never propagates out of mirror_revocation."""
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))

    def _boom(*a, **k):
        raise RuntimeError("capauth down")

    monkeypatch.setattr("capauth.pairing.list_devices", _boom)
    # Must NOT raise.
    PM.mirror_revocation("opus@chef.skworld")


def test_remove_unknown_peer_is_noop(tmp_path, monkeypatch):
    """remove_peer on an unknown fqid returns False and writes no capauth record."""
    from capauth.pairing import list_devices
    from skcomms.peers import remove_peer

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "skcomms"))
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path / "capauth"))
    assert remove_peer("ghost@chef.skworld") is False
    assert list_devices(subject="ghost@chef.skworld",
                        base_dir=str(tmp_path / "capauth")) == []


def test_revocation_kernel_disabled_writes_nothing(tmp_path, monkeypatch):
    """SKCOMMS_PAIRING_KERNEL=0 disables the revocation mirror too."""
    from capauth.pairing import list_devices

    # Seed a live device with the kernel ON, then flip it OFF for the revocation.
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", str(tmp_path))
    PM.mirror_pairing("opus@chef.skworld", _gen_pubkey())
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL", "0")
    PM.mirror_revocation("opus@chef.skworld")
    devs = list_devices(subject="opus@chef.skworld", base_dir=str(tmp_path))
    assert len(devs) == 1 and not devs[0].revoked
