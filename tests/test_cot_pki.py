"""[CoT][CB3] PKI + ATAK data-package tests.

Cover the sovereign TLS-enrollment material end to end without a phone:

  * CA + server + client certs generate, chain-verify, carry the right SANs/EKUs,
  * the CA is idempotent (re-init doesn't regenerate),
  * ``build_data_package`` emits a valid ATAK ``.zip`` (manifest + 2 p12s + pref)
    with the SSL connectString / host / port and importable PKCS#12 stores,
  * the device→identity mapping is realm-namespaced.
"""

from __future__ import annotations

import zipfile

import pytest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from skcomms import cot_pki


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    """Point SKCOMMS_HOME at a temp dir so the PKI is built in isolation."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    # cluster/identity may not resolve in CI — device_identity must still work.
    yield


def _load_pem_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_ca_create_and_idempotent():
    cert1, _ = cot_pki.init_ca()
    assert cert1.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "SKFed CoT CA"
    # CA is a CA cert
    bc = cert1.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    # idempotent: same serial on re-init (loaded, not regenerated)
    cert2, _ = cot_pki.init_ca()
    assert cert1.serial_number == cert2.serial_number
    assert (cot_pki.pki_dir() / "ca.pem").exists()
    assert (cot_pki.pki_dir() / "ca.key").exists()


def test_server_cert_has_sans_and_serverauth():
    sans = ["100.108.59.57", "noroc2027.tail204f0c.ts.net"]
    sp, sk = cot_pki.init_server_cert(sans)
    cert = _load_pem_cert(sp)
    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san_ext.get_values_for_type(x509.DNSName)
    ips = [str(i) for i in san_ext.get_values_for_type(x509.IPAddress)]
    assert "noroc2027.tail204f0c.ts.net" in dns
    assert "100.108.59.57" in ips
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert sk.exists()


def test_server_cert_chains_to_ca():
    ca_cert, ca_key = cot_pki.init_ca()
    sp, _ = cot_pki.init_server_cert()
    server = _load_pem_cert(sp)
    # server cert was signed by the CA's public key (raises on bad signature)
    ca_key.public_key().verify(
        server.signature,
        server.tbs_certificate_bytes,
        __import__("cryptography.hazmat.primitives.asymmetric.padding", fromlist=["PKCS1v15"]).PKCS1v15(),
        server.signature_hash_algorithm,
    )
    assert server.issuer == ca_cert.subject


def test_device_cert_clientauth_and_chains():
    ca_cert, ca_key = cot_pki.init_ca()
    pem, keyp = cot_pki.mint_device_cert("chef-pixel")
    cert = _load_pem_cert(pem)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "chef-pixel"
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert cert.issuer == ca_cert.subject
    # idempotent re-mint returns same serial
    pem2, _ = cot_pki.mint_device_cert("chef-pixel")
    assert _load_pem_cert(pem2).serial_number == cert.serial_number
    assert keyp.exists()


def test_device_identity_mapping():
    # Whether or not cluster resolves, the device name is namespaced sensibly.
    ident = cot_pki.device_identity("chef-pixel")
    assert "chef-pixel" in ident
    assert ident.startswith("chef-pixel@") or ident == "device:chef-pixel"


def test_fingerprint_format():
    cert, _ = cot_pki.init_ca()
    fp = cot_pki.cert_fingerprint(cert)
    parts = fp.split(":")
    assert len(parts) == 32  # SHA-256 = 32 bytes
    assert all(len(p) == 2 for p in parts)


def test_data_package_is_valid_zip_with_all_parts():
    dp = cot_pki.build_data_package("chef-pixel", "100.108.59.57", port=8089)
    assert dp.path.exists()
    assert dp.connect_string == "100.108.59.57:8089:ssl"
    assert dp.host == "100.108.59.57" and dp.port == 8089
    assert "chef-pixel" in dp.identity
    assert len(dp.fingerprint.split(":")) == 32

    with zipfile.ZipFile(dp.path) as z:
        names = set(z.namelist())
        assert "MANIFEST/manifest.xml" in names
        assert "cert/truststore-CA.p12" in names
        assert "cert/chef-pixel.p12" in names
        assert "chef-pixel.pref" in names

        manifest = z.read("MANIFEST/manifest.xml").decode()
        assert "onReceiveImport" in manifest
        assert "cert/chef-pixel.p12" in manifest
        assert "cert/truststore-CA.p12" in manifest

        pref = z.read("chef-pixel.pref").decode()
        assert "100.108.59.57:8089:ssl" in pref           # connectString
        assert "cot_streams" in pref
        assert "cert/truststore-CA.p12" in pref
        assert "cert/chef-pixel.p12" in pref
        assert "atakatak" in pref                          # default p12 password

        # the two p12 blobs actually load with the default password
        ts = z.read("cert/truststore-CA.p12")
        key, cert, cas = pkcs12.load_key_and_certificates(ts, b"atakatak")
        assert key is None and cert is None and len(cas) == 1   # truststore = CA only

        ks = z.read("cert/chef-pixel.p12")
        ckey, ccert, ccas = pkcs12.load_key_and_certificates(ks, b"atakatak")
        assert ckey is not None and ccert is not None           # client keystore
        assert ccert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "chef-pixel"


def test_data_package_custom_host_port():
    dp = cot_pki.build_data_package("itak-1", "noroc2027.tail204f0c.ts.net", port=8090)
    assert dp.connect_string == "noroc2027.tail204f0c.ts.net:8090:ssl"
    with zipfile.ZipFile(dp.path) as z:
        pref = z.read("itak-1.pref").decode()
        assert "noroc2027.tail204f0c.ts.net:8090:ssl" in pref
