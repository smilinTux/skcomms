"""[CoT][CB3] PKI + ATAK data-package generator — TLS-enrolled TAK over the tailnet.

A real ATAK/iTAK phone connects to a "TAK Server" over **TLS (:8089)** using the
standard *enrolled-server* flow: the operator imports ONE **data package** (.zip)
and ATAK auto-configures the connection + trusts our node. This module provides:

  * a tiny in-house **PKI** (``cryptography`` lib): a self-signed CA, a server cert
    (CN + SANs = the node's tailnet IP / MagicDNS), and per-device client certs all
    signed by that CA — persisted, idempotent, no OpenSSL CLI needed;
  * :func:`build_data_package` — produces a valid ATAK data-package ``.zip``
    (``MANIFEST/manifest.xml`` + ``truststore-CA.p12`` + ``<device>.p12`` client
    keystore + a ``*.pref`` with the SSL ``connectString``), the single file the
    operator imports into ATAK.

The TLS client cert binds the device to a sovereign capauth/skcomms identity that
is **TOFU-pinned** (see :mod:`skcomms.tofu`) on first connect — NOT a shared PSK.
This rides the tailnet, sidestepping the multicast/LAN constraint entirely.

PKI layout (under ``${SKCOMMS_HOME:-~/.skcapstone/skcomms}/cot-pki/``)::

    cot-pki/
      ca.pem   ca.key            # the sovereign TAK CA (root of trust)
      server.pem server.key      # the :8089 server cert (SANs = tailnet IP + MagicDNS)
      devices/<name>.p12         # per-device client keystore (PKCS#12)
      devices/<name>.pem/.key    # the same device cert/key in PEM (for tests/tooling)
      packages/<name>.zip        # generated ATAK data packages

CLI (``python -m skcomms.cot_pki``)::

    python -m skcomms.cot_pki init                       # create CA + server cert
    python -m skcomms.cot_pki mint  <device>             # mint a device cert
    python -m skcomms.cot_pki package <device> [--host H] # build the .zip data package
    python -m skcomms.cot_pki serve [--host H] [--port P] # run the TLS CoT server
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import logging
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence
from xml.sax.saxutils import quoteattr

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .home import skcomms_home

logger = logging.getLogger("skcomms.cot_pki")

# ATAK's universal default p12 password for data-package keystores/truststores.
DEFAULT_P12_PASSWORD = "atakatak"
DEFAULT_TLS_PORT = 8089

# This node's tailnet identity (overridable per call). Default = noroc2027 (.158).
NODE_TAILNET_IP = "100.108.59.57"
NODE_MAGICDNS = "noroc2027.tail204f0c.ts.net"

_CA_CN = "SKFed CoT CA"
_VALIDITY_DAYS = 3650  # 10y — sovereign infra, no public PKI lifecycle


def pki_dir() -> Path:
    """Directory holding the CoT PKI (``<SKCOMMS_HOME>/cot-pki``)."""
    return skcomms_home() / "cot-pki"


def devices_dir() -> Path:
    """Directory holding per-device certs/keystores."""
    return pki_dir() / "devices"


def packages_dir() -> Path:
    """Directory holding generated ATAK data packages (.zip)."""
    return pki_dir() / "packages"


# --------------------------------------------------------------------------- #
# low-level cert helpers
# --------------------------------------------------------------------------- #

def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _load_key(path: Path) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _san_entries(sans: Sequence[str]) -> list[x509.GeneralName]:
    """Map host strings to SAN entries — IPs as IPAddress, names as DNSName."""
    out: list[x509.GeneralName] = []
    for s in sans:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            out.append(x509.DNSName(s))
    return out


# --------------------------------------------------------------------------- #
# PKI material
# --------------------------------------------------------------------------- #

@dataclass
class CotPKI:
    """Resolved paths + loaded CA material for the CoT PKI."""

    ca_cert: x509.Certificate
    ca_key: rsa.RSAPrivateKey
    ca_pem: Path
    ca_key_path: Path
    server_pem: Path
    server_key_path: Path


def init_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Create (idempotently) the self-signed CA and return ``(cert, key)``.

    If ``ca.pem``/``ca.key`` already exist they are loaded and returned unchanged
    — the CA is the root of trust pinned in every device's truststore, so it must
    never be silently regenerated.
    """
    d = pki_dir()
    d.mkdir(parents=True, exist_ok=True)
    ca_pem, ca_key_path = d / "ca.pem", d / "ca.key"
    if ca_pem.exists() and ca_key_path.exists():
        return _load_cert(ca_pem), _load_key(ca_key_path)

    key = _gen_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_CN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - _dt.timedelta(minutes=1))
        .not_valid_after(_now() + _dt.timedelta(days=_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    _write_cert(ca_pem, cert)
    _write_key(ca_key_path, key)
    logger.info("created CoT CA at %s", ca_pem)
    return cert, key


def init_server_cert(
    sans: Optional[Sequence[str]] = None,
    *,
    cn: Optional[str] = None,
    force: bool = False,
) -> tuple[Path, Path]:
    """Create (idempotently) the server cert signed by the CA.

    Args:
        sans: Subject-Alternative-Names — the addresses ATAK will connect to.
            Defaults to the node's tailnet IP + MagicDNS. IP-shaped entries are
            emitted as ``IPAddress`` SANs, others as ``DNSName``.
        cn: Subject CN (defaults to the first SAN).
        force: Regenerate even if ``server.pem`` exists (e.g. SANs changed).

    Returns:
        ``(server.pem, server.key)`` paths.
    """
    sans = list(sans) if sans else [NODE_TAILNET_IP, NODE_MAGICDNS]
    cn = cn or sans[0]
    d = pki_dir()
    server_pem, server_key = d / "server.pem", d / "server.key"
    if server_pem.exists() and server_key.exists() and not force:
        return server_pem, server_key

    ca_cert, ca_key = init_ca()
    key = _gen_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - _dt.timedelta(minutes=1))
        .not_valid_after(_now() + _dt.timedelta(days=_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(_san_entries(sans)), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_cert(server_pem, cert)
    _write_key(server_key, key)
    logger.info("created CoT server cert at %s (SANs=%s)", server_pem, sans)
    return server_pem, server_key


def mint_device_cert(device_name: str, *, force: bool = False) -> tuple[Path, Path]:
    """Mint (idempotently) a per-device client cert signed by the CA.

    The cert's CN is *device_name*; it carries ``clientAuth`` EKU so ATAK can use
    it as a TLS client keystore. Writes both PEM (``devices/<name>.pem`` +
    ``.key``) and is the basis for the PKCS#12 keystore built later.

    Args:
        device_name: Logical device handle (e.g. ``chef-pixel``). Also the cert CN.
        force: Re-mint even if a cert already exists.

    Returns:
        ``(devices/<name>.pem, devices/<name>.key)`` paths.
    """
    dd = devices_dir()
    dd.mkdir(parents=True, exist_ok=True)
    pem, keyp = dd / f"{device_name}.pem", dd / f"{device_name}.key"
    if pem.exists() and keyp.exists() and not force:
        return pem, keyp

    ca_cert, ca_key = init_ca()
    key = _gen_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - _dt.timedelta(minutes=1))
        .not_valid_after(_now() + _dt.timedelta(days=_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_cert(pem, cert)
    _write_key(keyp, key)
    logger.info("minted device cert for %s at %s", device_name, pem)
    return pem, keyp


def cert_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint of a cert as ``AA:BB:...`` uppercase hex (TOFU key)."""
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def device_identity(device_name: str) -> str:
    """The skcomms identity string a device's connection is attributed to.

    Combines this node's resolved self-fqid realm/operator with the device name
    so a device handle is namespaced to the operator who enrolled it, e.g.
    ``chef-pixel@chef.skworld``. Falls back to a bare ``device:<name>`` handle if
    the cluster/identity is not resolvable.
    """
    try:
        from .identity import resolve_self_identity

        fqid = resolve_self_identity().get("fqid")
        if fqid and "@" in fqid:
            _, rest = fqid.split("@", 1)
            return f"{device_name}@{rest}"
    except Exception:  # noqa: BLE001
        pass
    return f"device:{device_name}"


# --------------------------------------------------------------------------- #
# PKCS#12 keystore/truststore builders (for the data package)
# --------------------------------------------------------------------------- #

def _truststore_p12(
    ca_cert: x509.Certificate, *, password: str = DEFAULT_P12_PASSWORD
) -> bytes:
    """A PKCS#12 truststore containing just the CA cert (no private key).

    ATAK pins this as the set of CAs it will trust for the server's TLS cert.
    """
    return pkcs12.serialize_key_and_certificates(
        name=b"SKFed CoT CA",
        key=None,
        cert=None,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


def _client_keystore_p12(
    device_name: str,
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    password: str = DEFAULT_P12_PASSWORD,
) -> bytes:
    """A PKCS#12 client keystore: device key + cert (+ CA in the chain)."""
    return pkcs12.serialize_key_and_certificates(
        name=device_name.encode(),
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


# --------------------------------------------------------------------------- #
# data-package XML
# --------------------------------------------------------------------------- #

def _manifest_xml(uid: str, files: Sequence[str], name: str) -> str:
    """ATAK data-package ``manifest.xml`` listing the package contents.

    Each ``<Content>`` is zipPath-relative; ``onReceiveImport=true`` makes ATAK
    auto-apply the connection profile on import.
    """
    entries = "\n".join(
        f'    <Content ignore="false" zipEntry={quoteattr(f)} />' for f in files
    )
    return (
        '<MissionPackageManifest version="2">\n'
        "  <Configuration>\n"
        f'    <Parameter name="uid" value={quoteattr(uid)} />\n'
        f'    <Parameter name="name" value={quoteattr(name)} />\n'
        '    <Parameter name="onReceiveImport" value="true" />\n'
        '    <Parameter name="onReceiveDelete" value="false" />\n'
        "  </Configuration>\n"
        "  <Contents>\n"
        f"{entries}\n"
        "  </Contents>\n"
        "</MissionPackageManifest>\n"
    )


def _connect_string(host: str, port: int) -> str:
    """ATAK SSL connectString: ``<host>:<port>:ssl``."""
    return f"{host}:{port}:ssl"


def _pref_xml(
    device_name: str,
    host: str,
    port: int,
    *,
    truststore_zippath: str,
    keystore_zippath: str,
    password: str = DEFAULT_P12_PASSWORD,
) -> str:
    """ATAK ``.pref`` (cot_streams) — the enrolled-server connection profile.

    Sets the streaming connection (``connectString0`` = ``host:port:ssl``), wires
    the truststore + client keystore (cert locations are ``cert/`` relative inside
    ATAK's import) and their passwords, and disables enrollment-for-cert (we ship
    the client cert in the package, no CA-server enrollment round-trip).
    """
    cs = _connect_string(host, port)
    desc = f"SKFed CoT ({device_name})"
    return (
        '<?xml version="1.0" standalone="yes"?>\n'
        "<preferences>\n"
        '  <preference version="1" name="cot_streams">\n'
        '    <entry key="count" class="class java.lang.Integer">1</entry>\n'
        f'    <entry key="description0" class="class java.lang.String">{desc}</entry>\n'
        '    <entry key="enabled0" class="class java.lang.Boolean">true</entry>\n'
        '    <entry key="useAuth0" class="class java.lang.Boolean">false</entry>\n'
        f'    <entry key="connectString0" class="class java.lang.String">{cs}</entry>\n'
        '    <entry key="caLocation0" class="class java.lang.String">'
        f'cert/{truststore_zippath}</entry>\n'
        f'    <entry key="caPassword0" class="class java.lang.String">{password}</entry>\n'
        '    <entry key="clientPassword0" class="class java.lang.String">'
        f'{password}</entry>\n'
        '    <entry key="certificateLocation0" class="class java.lang.String">'
        f'cert/{keystore_zippath}</entry>\n'
        '    <entry key="enrollForCertificateWithTrust0" '
        'class="class java.lang.Boolean">false</entry>\n'
        "  </preference>\n"
        '  <preference version="1" name="com.atakmap.app_preferences">\n'
        '    <entry key="displayServerConnectionWidget" '
        'class="class java.lang.Boolean">true</entry>\n'
        "  </preference>\n"
        "</preferences>\n"
    )


# --------------------------------------------------------------------------- #
# the public builder
# --------------------------------------------------------------------------- #

@dataclass
class DataPackage:
    """Result of :func:`build_data_package`."""

    path: Path
    device_name: str
    host: str
    port: int
    connect_string: str
    identity: str
    fingerprint: str


def build_data_package(
    device_name: str,
    host: str,
    *,
    port: int = DEFAULT_TLS_PORT,
    password: str = DEFAULT_P12_PASSWORD,
    out_path: Optional[Path] = None,
) -> DataPackage:
    """Build an ATAK data-package ``.zip`` enrolling *device_name* to this node.

    The package contains everything ATAK needs to auto-configure + trust the
    :8089 TLS endpoint on first import:

      * ``MANIFEST/manifest.xml`` — package manifest (``onReceiveImport=true``),
      * ``cert/truststore-CA.p12`` — the CA (server-trust anchor),
      * ``cert/<device>.p12`` — the device's client keystore (key + cert),
      * ``<device>.pref`` — the ``cot_streams`` profile with the SSL connectString.

    The CA + server cert are created on demand if absent; the device cert is
    minted if absent. The device's client-cert SHA-256 fingerprint is returned so
    the caller can pre-pin it / log the TOFU identity binding.

    Args:
        device_name: Logical device handle (cert CN + keystore name).
        host: The address the phone will dial (e.g. the tailnet IP/MagicDNS).
        port: TLS port (default 8089).
        password: PKCS#12 password (ATAK default ``atakatak``).
        out_path: Override the output ``.zip`` path.

    Returns:
        A :class:`DataPackage` with the ``.zip`` path, connectString, the mapped
        device identity, and the client-cert fingerprint.
    """
    ca_cert, _ = init_ca()
    init_server_cert()  # ensure a server cert exists (SANs = node tailnet defaults)
    cert_pem, key_pem = mint_device_cert(device_name)
    cert = _load_cert(cert_pem)
    key = _load_key(key_pem)

    truststore_name = "truststore-CA.p12"
    keystore_name = f"{device_name}.p12"
    pref_name = f"{device_name}.pref"

    truststore = _truststore_p12(ca_cert, password=password)
    keystore = _client_keystore_p12(device_name, cert, key, ca_cert, password=password)
    pref = _pref_xml(
        device_name, host, port,
        truststore_zippath=truststore_name,
        keystore_zippath=keystore_name,
        password=password,
    )
    uid = f"skfed-cot-{device_name}"
    manifest_files = [
        f"cert/{truststore_name}",
        f"cert/{keystore_name}",
        pref_name,
    ]
    manifest = _manifest_xml(uid, manifest_files, name=f"SKFed CoT {device_name}")

    if out_path is None:
        packages_dir().mkdir(parents=True, exist_ok=True)
        out_path = packages_dir() / f"{device_name}.zip"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("MANIFEST/manifest.xml", manifest)
        z.writestr(f"cert/{truststore_name}", truststore)
        z.writestr(f"cert/{keystore_name}", keystore)
        z.writestr(pref_name, pref)

    cs = _connect_string(host, port)
    ident = device_identity(device_name)
    fp = cert_fingerprint(cert)
    logger.info(
        "built data package %s (connectString=%s identity=%s fp=%s)",
        out_path, cs, ident, fp,
    )
    return DataPackage(
        path=out_path,
        device_name=device_name,
        host=host,
        port=port,
        connect_string=cs,
        identity=ident,
        fingerprint=fp,
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _cli(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    p = argparse.ArgumentParser(prog="python -m skcomms.cot_pki", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="create CA + server cert (idempotent)")
    p_init.add_argument("--san", action="append", help="server SAN (repeatable)")

    p_mint = sub.add_parser("mint", help="mint a per-device client cert")
    p_mint.add_argument("device")

    p_pkg = sub.add_parser("package", help="build a device's ATAK data package .zip")
    p_pkg.add_argument("device")
    p_pkg.add_argument("--host", default=NODE_TAILNET_IP)
    p_pkg.add_argument("--port", type=int, default=DEFAULT_TLS_PORT)

    p_srv = sub.add_parser("serve", help="run the TLS CoT server")
    p_srv.add_argument("--host", default="0.0.0.0")
    p_srv.add_argument("--port", type=int, default=DEFAULT_TLS_PORT)

    args = p.parse_args(argv)

    if args.cmd == "init":
        ca_cert, _ = init_ca()
        sp, _ = init_server_cert(args.san)
        print(f"CA: {pki_dir()/'ca.pem'}  fp={cert_fingerprint(ca_cert)}")
        print(f"server cert: {sp}")
        return 0

    if args.cmd == "mint":
        pem, _ = mint_device_cert(args.device)
        print(f"device cert: {pem}  fp={cert_fingerprint(_load_cert(pem))}")
        print(f"identity:    {device_identity(args.device)}")
        return 0

    if args.cmd == "package":
        dp = build_data_package(args.device, args.host, port=args.port)
        print(f"data package: {dp.path}")
        print(f"connectString: {dp.connect_string}")
        print(f"identity:      {dp.identity}")
        print(f"client fp:     {dp.fingerprint}")
        print(
            "\nOperator steps:\n"
            f"  1. transfer {dp.path} to the phone\n"
            "  2. ATAK → ☰ → Import → Local SD → pick the .zip (or share-to-ATAK)\n"
            f"  3. ATAK auto-adds the server; connect to {dp.connect_string}"
        )
        return 0

    if args.cmd == "serve":
        import asyncio

        from .cot_service import main as _serve_main

        import os

        os.environ["SKCOMMS_COT_TLS"] = "1"
        os.environ["SKCOMMS_COT_TLS_PORT"] = str(args.port)
        os.environ.setdefault("SKCOMMS_COT_HOST", args.host)
        asyncio.run(_serve_main())
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
