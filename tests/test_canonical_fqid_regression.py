"""Regression pin: skcomms never enrolls a non-canonical subject in capauth.

Why this file exists
--------------------
``sk-standards/standards/IDENTITY_NAMING_STANDARD.md`` (ratified 2026-08-14)
defines ONE subject grammar, the fqid: ``<agent>@<operator>.<org-domain>``,
lowercase ASCII. capauth enforces it in ``capauth.subject.canonical_subject``,
called from ``capauth.pairing.enroll_device``.

skcomms' fixtures had drifted to a TLD-less ``<agent>@<operator>.skworld``
spelling, so :mod:`skcomms.pairing_mirror` was handing capauth subjects it now
refuses. Renaming those strings alone would leave the door open: the mirror is
deliberately best-effort (every capauth error is logged at debug and swallowed
so a mirror failure can never break a live pairing), which means a
non-canonical subject fails **silently** with nothing enrolled and no
exception raised. That is exactly the failure shape this file pins, so the
invalid form cannot quietly come back.

Each assertion below carries its own negative control: the SAME call with a
canonical subject must succeed, so a green bar proves the subject SHAPE is
what got refused rather than the test plumbing being broken.
"""

from __future__ import annotations

import pgpy
import pytest
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from skcomms.pairing_mirror import mirror_pairing

#: A canonical fqid: local-part @ operator segment . org-domain, all lowercase
#: ASCII (IDENTITY_NAMING_STANDARD sec 1, "Agents" row).
CANONICAL_FQID = "regress@example.skworld.io"

#: The same identity with the org-domain TLD missing. The standard's
#: legacy-shape table calls this out explicitly: a missing domain is not a
#: spelling variant of a valid identity, it is an invalid record that must be
#: re-enrolled under a real fqid.
TLD_LESS_FQID = "regress@example.skworld"


def _gen_pubkey(uid: str = "regress <regress@example.skworld.io>") -> str:
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key.pubkey)


@pytest.fixture
def kernel_base(tmp_path, monkeypatch):
    """Point the pairing mirror at a tmp capauth root, kernel ON."""
    monkeypatch.delenv("SKCOMMS_PAIRING_KERNEL", raising=False)  # default ON
    base = str(tmp_path / "capauth")
    monkeypatch.setenv("SKCOMMS_PAIRING_KERNEL_BASE", base)
    return base


def _devices(subject: str, base: str):
    from capauth.pairing import list_devices

    return list_devices(subject=subject, base_dir=base, include_revoked=True)


def test_canonical_normalizer_refuses_a_tld_less_subject():
    """capauth refuses the TLD-less shape outright, and accepts the canonical one."""
    from capauth.exceptions import SubjectNamingError
    from capauth.subject import canonical_subject

    with pytest.raises(SubjectNamingError):
        canonical_subject(TLD_LESS_FQID)

    # Negative control: the only difference is the missing org-domain tail.
    assert canonical_subject(CANONICAL_FQID) == CANONICAL_FQID


def test_mirror_pairing_enrolls_nothing_for_a_tld_less_subject(kernel_base):
    """The mirror's swallow-everything contract must not become a silent back door.

    The call is a no-op rather than a raise (best-effort by design), so the
    assertion has to be on the STORE, not on an exception.
    """
    mirror_pairing(TLD_LESS_FQID, _gen_pubkey())

    assert _devices(TLD_LESS_FQID, kernel_base) == []
    # It must not have landed under a "helpfully repaired" spelling either.
    assert _devices(CANONICAL_FQID, kernel_base) == []


def test_mirror_pairing_enrolls_a_canonical_subject(kernel_base):
    """Negative control for the test above: the same call path DOES enrol a
    canonical fqid, so an empty store there means the shape was refused."""
    mirror_pairing(CANONICAL_FQID, _gen_pubkey())

    devices = _devices(CANONICAL_FQID, kernel_base)
    assert len(devices) == 1
    assert devices[0].subject == CANONICAL_FQID


def test_no_tld_less_fqid_literals_survive_in_the_test_suite():
    """The fixture sweep must stay swept.

    A single re-introduced ``@<operator>.skworld`` literal is enough to bring
    the original four-test failure back, and it fails as a confusing empty
    store rather than as a naming error. Catch it at the source instead.
    """
    import re
    from pathlib import Path

    tests_dir = Path(__file__).resolve().parent
    # A fqid whose domain ends at ".skworld" with no TLD after it.
    pattern = re.compile(r"@[a-z0-9][a-z0-9-]*\.skworld(?![.a-z0-9-])")

    # test_mailbox_recipient_key.py deliberately feeds the drifted realm form
    # to _load_recipient_key to prove the operator-component match still
    # resolves it; that legacy string is the point of the test.
    allowed = {"test_mailbox_recipient_key.py", Path(__file__).name}

    offenders = []
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name in allowed:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")

    assert not offenders, (
        "TLD-less fqid literals are back in the test suite; the canonical form is "
        "<agent>@<operator>.<org-domain> per IDENTITY_NAMING_STANDARD:\n  "
        + "\n  ".join(offenders)
    )
