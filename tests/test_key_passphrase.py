"""Unified passphrase resolution (chiap08 send-path stopgap).

One helper, ``skcomms.crypto.resolve_key_passphrase``, feeds every key-unlock
path: EnvelopeCrypto.from_capauth (the transport send path, which previously
hardcoded ``""`` and could never open a passphrase-protected key), mailbox
signing, and the mailbox at-rest reader. These tests never read or print a
real passphrase: the value under test is a synthetic sentinel.
"""

from __future__ import annotations

import json
from pathlib import Path

import skcomms.mailbox as mailbox
from skcomms import crypto as crypto_mod
from skcomms.crypto import EnvelopeCrypto, resolve_key_passphrase

SENTINEL = "synthetic-test-passphrase"  # noqa: S105 (not a real secret)


def test_env_set_is_used(monkeypatch) -> None:
    monkeypatch.setenv(crypto_mod.KEY_PASSPHRASE_ENV_VAR, SENTINEL)
    assert resolve_key_passphrase() == SENTINEL


def test_env_unset_defaults_empty(monkeypatch) -> None:
    monkeypatch.delenv(crypto_mod.KEY_PASSPHRASE_ENV_VAR, raising=False)
    assert resolve_key_passphrase() == ""


def _capauth_dir(tmp_path: Path) -> Path:
    identity = tmp_path / "identity"
    identity.mkdir(parents=True)
    (identity / "private.asc").write_text("synthetic armor", encoding="utf-8")
    (identity / "profile.json").write_text(
        json.dumps({"key_info": {"fingerprint": "A" * 40}}), encoding="utf-8"
    )
    return tmp_path


def test_from_capauth_uses_resolved_passphrase(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(crypto_mod.KEY_PASSPHRASE_ENV_VAR, SENTINEL)
    crypto = EnvelopeCrypto.from_capauth(capauth_dir=_capauth_dir(tmp_path))
    assert crypto is not None
    assert crypto._passphrase == SENTINEL  # noqa: SLF001 — test-only state check


def test_from_capauth_defaults_empty(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(crypto_mod.KEY_PASSPHRASE_ENV_VAR, raising=False)
    crypto = EnvelopeCrypto.from_capauth(capauth_dir=_capauth_dir(tmp_path))
    assert crypto is not None
    assert crypto._passphrase == ""  # noqa: SLF001 — test-only state check


def _identity_dir(tmp_path: Path) -> Path:
    identity = tmp_path / "agents" / "lumina" / "capauth" / "identity"
    identity.mkdir(parents=True, exist_ok=True)
    (identity / "private.asc").write_text("synthetic armor", encoding="utf-8")
    return identity


def test_mailbox_signer_consults_the_helper(monkeypatch, tmp_path) -> None:
    _identity_dir(tmp_path)
    monkeypatch.setattr(mailbox, "_agent_identity_dir", lambda agent: _identity_dir(tmp_path))
    monkeypatch.setattr(mailbox, "resolve_key_passphrase", lambda: SENTINEL)
    seen = {}

    class _Recorder:
        def __init__(self, armor: str, passphrase: str) -> None:
            seen["passphrase"] = passphrase

    monkeypatch.setattr(mailbox, "EnvelopeSigner", _Recorder)
    mailbox._load_signer("lumina")  # noqa: SLF001 — test-only seam
    assert seen["passphrase"] == SENTINEL


def test_mailbox_reader_crypto_consults_the_helper(monkeypatch, tmp_path) -> None:
    _identity_dir(tmp_path)
    monkeypatch.setattr(mailbox, "_agent_identity_dir", lambda agent: _identity_dir(tmp_path))
    monkeypatch.setattr(mailbox, "resolve_key_passphrase", lambda: SENTINEL)
    seen = {}

    class _Recorder:
        def __init__(self, private_key_armor: str, passphrase: str) -> None:
            seen["passphrase"] = passphrase

    monkeypatch.setattr(mailbox, "EnvelopeCrypto", _Recorder)
    mailbox._reader_crypto_for("lumina")  # noqa: SLF001 — test-only seam
    assert seen["passphrase"] == SENTINEL


def test_grants_signer_consults_the_helper(monkeypatch, tmp_path) -> None:
    import skcomms.grants as grants

    _identity_dir(tmp_path)
    monkeypatch.setattr(grants, "_agent_identity_dir", lambda agent: _identity_dir(tmp_path))
    monkeypatch.setattr(grants, "resolve_key_passphrase", lambda: SENTINEL)
    seen = {}

    class _Recorder:
        def __init__(self, armor: str, passphrase: str) -> None:
            seen["passphrase"] = passphrase

    monkeypatch.setattr(grants, "EnvelopeSigner", _Recorder)
    grants._load_signer("lumina")  # noqa: SLF001 — test-only seam
    assert seen["passphrase"] == SENTINEL
