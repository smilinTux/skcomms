"""``skcomms consent`` operator MANAGEMENT subcommands.

Covers the policy / feeds / tier surfaces added on top of the existing
request-management group:

* ``consent policy show|allow|block|ignore <fqid>`` over
  :class:`skcomms.consent_policy.InvitePolicy`.
* ``consent feeds list|subscribe <publisher> <pubkey-file>|unsubscribe <publisher>``
  managing the trusted ban-feed list in ``runtime.yml``
  (:mod:`skcomms.consent_runtime`).
* ``consent tier <fqid>`` showing ``classify_tier`` + ``friction_for``.
"""
import pytest
from click.testing import CliRunner

from skcomms.cli import main
from skcomms.consent_policy import InviteDecision, InvitePolicy
from skcomms.consent_runtime import list_feeds


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "lumina")
    monkeypatch.delenv("SKCOMMS_CONSENT_MODE", raising=False)


def _run(*args):
    return CliRunner().invoke(main, ["consent", *args])


def _gen_pubkey():
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new("mod-a <mod@trust-a.skworld>"),
        usage={KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key.pubkey)


# --- policy -----------------------------------------------------------------


def test_policy_show_default_disabled():
    r = _run("policy", "show")
    assert r.exit_code == 0
    assert "disabled" in r.output.lower()


def test_policy_allow_persists_and_enables():
    r = _run("policy", "allow", "friend@a.b")
    assert r.exit_code == 0
    pol = InvitePolicy.load("lumina")
    assert pol.enabled is True
    assert "friend@a.b" in pol.allowed_users
    assert pol.evaluate("friend@a.b") == InviteDecision.ALLOW
    # it shows up in `show`
    assert "friend@a.b" in _run("policy", "show").output


def test_policy_block_then_allow_moves_verb():
    _run("policy", "block", "x@y.z")
    assert "x@y.z" in InvitePolicy.load("lumina").blocked_users
    assert InvitePolicy.load("lumina").evaluate("x@y.z") == InviteDecision.BLOCK
    # re-classifying as allow removes it from blocked (no double membership)
    _run("policy", "allow", "x@y.z")
    pol = InvitePolicy.load("lumina")
    assert "x@y.z" in pol.allowed_users
    assert "x@y.z" not in pol.blocked_users


def test_policy_ignore_persists():
    _run("policy", "ignore", "noise@a.b")
    pol = InvitePolicy.load("lumina")
    assert "noise@a.b" in pol.ignored_users
    assert pol.evaluate("noise@a.b") == InviteDecision.IGNORE


# --- feeds ------------------------------------------------------------------


def test_feeds_list_empty():
    r = _run("feeds", "list")
    assert r.exit_code == 0
    assert "no" in r.output.lower()


def test_feeds_subscribe_then_list_then_unsubscribe(tmp_path):
    keyfile = tmp_path / "pub_a.asc"
    keyfile.write_text(_gen_pubkey(), encoding="utf-8")

    r = _run("feeds", "subscribe", "mod@trust-a.skworld", str(keyfile))
    assert r.exit_code == 0
    feeds = list_feeds("lumina")
    assert len(feeds) == 1 and feeds[0]["publisher"] == "mod@trust-a.skworld"
    assert feeds[0]["pubkey"].startswith("-----BEGIN PGP PUBLIC KEY")

    listed = _run("feeds", "list")
    assert "mod@trust-a.skworld" in listed.output

    u = _run("feeds", "unsubscribe", "mod@trust-a.skworld")
    assert u.exit_code == 0
    assert list_feeds("lumina") == []


def test_feeds_unsubscribe_unknown_is_graceful():
    r = _run("feeds", "unsubscribe", "ghost@nowhere")
    assert r.exit_code == 0
    assert "no" in r.output.lower() or "not" in r.output.lower()


# --- tier -------------------------------------------------------------------


def test_tier_anonymous_default():
    r = _run("tier", "stranger@x.y")
    assert r.exit_code == 0
    assert "anonymous" in r.output.lower()
    # friction surfaced (greylist default True for anonymous)
    assert "greylist" in r.output.lower()


def test_tier_verified_is_sovereign():
    r = _run("tier", "peer@trust.skworld", "--verified")
    assert r.exit_code == 0
    assert "sovereign" in r.output.lower()


def test_tier_introduced():
    r = _run("tier", "vouched@a.b", "--introduced")
    assert r.exit_code == 0
    assert "introduced" in r.output.lower()
