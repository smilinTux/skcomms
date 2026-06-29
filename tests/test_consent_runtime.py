"""``consent_runtime.build_pipeline`` — configured-pipeline factory.

A node startup / the api gate calls :func:`skcomms.consent_runtime.build_pipeline`
instead of bare ``ConsentPipeline(agent, mode=...)``. It reads node config from
``skcomms_home()/consent/<agent>/runtime.yml`` (or env), pins each trusted
ban-feed publisher's key into a :class:`~skcomms.consent_banfeeds.FeedSubscription`
(fail-closed), and applies per-tier friction overrides — returning a fully wired
:class:`~skcomms.consent_pipeline.ConsentPipeline`.

Keys are generated in-process via pgpy (no live CapAuth), mirroring
``tests/test_consent_banfeeds.py``.
"""
import json

import pytest

from skcomms.consent_pipeline import ConsentPipeline

S = "stranger@x.y"
BANNED = "evil@attacker.realm"


# --- in-process signing key (mirror tests/test_consent_banfeeds.py) ---------


def _gen_key(uid: str):
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
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey)


PUB = "mod@trust-a.skworld"


@pytest.fixture(scope="module")
def pub_keys():
    return _gen_key("mod-a <mod@trust-a.skworld>")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.delenv("SKCOMMS_CONSENT_MODE", raising=False)
    return tmp_path


def _signed_feed_bytes(priv, entries):
    from skcomms.consent_banfeeds import BanFeed
    from skcomms.signing import EnvelopeSigner

    feed = BanFeed.build(publisher=PUB, entries=entries, signer=EnvelopeSigner(priv))
    return feed.to_bytes()


# --- mode resolution --------------------------------------------------------


def test_default_no_config_is_public_passthrough():
    p = build = None
    from skcomms.consent_runtime import build_pipeline

    p = build_pipeline("lumina")
    assert isinstance(p, ConsentPipeline)
    assert p.mode == "public"
    # unknown anonymous → greylist defer (default friction), nothing banned
    assert p.decide(S).decision == "defer"


def test_env_mode_overrides_config(monkeypatch):
    from skcomms.consent_runtime import build_pipeline, runtime_config_path

    path = runtime_config_path("lumina")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("mode: public\n", encoding="utf-8")
    monkeypatch.setenv("SKCOMMS_CONSENT_MODE", "tailnet")
    p = build_pipeline("lumina")
    assert p.mode == "tailnet"
    # tailnet = network membership is consent → unknown delivers
    assert p.decide(S).decision == "deliver"


def test_config_mode_used_when_no_env():
    from skcomms.consent_runtime import build_pipeline, save_runtime_config

    save_runtime_config("lumina", {"mode": "tailnet"})
    assert build_pipeline("lumina").mode == "tailnet"


# --- ban feeds (fail-closed) ------------------------------------------------


def test_trusted_banfeed_drops_banned_sender(pub_keys, home):
    priv, pub = pub_keys
    from skcomms.consent_runtime import build_pipeline, save_runtime_config

    feed_path = home / "feed_a.json"
    feed_path.write_bytes(
        _signed_feed_bytes(priv, [{"entity": BANNED, "recommendation": "ban", "reason": "spam"}])
    )
    save_runtime_config(
        "lumina",
        {"ban_feeds": [{"publisher": PUB, "pubkey": pub, "feed": str(feed_path)}]},
    )
    p = build_pipeline("lumina")
    out = p.decide(BANNED)
    assert out.decision == "drop" and out.reason == "ban-feed"
    # a non-banned stranger is unaffected
    assert p.decide(S).decision != "drop"


def test_wrong_pinned_key_is_failclosed_ignored(pub_keys, home):
    """A feed pinned to the WRONG publisher key never verifies → not blended."""
    priv, _pub = pub_keys
    _other_priv, other_pub = _gen_key("attacker <evil@x>")
    from skcomms.consent_runtime import build_pipeline, save_runtime_config

    feed_path = home / "feed_a.json"
    feed_path.write_bytes(_signed_feed_bytes(priv, [{"entity": BANNED, "recommendation": "ban"}]))
    # pin the wrong pubkey → verification fails → feed ignored (fail-closed)
    save_runtime_config(
        "lumina",
        {"ban_feeds": [{"publisher": PUB, "pubkey": other_pub, "feed": str(feed_path)}]},
    )
    p = build_pipeline("lumina")
    assert p.decide(BANNED).decision != "drop"


def test_missing_feed_file_is_tolerated(pub_keys, home):
    priv, pub = pub_keys
    from skcomms.consent_runtime import build_pipeline, save_runtime_config

    save_runtime_config(
        "lumina",
        {"ban_feeds": [{"publisher": PUB, "pubkey": pub, "feed": str(home / "nope.json")}]},
    )
    p = build_pipeline("lumina")  # must not raise
    assert p.decide(BANNED).decision != "drop"


# --- friction overrides -----------------------------------------------------


def test_friction_override_disables_greylist():
    from skcomms.consent_runtime import build_pipeline, save_runtime_config

    save_runtime_config(
        "lumina",
        {"friction": {"anonymous": {"greylist": False, "rate_per_day": 3, "require_token": True}}},
    )
    out = build_pipeline("lumina").decide(S)
    # greylist off → straight to quarantine knock (not defer)
    assert out.decision == "quarantine" and out.reason == "knock"


# --- config helpers (used by the CLI) ---------------------------------------


def test_add_remove_list_feed_roundtrip(pub_keys):
    priv, pub = pub_keys
    from skcomms.consent_runtime import add_feed, list_feeds, remove_feed

    assert list_feeds("lumina") == []
    add_feed("lumina", PUB, pub)
    feeds = list_feeds("lumina")
    assert len(feeds) == 1 and feeds[0]["publisher"] == PUB
    assert feeds[0]["pubkey"].startswith("-----BEGIN PGP PUBLIC KEY")
    # idempotent re-add replaces (no duplicate publisher)
    add_feed("lumina", PUB, pub)
    assert len(list_feeds("lumina")) == 1
    assert remove_feed("lumina", PUB) is True
    assert list_feeds("lumina") == []
    assert remove_feed("lumina", PUB) is False


def test_injected_config_path_is_pure(tmp_path, pub_keys):
    """build_pipeline accepts an explicit config path (pure / testable)."""
    priv, pub = pub_keys
    from skcomms.consent_runtime import build_pipeline

    cfg = tmp_path / "custom.yml"
    cfg.write_text("mode: tailnet\n", encoding="utf-8")
    p = build_pipeline("lumina", config_path=cfg)
    assert p.mode == "tailnet"
