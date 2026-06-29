"""Configured consent-pipeline factory — wire a node's policy into one gate.

:class:`~skcomms.consent_pipeline.ConsentPipeline` is a pure composition that takes
its ``mode``, ``ban_subscription`` and ``node_policy`` as constructor arguments. A
node startup (and the api gate) shouldn't hand-assemble those each time — this
module is the **factory** that reads a node's persisted consent config and returns
a fully-wired pipeline, so callers do::

    from skcomms.consent_runtime import build_pipeline
    pipeline = build_pipeline(agent)          # instead of bare ConsentPipeline(...)

Config source — ``skcomms_home()/consent/<agent>/runtime.yml`` (Syncthing-shareable,
per-agent, same home tree as the rest of the consent stack), optionally overridden
by env. Schema (every key optional)::

    mode: public                # delivery mode; SKCOMMS_CONSENT_MODE env wins
    ban_feeds:                  # gate-3 trusted, pinned ban-feed publishers
      - publisher: mod@trust-a.skworld
        pubkey: |               # the publisher's pinned ASCII-armored PGP pubkey
          -----BEGIN PGP PUBLIC KEY BLOCK-----
          ...
        feed: /path/to/feed.json   # optional; signed BanFeed JSON to blend
    friction:                   # gate-2 per-tier friction overrides (node POLICY)
      anonymous: {greylist: false, rate_per_day: 5, require_token: true}

**Fail-closed ban feeds.** Each publisher's key is *pinned*; a feed is only blended
into the :class:`~skcomms.consent_banfeeds.FeedSubscription` if it verifies against
that pinned key (mirrors ``consent_banfeeds`` semantics). A missing / unsigned /
tampered / wrong-key feed is silently ignored — it never bans anyone.

**Opt-in / additive.** With no ``runtime.yml`` (the default) this returns a plain
public-mode pipeline with an empty ban subscription and built-in friction — i.e.
identical behaviour to ``ConsentPipeline(agent)``. Nothing changes live until the
operator writes config and ``SKCOMMS_CONSENT_MODE`` is set.

Pure / testable: ``build_pipeline(agent, config_path=...)`` injects the config
file, and every helper accepts an explicit ``config_path`` so nothing depends on
ambient state beyond the env it deliberately reads.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml

from .consent_banfeeds import BanFeed, FeedSubscription
from .consent_pipeline import ConsentPipeline
from .consent_tiering import FrictionPolicy, SenderTier
from .home import skcomms_home
from .signing import EnvelopeVerifier

logger = logging.getLogger("skcomms.consent_runtime")

DEFAULT_MODE = "public"


# -- config location + persistence ------------------------------------------


def runtime_config_path(agent: str) -> Path:
    """Path of *agent*'s node consent config: ``…/consent/<agent>/runtime.yml``."""
    return skcomms_home() / "consent" / agent / "runtime.yml"


def load_runtime_config(agent: str, *, config_path: Optional[Path] = None) -> dict:
    """Load *agent*'s ``runtime.yml`` as a dict; missing file → ``{}`` (pure default).

    Args:
        agent: Short agent name (persistence + isolation key).
        config_path: Explicit override (testing); defaults to
            :func:`runtime_config_path`.
    """
    path = Path(config_path) if config_path else runtime_config_path(agent)
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def save_runtime_config(
    agent: str, cfg: dict, *, config_path: Optional[Path] = None
) -> Path:
    """Persist *cfg* to *agent*'s ``runtime.yml`` (creating parents). Returns the path."""
    path = Path(config_path) if config_path else runtime_config_path(agent)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(cfg, sort_keys=True, default_flow_style=False),
        encoding="utf-8",
    )
    return path


# -- ban-feed list management (used by the operator CLI) --------------------


def list_feeds(agent: str, *, config_path: Optional[Path] = None) -> list[dict]:
    """Return the configured trusted ban-feed publisher entries (possibly empty)."""
    cfg = load_runtime_config(agent, config_path=config_path)
    return list(cfg.get("ban_feeds") or [])


def add_feed(
    agent: str,
    publisher: str,
    pubkey_armor: str,
    *,
    feed: Optional[str] = None,
    config_path: Optional[Path] = None,
) -> dict:
    """Pin *publisher*'s ban-feed key (idempotent on ``publisher``).

    Re-adding the same publisher replaces its entry (no duplicates). The pinned
    ASCII-armored ``pubkey`` is stored inline so the config is self-contained and
    Syncthing-shareable. ``feed`` is an optional path to a signed ``BanFeed`` JSON
    to blend at build time.

    Returns:
        dict: The stored feed entry.
    """
    cfg = load_runtime_config(agent, config_path=config_path)
    feeds = [f for f in (cfg.get("ban_feeds") or []) if f.get("publisher") != publisher]
    entry = {"publisher": publisher, "pubkey": pubkey_armor}
    if feed:
        entry["feed"] = feed
    feeds.append(entry)
    cfg["ban_feeds"] = feeds
    save_runtime_config(agent, cfg, config_path=config_path)
    return entry


def remove_feed(
    agent: str, publisher: str, *, config_path: Optional[Path] = None
) -> bool:
    """Unsubscribe (un-pin) *publisher*. Returns whether an entry was removed."""
    cfg = load_runtime_config(agent, config_path=config_path)
    feeds = cfg.get("ban_feeds") or []
    kept = [f for f in feeds if f.get("publisher") != publisher]
    if len(kept) == len(feeds):
        return False
    cfg["ban_feeds"] = kept
    save_runtime_config(agent, cfg, config_path=config_path)
    return True


# -- internal wiring ---------------------------------------------------------


def _build_ban_subscription(agent: str, cfg: dict) -> FeedSubscription:
    """Pin each configured publisher's key and blend its (verified) feed.

    Fail-closed throughout: any malformed entry, missing/unsigned/tampered/wrong-key
    feed is logged and skipped — it never influences ``is_banned``.
    """
    sub = FeedSubscription()
    for entry in cfg.get("ban_feeds") or []:
        publisher = entry.get("publisher")
        pubkey = entry.get("pubkey")
        feed_path = entry.get("feed")
        if not publisher or not pubkey:
            logger.info("ban_feed entry missing publisher/pubkey — skipped: %r", entry)
            continue
        if not feed_path:
            # Key pinned but no feed data to blend yet — nothing to subscribe.
            logger.debug("ban_feed %r pinned without a feed file — nothing to blend", publisher)
            continue
        path = Path(feed_path).expanduser()
        if not path.exists():
            logger.info("ban_feed %r feed file missing (%s) — skipped", publisher, path)
            continue
        try:
            verifier = EnvelopeVerifier()
            verifier.add_key(publisher, pubkey)
            feed = BanFeed.from_bytes(path.read_bytes())
            if not sub.subscribe(feed, verifier):
                logger.info("ban_feed %r failed verification — ignored (fail-closed)", publisher)
        except Exception:  # noqa: BLE001 — fail-closed, never crash node startup
            logger.exception("ban_feed %r could not be loaded — ignored", publisher)
    return sub


def _build_friction_overrides(cfg: dict) -> dict:
    """Translate the ``friction:`` block into ``{SenderTier: FrictionPolicy}``.

    Unknown tier names / malformed policies are skipped (built-in default applies).
    """
    overrides: dict = {}
    for name, vals in (cfg.get("friction") or {}).items():
        try:
            tier = SenderTier(name)
        except ValueError:
            logger.info("friction override for unknown tier %r — skipped", name)
            continue
        try:
            overrides[tier] = FrictionPolicy(
                greylist=bool(vals["greylist"]),
                rate_per_day=int(vals["rate_per_day"]),
                require_token=bool(vals["require_token"]),
            )
        except (KeyError, TypeError, ValueError):
            logger.info("malformed friction override for tier %r — skipped", name)
            continue
    return overrides


def _resolve_mode(cfg: dict) -> str:
    """``SKCOMMS_CONSENT_MODE`` env wins, else config ``mode``, else the default."""
    env_mode = os.environ.get("SKCOMMS_CONSENT_MODE")
    if env_mode:
        return env_mode
    return cfg.get("mode") or DEFAULT_MODE


# -- the factory -------------------------------------------------------------


def build_pipeline(agent: str, *, config_path: Optional[Path] = None) -> ConsentPipeline:
    """Build a :class:`ConsentPipeline` wired from *agent*'s node consent config.

    Reads ``runtime.yml`` (or *config_path*), pins each trusted ban-feed publisher
    into a fail-closed :class:`FeedSubscription`, applies per-tier friction
    overrides, and resolves the delivery mode (``SKCOMMS_CONSENT_MODE`` env wins).

    With no config this is identical to ``ConsentPipeline(agent)`` — opt-in/additive.

    Args:
        agent: Short agent name (whose policy + isolation to use).
        config_path: Explicit config file (testing); defaults to
            :func:`runtime_config_path`.

    Returns:
        ConsentPipeline: Ready to ``decide(...)`` / ``on_accept(...)``.
    """
    cfg = load_runtime_config(agent, config_path=config_path)
    mode = _resolve_mode(cfg)
    ban_subscription = _build_ban_subscription(agent, cfg)
    node_policy = _build_friction_overrides(cfg)
    return ConsentPipeline(
        agent,
        mode=mode,
        ban_subscription=ban_subscription,
        node_policy=node_policy,
    )
