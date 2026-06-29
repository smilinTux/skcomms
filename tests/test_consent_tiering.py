"""Sender-auth tiering (skfed-consent-design gate 2 + open problem (B)).

E2EE forces spam defense onto *structural* signals: the protocol supplies the
TIER (sovereign / introduced / anonymous), node POLICY supplies the FRICTION.
Per the design's forced answer to problem (B), the friction thresholds are NOT
baked into the protocol — they are policy defaults, fully overridable.

  * ``verified`` (capauth/DID signature checked) → SOVEREIGN — sails through.
  * ``introduced`` (contact-of-a-contact / web-of-trust) → INTRODUCED — reduced.
  * neither                                            → ANONYMOUS — strictest.

Friction ordering MUST be monotone: anonymous is never softer than introduced,
which is never softer than sovereign.
"""
import dataclasses

import pytest

from skcomms.consent_tiering import (FrictionPolicy, SenderTier, classify_tier,
                                     friction_for)

L = "lumina@chef.skworld"
O = "opus@chef.skworld"
J = "jarvis@chef.skworld"
ANON = "k7x9q@anon.relay"


# --- classification: each tier --------------------------------------------


def test_verified_is_sovereign():
    assert classify_tier(L, verified=True) is SenderTier.SOVEREIGN


def test_verified_wins_even_if_introduced():
    # A cryptographically verified sender is sovereign regardless of vouching.
    assert classify_tier(L, verified=True, introduced=True) is SenderTier.SOVEREIGN


def test_introduced_only_is_introduced():
    assert classify_tier(O, introduced=True) is SenderTier.INTRODUCED


def test_unknown_is_anonymous():
    assert classify_tier(ANON) is SenderTier.ANONYMOUS


def test_neither_flag_is_anonymous():
    assert classify_tier(ANON, verified=False, introduced=False) is SenderTier.ANONYMOUS


# --- friction: shape + safe defaults --------------------------------------


def test_friction_returns_policy_dataclass():
    pol = friction_for(SenderTier.ANONYMOUS)
    assert isinstance(pol, FrictionPolicy)
    assert hasattr(pol, "greylist")
    assert hasattr(pol, "rate_per_day")
    assert hasattr(pol, "require_token")


def test_sovereign_low_friction():
    pol = friction_for(SenderTier.SOVEREIGN)
    assert pol.greylist is False
    assert pol.require_token is False
    assert pol.rate_per_day >= 100  # effectively unthrottled


def test_anonymous_strict_friction():
    pol = friction_for(SenderTier.ANONYMOUS)
    assert pol.greylist is True
    assert pol.require_token is True
    assert pol.rate_per_day <= 10  # tight cap


# --- friction ordering: anonymous strictest, monotone ---------------------


def test_rate_ordering_anon_strictest():
    sov = friction_for(SenderTier.SOVEREIGN).rate_per_day
    intro = friction_for(SenderTier.INTRODUCED).rate_per_day
    anon = friction_for(SenderTier.ANONYMOUS).rate_per_day
    assert anon < intro < sov


def test_greylist_ordering_monotone():
    # greylist (bool) is non-decreasing in strictness: sov<=intro<=anon
    sov = friction_for(SenderTier.SOVEREIGN).greylist
    intro = friction_for(SenderTier.INTRODUCED).greylist
    anon = friction_for(SenderTier.ANONYMOUS).greylist
    assert int(sov) <= int(intro) <= int(anon)


def test_require_token_ordering_monotone():
    sov = int(friction_for(SenderTier.SOVEREIGN).require_token)
    intro = int(friction_for(SenderTier.INTRODUCED).require_token)
    anon = int(friction_for(SenderTier.ANONYMOUS).require_token)
    assert sov <= intro <= anon


# --- policy not protocol: defaults overridable ----------------------------


def test_overrides_replace_defaults():
    # A node operator can tune any tier's friction without code changes.
    custom = {
        SenderTier.ANONYMOUS: FrictionPolicy(
            greylist=False, rate_per_day=999, require_token=False
        )
    }
    pol = friction_for(SenderTier.ANONYMOUS, overrides=custom)
    assert pol.greylist is False
    assert pol.rate_per_day == 999
    assert pol.require_token is False


def test_override_one_tier_leaves_others_default():
    custom = {SenderTier.ANONYMOUS: FrictionPolicy(greylist=False, rate_per_day=999,
                                                   require_token=False)}
    # Sovereign untouched → still the built-in default.
    pol = friction_for(SenderTier.SOVEREIGN, overrides=custom)
    assert pol == friction_for(SenderTier.SOVEREIGN)


def test_policy_is_frozen_dataclass():
    # Immutable so a shared default can't be mutated by one caller.
    pol = friction_for(SenderTier.SOVEREIGN)
    with pytest.raises(dataclasses.FrozenInstanceError):
        pol.rate_per_day = 1  # type: ignore[misc]
