"""Sender-auth tiering — *mode picks the gate stack; tier picks the friction* (gate 2).

The consent design (``docs/skfed-consent-design.md``) forces an answer to open
problem **(B)**: the literature gives **no canonical tiering policy**, so concrete
friction thresholds must NOT be baked into the protocol. The protocol supplies the
**signals** (was this sender's capauth/DID signature verified? are they introduced
by a contact-of-a-contact?); the node's **policy** maps a tier to friction.

This module is exactly that split:

* :func:`classify_tier` is the **protocol** half — pure, deterministic, no policy
  numbers. ``verified`` (a checked capauth/DID signature) ⇒ :attr:`SenderTier.SOVEREIGN`;
  else ``introduced`` (web-of-trust / contact-of-a-contact) ⇒
  :attr:`SenderTier.INTRODUCED`; else :attr:`SenderTier.ANONYMOUS`.
* :func:`friction_for` is the **policy** half — a small, frozen
  :class:`FrictionPolicy` per tier, with safe built-in defaults (sovereign sails
  through, anonymous hits every gate) that a node operator can fully override.

It deliberately holds NO state and imports no crypto: the caller has already run
sender authentication (``signing.EnvelopeVerifier.verify_bytes`` / the DID path)
and the introduction check before calling :func:`classify_tier`. This keeps gate 2
a pure decision function the orchestrator can compose with the request queue
(gate 5), greylist and capability-token (gate 4) modules.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional


class SenderTier(str, Enum):
    """Structural trust tier of a first-contact sender (the protocol signal).

    Ordered low→high friction. E2EE makes content opaque, so this tier — derived
    from *who the sender is*, not *what they said* — is the lever the friction
    policy turns.
    """

    SOVEREIGN = "sovereign"      #: capauth/DID signature verified → trusted realm
    INTRODUCED = "introduced"    #: vouched / contact-of-a-contact (web-of-trust)
    ANONYMOUS = "anonymous"      #: unauthenticated unknown → strictest gate


@dataclass(frozen=True)
class FrictionPolicy:
    """Node-side friction applied to a sender of a given :class:`SenderTier`.

    Frozen so a shared default can't be mutated by one caller. These are **policy,
    not protocol** — the defaults below are a safe starting point, never a
    standard; a node operator overrides them via :func:`friction_for`.

    Attributes:
        greylist: Temp-defer an unknown first-contact (email greylisting — the
            cheap speed-bump that *replaced* proof-of-work). The sender must retry;
            naive bulk spammers never do.
        rate_per_day: Max accepted first-contact knocks per day from this sender.
        require_token: Whether a valid per-contact capability token (gate 4) is
            required before delivery (an established contact already holds one).
    """

    greylist: bool
    rate_per_day: int
    require_token: bool


# Safe built-in defaults — monotone in strictness (sovereign softest, anonymous
# strictest) on every axis. POLICY: tune per node via the ``overrides`` arg.
_DEFAULT_FRICTION: dict[SenderTier, FrictionPolicy] = {
    SenderTier.SOVEREIGN: FrictionPolicy(
        greylist=False, rate_per_day=1000, require_token=False
    ),
    SenderTier.INTRODUCED: FrictionPolicy(
        greylist=False, rate_per_day=50, require_token=False
    ),
    SenderTier.ANONYMOUS: FrictionPolicy(
        greylist=True, rate_per_day=3, require_token=True
    ),
}


def classify_tier(
    fqid: str, *, verified: bool = False, introduced: bool = False
) -> SenderTier:
    """Classify a sender into a :class:`SenderTier` from authentication signals.

    Pure protocol logic — no policy numbers, no state. The caller runs the actual
    capauth/DID signature check and the introduction (web-of-trust) lookup, then
    passes the booleans here.

    Precedence: a cryptographically *verified* sender is :attr:`SenderTier.SOVEREIGN`
    regardless of vouching (a checked signature is the strongest signal); a merely
    *introduced* sender is :attr:`SenderTier.INTRODUCED`; everyone else is
    :attr:`SenderTier.ANONYMOUS`.

    Args:
        fqid: The sender's fully-qualified id (carried for caller context / logging;
            classification depends only on the signal flags, not the string).
        verified: True iff the sender's capauth/DID signature was checked and valid.
        introduced: True iff the sender is vouched (contact-of-a-contact).

    Returns:
        SenderTier: The structural trust tier.
    """
    if verified:
        return SenderTier.SOVEREIGN
    if introduced:
        return SenderTier.INTRODUCED
    return SenderTier.ANONYMOUS


def friction_for(
    tier: SenderTier,
    *,
    overrides: Optional[Mapping[SenderTier, FrictionPolicy]] = None,
) -> FrictionPolicy:
    """Map a :class:`SenderTier` to its :class:`FrictionPolicy` (the policy half).

    Returns the built-in default for *tier* unless the caller supplies an
    ``overrides`` mapping containing that tier — the design's forced answer to open
    problem (B): friction is node POLICY, fully overridable, never protocol.

    Args:
        tier: The sender's classified tier.
        overrides: Optional per-tier replacements. A tier present here uses the
            override verbatim; absent tiers fall back to the safe default.

    Returns:
        FrictionPolicy: The (frozen) friction to apply.
    """
    if overrides and tier in overrides:
        return overrides[tier]
    return _DEFAULT_FRICTION[tier]
