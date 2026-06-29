"""ConsentPipeline — compose the full SKFed consent gate stack into one decision.

Evaluation order (``docs/skfed-consent-design.md``):
  1. MSC4155 invite policy (``consent_policy``) — block/ignore → drop.
  2. Subscribable signed ban-feeds (``consent_banfeeds``) → drop.
  3. Blocked contact (``consent.ContactStore``) → drop.
  4. Tailnet mode → deliver (network membership = consent).
  5. Known contact + capability token (``consent_tokens``) → deliver.
  6. Unknown → tier (``consent_tiering``) → friction → greylist
     (``consent_greylist``) → defer, else quarantine (knock).

Pure composition over the per-module primitives — it owns no persistence of its
own, so it stays additive and each gate keeps its own tested behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .consent import ContactStore
from .consent_greylist import Greylist
from .consent_policy import InviteDecision, InvitePolicy
from .consent_tiering import classify_tier, friction_for
from .consent_tokens import TokenStore


@dataclass
class ConsentOutcome:
    """The composed decision: ``deliver`` | ``quarantine`` | ``drop`` | ``defer``."""

    decision: str
    reason: str = ""
    tier: str = ""


class ConsentPipeline:
    def __init__(
        self,
        agent: str,
        *,
        mode: str = "public",
        ban_subscription=None,
        node_policy: Optional[dict] = None,
    ) -> None:
        self.agent = agent
        self.mode = mode
        self._ban = ban_subscription
        self._node_policy = node_policy or {}

    def decide(
        self,
        sender_fqid: str,
        *,
        verified: bool = False,
        introduced: bool = False,
        token: Optional[str] = None,
    ) -> ConsentOutcome:
        # 1) MSC4155 invite policy — first gate.
        pol = InvitePolicy.load(self.agent).evaluate(sender_fqid)
        if pol == InviteDecision.BLOCK:
            return ConsentOutcome("drop", "invite-policy:block")
        if pol == InviteDecision.IGNORE:
            return ConsentOutcome("drop", "invite-policy:ignore")

        # 2) Subscribable signed ban-feeds.
        if self._ban is not None and self._ban.is_banned(sender_fqid):
            return ConsentOutcome("drop", "ban-feed")

        contacts = ContactStore(self.agent)
        # 3) Locally blocked.
        if contacts.is_blocked(sender_fqid):
            return ConsentOutcome("drop", "blocked")

        # 4) Tailnet mode — consent by construction (network membership).
        if self.mode == "tailnet":
            return ConsentOutcome("deliver", "tailnet")

        # 5) Known contact — gate-4 capability token (if presented, it must verify).
        if contacts.is_known(sender_fqid):
            if token is not None and not TokenStore(self.agent).verify(sender_fqid, token):
                return ConsentOutcome("drop", "bad-token")
            return ConsentOutcome("deliver", "known")

        # 6) Unknown — tier → friction → greylist → knock.
        tier = classify_tier(sender_fqid, verified=verified, introduced=introduced)
        friction = friction_for(tier, overrides=self._node_policy)
        if friction.greylist and Greylist(self.agent).see(sender_fqid) == "defer":
            return ConsentOutcome("defer", "greylist", tier.value)
        return ConsentOutcome("quarantine", "knock", tier.value)

    def on_accept(self, sender_fqid: str) -> str:
        """Promote *sender* to a known contact and mint its per-contact delivery token."""
        ContactStore(self.agent).accept(sender_fqid)
        return TokenStore(self.agent).issue(sender_fqid)
