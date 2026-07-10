"""ConsentPipeline — compose the full SKFed consent gate stack into one decision.

Evaluation order (``docs/skfed-consent-design.md``):
  0. Ban gate (:meth:`ConsentPipeline.ban_gate`): signed ban-feeds
     (``consent_banfeeds``) + blocked contact (``consent.ContactStore``) → drop.
     SECURITY: runs FIRST, independent of mode and tiering, and FAILS CLOSED
     (an error while checking is a drop, never an admit).
  1. MSC4155 invite policy (``consent_policy``) — block/ignore → drop.
  2. Tailnet mode → deliver (network membership = consent).
  3. Known contact + capability token (``consent_tokens``) → deliver.
  4. Unknown → tier (``consent_tiering``) → friction → greylist
     (``consent_greylist``) → defer, else quarantine (knock).

Pure composition over the per-module primitives — it owns no persistence of its
own, so it stays additive and each gate keeps its own tested behaviour.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from .consent import ContactStore
from .consent_greylist import Greylist
from .consent_policy import InviteDecision, InvitePolicy
from .consent_tiering import classify_tier, friction_for
from .consent_tokens import TokenStore

logger = logging.getLogger("skcomms.consent_pipeline")


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

    def ban_gate(self, sender_fqid: str) -> Optional[ConsentOutcome]:
        """Run ONLY the ban gate: signed ban-feeds + locally blocked contacts.

        SECURITY (coord ad0c4c01, fails closed): the ban gate rejects
        independently of delivery mode and tiering. It runs before every admit
        path in :meth:`decide`, and callers that bypass tiering entirely
        (consent mode "off") still consult it directly. Any internal error
        while checking is treated as a ban (drop), never as an admit.

        Args:
            sender_fqid: The inbound sender being checked.

        Returns:
            ConsentOutcome: a ``drop`` outcome when the sender is banned or
            blocked (or when the check itself failed, reason
            ``ban-gate-error``), else ``None`` (not banned; continue the stack).
        """
        try:
            if self._ban is not None and self._ban.is_banned(sender_fqid):
                return ConsentOutcome("drop", "ban-feed")
            if ContactStore(self.agent).is_blocked(sender_fqid):
                return ConsentOutcome("drop", "blocked")
        except Exception:
            logger.exception(
                "ban gate check failed for %s (dropping, fail-closed)", sender_fqid
            )
            return ConsentOutcome("drop", "ban-gate-error")
        return None

    def decide(
        self,
        sender_fqid: str,
        *,
        verified: bool = False,
        introduced: bool = False,
        token: Optional[str] = None,
    ) -> ConsentOutcome:
        # 0) Ban gate FIRST, before any admit path (including tailnet mode and
        # the known-contact fast path), fail-closed and mode-independent.
        banned = self.ban_gate(sender_fqid)
        if banned is not None:
            return banned

        # 1) MSC4155 invite policy.
        pol = InvitePolicy.load(self.agent).evaluate(sender_fqid)
        if pol == InviteDecision.BLOCK:
            return ConsentOutcome("drop", "invite-policy:block")
        if pol == InviteDecision.IGNORE:
            return ConsentOutcome("drop", "invite-policy:ignore")

        # 2) Tailnet mode: consent by construction (network membership). The
        # ban gate above already ran, so a banned peer on the tailnet is still
        # dropped.
        if self.mode == "tailnet":
            return ConsentOutcome("deliver", "tailnet")

        contacts = ContactStore(self.agent)
        # 3) Known contact: gate-4 capability token (if presented, it must verify).
        if contacts.is_known(sender_fqid):
            if token is not None and not TokenStore(self.agent).verify(sender_fqid, token):
                return ConsentOutcome("drop", "bad-token")
            return ConsentOutcome("deliver", "known")

        # 4) Unknown: tier, then friction, then greylist, then knock.
        tier = classify_tier(sender_fqid, verified=verified, introduced=introduced)
        friction = friction_for(tier, overrides=self._node_policy)
        if friction.greylist and Greylist(self.agent).see(sender_fqid) == "defer":
            return ConsentOutcome("defer", "greylist", tier.value)
        return ConsentOutcome("quarantine", "knock", tier.value)

    def on_accept(self, sender_fqid: str) -> str:
        """Promote *sender* to a known contact and mint its per-contact delivery token."""
        ContactStore(self.agent).accept(sender_fqid)
        return TokenStore(self.agent).issue(sender_fqid)
