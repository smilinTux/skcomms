"""GroupConsentGate — one gate that wires the group-consent modules together.

The 1:1 first-contact stack (``consent.py`` / ``consent_pipeline.py``) gives DMs
the **knock -> review -> admit** flow plus blocking/reporting. This gate gives
**groups the same protection** by composing the already-built, already-tested
group primitives behind a single small API — exactly as :class:`ConsentPipeline`
composes the 1:1 gates:

* :class:`skcomms.consent_groups.GroupJoinPolicy` — admission state machine
  (``invite_only`` / ``knock`` / ``open``) + owner/moderator/member roles.
* :class:`skcomms.consent_captcha.Captcha` — sovereign, bot-issued captcha (no
  3rd-party server); an open-mode joiner that needs a captcha is held PENDING
  until it presents a verifying answer.
* :class:`skcomms.consent_moderation.ShadowBlockSet` — a shadow-blocked member's
  messages are hidden from everyone but themselves.
* :class:`skcomms.consent_moderation.ReportLog` — consent-gated abuse reporting
  (metadata only; an unreported message leaves no record).

Pure composition — the gate owns no persistence of its own. Each per-group
primitive keeps its own SQLite store under ``skcomms_home()/consent/...`` so a
fresh :class:`GroupConsentGate` over the same home re-reads identical state. The
gate just caches the live handles for the groups it has touched.

Gate API
--------
* ``join_decision(group_id, fqid)`` — run the JOIN path: invite_only rejects an
  un-invited stranger, knock queues for review, open admits (issuing a captcha
  first when the group requires one).
* ``admit(group_id, fqid, *, by=None, challenge_id=None, captcha_answer=None)`` —
  finish a pending join: a moderator/owner approves a knock, **or** a captcha
  answer is verified and admits on success.
* ``visible(group_id, viewer, sender)`` — the MESSAGE path: filter through the
  per-group :class:`ShadowBlockSet`.
* ``shadow_block`` / ``report`` / ``list_reports`` — moderator actions.

This module is **purely additive**: it imports the per-module primitives and the
shared :func:`skcomms.home.skcomms_home` and edits nothing in ``api.py`` /
``cli.py`` / ``consent*.py``. Like the 1:1 gate it stays opt-in — a group
implementation only reaches for it when consent is switched on.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .consent_captcha import Captcha, derive_challenge
from .consent_groups import GroupJoinPolicy, JoinRequest, JoinStatus, Role
from .consent_moderation import Report, ReportLog, ShadowBlockSet


@dataclass
class GroupJoinResult:
    """Outcome of a JOIN attempt (the gate's composed return value).

    Mirrors :class:`skcomms.consent_groups.JoinRequest` but additionally carries
    captcha state so the caller can render the challenge and drive verification.
    """

    group_id: str
    fqid: str
    status: JoinStatus
    captcha_required: bool = False
    challenge_id: Optional[str] = None
    captcha_prompt: Optional[str] = None
    #: The seed the captcha was derived from — surfaced so the *issuer* (the bot)
    #: can drive verification deterministically; never shown to the solver.
    seed: Optional[str] = None

    @classmethod
    def _from_req(cls, req: JoinRequest) -> "GroupJoinResult":
        return cls(group_id=req.group_id, fqid=req.fqid, status=req.status)


@dataclass
class _GroupConfig:
    """Per-group admission configuration registered via :meth:`configure_group`."""

    mode: str
    owner: Optional[str]
    require_captcha: bool
    persisted: bool


class GroupConsentGate:
    """Compose the group-consent primitives into one knock/captcha/moderation gate.

    Args:
        agent: The agent that owns this gate (path/namespace isolation, matching
            :class:`~skcomms.consent_pipeline.ConsentPipeline`).
    """

    def __init__(self, agent: str = "default") -> None:
        self.agent = agent
        self._configs: dict[str, _GroupConfig] = {}
        self._policies: dict[str, GroupJoinPolicy] = {}
        self._captchas: dict[str, Captcha] = {}
        self._shadow: dict[str, ShadowBlockSet] = {}
        self._reports: dict[str, ReportLog] = {}

    # -- configuration ---------------------------------------------------------

    def configure_group(
        self,
        group_id: str,
        *,
        mode: str = "invite_only",
        owner: Optional[str] = None,
        require_captcha: bool = False,
        persisted: bool = True,
    ) -> None:
        """Register a group's admission policy (idempotent; rebuilds handles).

        Args:
            group_id: Stable group identifier.
            mode: ``invite_only`` (default) / ``knock`` / ``open``.
            owner: FQID seeded as the group owner (needed to approve knocks).
            require_captcha: For ``open`` mode, hold joiners behind a bot-issued
                captcha (:class:`Captcha`) until they verify.
            persisted: Back state on disk (default) or keep in-memory (tests).
        """
        self._configs[group_id] = _GroupConfig(
            mode=mode, owner=owner, require_captcha=require_captcha, persisted=persisted
        )
        # Drop cached handles so the new config takes effect.
        self._policies.pop(group_id, None)
        self._captchas.pop(group_id, None)

    # -- lazy per-group handle accessors --------------------------------------

    def _cfg(self, group_id: str) -> _GroupConfig:
        cfg = self._configs.get(group_id)
        if cfg is None:
            # Fail safe: an unconfigured group defaults to the strictest mode.
            cfg = _GroupConfig(
                mode="invite_only", owner=None, require_captcha=False, persisted=True
            )
            self._configs[group_id] = cfg
        return cfg

    def _policy(self, group_id: str) -> GroupJoinPolicy:
        pol = self._policies.get(group_id)
        if pol is None:
            cfg = self._cfg(group_id)
            pol = GroupJoinPolicy(
                group_id,
                mode=cfg.mode,
                owner=cfg.owner,
                persisted=cfg.persisted,
            )
            self._policies[group_id] = pol
        return pol

    def _captcha(self, group_id: str) -> Captcha:
        cap = self._captchas.get(group_id)
        if cap is None:
            # Per-group captcha store (group_id used as the isolation key).
            cap = Captcha(f"group-{group_id}")
            self._captchas[group_id] = cap
        return cap

    def _shadowset(self, group_id: str) -> ShadowBlockSet:
        sb = self._shadow.get(group_id)
        if sb is None:
            sb = ShadowBlockSet(group_id, persisted=self._cfg(group_id).persisted)
            self._shadow[group_id] = sb
        return sb

    def _reportlog(self, group_id: str) -> ReportLog:
        rl = self._reports.get(group_id)
        if rl is None:
            rl = ReportLog(group_id, persisted=self._cfg(group_id).persisted)
            self._reports[group_id] = rl
        return rl

    # -- JOIN path -------------------------------------------------------------

    def join_decision(
        self, group_id: str, fqid: str, *, seed: Optional[str] = None
    ) -> GroupJoinResult:
        """Run the JOIN path for *fqid* against *group_id*'s policy.

        * ``invite_only`` — admit a pre-invited fqid, else reject the stranger.
        * ``knock`` — queue for moderator review (PENDING).
        * ``open`` without captcha — admit immediately.
        * ``open`` with ``require_captcha`` — issue a bot captcha and hold the
          joiner PENDING; :meth:`admit` finishes the join on a verifying answer.

        Args:
            group_id: The group being joined.
            fqid: The prospective member.
            seed: Optional captcha seed (defaults to a deterministic per-join
                value). Surfaced on the result so the issuer can verify.

        Returns:
            GroupJoinResult: the admission outcome (+ captcha state when issued).
        """
        cfg = self._cfg(group_id)
        pol = self._policy(group_id)

        # open + captcha: don't let GroupJoinPolicy auto-admit — gate the join on
        # a bot-issued Captcha (consent_captcha), admitting only on verify.
        if cfg.mode == "open" and cfg.require_captcha:
            # Already a member / blocked → pass straight through.
            if pol.is_member(fqid):
                return GroupJoinResult(group_id, fqid, JoinStatus.MEMBER)
            if pol.is_blocked(fqid):
                return GroupJoinResult(group_id, fqid, JoinStatus.BLOCKED)
            use_seed = seed if seed is not None else f"{group_id}:{fqid}"
            challenge_id, prompt = self._captcha(group_id).generate(use_seed)
            # Park them PENDING (knock-style) until the captcha verifies.
            self._set_pending(group_id, fqid)
            return GroupJoinResult(
                group_id=group_id,
                fqid=fqid,
                status=JoinStatus.PENDING,
                captcha_required=True,
                challenge_id=challenge_id,
                captcha_prompt=prompt,
                seed=use_seed,
            )

        req = pol.request_join(fqid)
        return GroupJoinResult._from_req(req)

    def _set_pending(self, group_id: str, fqid: str) -> None:
        """Force *fqid* into PENDING in the policy store (captcha hold)."""
        pol = self._policy(group_id)
        pol._upsert(fqid, None, JoinStatus.PENDING)  # noqa: SLF001 (sibling module)

    def admit(
        self,
        group_id: str,
        fqid: str,
        *,
        by: Optional[str] = None,
        challenge_id: Optional[str] = None,
        captcha_answer: Optional[str] = None,
    ) -> GroupJoinResult:
        """Finish a pending JOIN: moderator approval **or** captcha verification.

        Exactly one of two paths runs:

        * **captcha** — when ``challenge_id`` + ``captcha_answer`` are given, verify
          them via :class:`Captcha`. On success the joiner is seated as a member;
          on failure they stay PENDING (the challenge burns an attempt).
        * **moderator** — otherwise ``by`` must be an owner/moderator and the
          pending knock is approved (:meth:`GroupJoinPolicy.approve`).

        Args:
            group_id: The group being joined.
            fqid: The pending joiner.
            by: Approving owner/moderator (moderator path).
            challenge_id: The captcha challenge id (captcha path).
            captcha_answer: The submitted captcha answer (captcha path).

        Raises:
            PermissionError: moderator path with a non-moderator *by*.

        Returns:
            GroupJoinResult: MEMBER on admit, else PENDING.
        """
        pol = self._policy(group_id)

        if challenge_id is not None:
            if self._captcha(group_id).verify(challenge_id, captcha_answer or ""):
                pol.add_member(fqid)
                return GroupJoinResult(group_id, fqid, JoinStatus.MEMBER)
            # Wrong / expired answer → remain queued.
            return GroupJoinResult(
                group_id, fqid, JoinStatus.PENDING, captcha_required=True,
                challenge_id=challenge_id,
            )

        # Moderator-approval path (role-gated; raises PermissionError if not).
        req = pol.approve(fqid, by=by)
        return GroupJoinResult._from_req(req)

    # -- invite / direct seat helpers (delegate to the policy) ----------------

    def invite(self, group_id: str, fqid: str, *, by: Optional[str] = None) -> None:
        """Pre-authorize *fqid* to join an ``invite_only`` group."""
        self._policy(group_id).invite(fqid, by=by)

    def add_member(self, group_id: str, fqid: str, *, role: Role = Role.MEMBER) -> None:
        """Directly seat *fqid* as a member (owner action / test seam)."""
        self._policy(group_id).add_member(fqid, role=role)

    def is_member(self, group_id: str, fqid: str) -> bool:
        """Whether *fqid* is an admitted member of *group_id*."""
        return self._policy(group_id).is_member(fqid)

    def list_pending(self, group_id: str) -> list[JoinRequest]:
        """The moderator's review queue (queued knocks / captcha-waiters)."""
        return self._policy(group_id).list_pending()

    # -- MESSAGE path + moderation --------------------------------------------

    def visible(self, group_id: str, viewer: str, sender: str) -> bool:
        """Whether *viewer* should see *sender*'s messages in *group_id*.

        Realizes the shadow-block rule: a shadow-blocked sender is hidden from
        everyone except themselves.
        """
        return self._shadowset(group_id).visible_to(viewer, sender)

    def shadow_block(self, group_id: str, member: str, *, by: str) -> None:
        """Shadow-block *member* (moderator action — hidden from all but self).

        Raises:
            PermissionError: *by* is not an owner/moderator of the group.
        """
        self._policy(group_id)._require_moderator(by)  # noqa: SLF001 (sibling module)
        self._shadowset(group_id).shadow_block(member)

    def unblock(self, group_id: str, member: str, *, by: str) -> None:
        """Lift a shadow-block (moderator action)."""
        self._policy(group_id)._require_moderator(by)  # noqa: SLF001
        self._shadowset(group_id).unblock(member)

    def report(
        self, group_id: str, *, message_id: str, reporter: str, reason: str
    ) -> Report:
        """File a consent-gated abuse report (metadata only, never content)."""
        return self._reportlog(group_id).file_report(message_id, reporter, reason)

    def list_reports(self, group_id: str) -> list[Report]:
        """The moderator's report queue for *group_id* (oldest first)."""
        return self._reportlog(group_id).list_reports()
