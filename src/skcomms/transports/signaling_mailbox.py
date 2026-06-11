"""Mailbox signaling backend for WebRTC P2P (sub-project B, sovereign path).

Exchanges WebRTC SDP offers/answers and ICE candidates as **capauth-signed skcomms
mailbox envelopes** — no signaling server. Each signal is a signed envelope with one
of the subjects below; on receipt it is accepted only if the signature verifies
against the peer's TOFU-pinned fingerprint (the ``VerificationResult.valid`` gate)
AND it is addressed to us. This is the same mechanism as the A-phase ``CALL_INVITE``
ring, whose per-agent signing was fixed 2026-06-11.

This is the sovereign default of B's dual-signaling design ("if you need one, get
two"); the ``/webrtc/ws`` broker is the optional low-latency fast path.

Latency note: mailbox delivery is not as fast as a WebSocket relay, so ICE
candidates are exchanged in batches (full-candidate, non-trickle) rather than one
datagram at a time. The caller gathers candidates, then sends them as a single
``ice`` signal.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from ..mailbox import read_inbox, resolve_self_identity, send_message

logger = logging.getLogger("skcomms.signaling_mailbox")

SUBJECT_OFFER = "CALL_SDP_OFFER"
SUBJECT_ANSWER = "CALL_SDP_ANSWER"
SUBJECT_ICE = "CALL_ICE"

# kind <-> subject (the only signaling subjects this backend handles)
_KIND_TO_SUBJECT = {
    "offer": SUBJECT_OFFER,
    "answer": SUBJECT_ANSWER,
    "ice": SUBJECT_ICE,
}
_SUBJECT_TO_KIND = {v: k for k, v in _KIND_TO_SUBJECT.items()}


def subject_for_kind(kind: str) -> str:
    """Map a signal kind ('offer'|'answer'|'ice') to its envelope subject."""
    try:
        return _KIND_TO_SUBJECT[kind]
    except KeyError as exc:
        raise ValueError(f"unknown signal kind: {kind!r}") from exc


def kind_for_subject(subject: str) -> Optional[str]:
    """Map an envelope subject to a signal kind, or None if not a signaling subject."""
    return _SUBJECT_TO_KIND.get(subject)


def _self_fqid(agent: Optional[str] = None) -> str:
    """The active agent's own FQID (used to filter inbound signals)."""
    return (resolve_self_identity(agent) or {}).get("fqid", "")


class MailboxSignaling:
    """Send/receive WebRTC SDP/ICE over signed skcomms mailbox envelopes.

    Usage:
        chan = MailboxSignaling(agent="opus")
        chan.send_signal("lumina@chef.skworld", "offer", {"type": "offer", "sdp": ...})
        for sig in chan.poll_signals():
            # sig = {"from_fqid", "kind", "payload", "id"}
            ...
    """

    def __init__(self, agent: Optional[str] = None) -> None:
        self.agent = agent

    def send_signal(self, to_fqid: str, kind: str, payload: dict) -> dict:
        """Sign + deposit a signaling envelope for ``to_fqid``.

        Args:
            to_fqid: recipient FQID.
            kind: 'offer' | 'answer' | 'ice'.
            payload: the SDP dict (``{"type", "sdp"}``) or the ICE candidate(s).

        Returns:
            The ``send_message`` result dict (id, paths, ...).
        """
        subject = subject_for_kind(kind)
        body = json.dumps({"kind": kind, "payload": payload})
        return send_message(to_fqid, body, subject=subject, agent=self.agent)

    def poll_signals(self) -> list[dict]:
        """Return verified signaling messages addressed to us, oldest first.

        Drops any envelope that is not a signaling subject, fails signature
        verification, is not addressed to us, or has an unparseable body.
        """
        me = _self_fqid(self.agent)
        out: list[dict] = []
        for env, verification in read_inbox(self.agent):
            kind = kind_for_subject(getattr(env, "subject", "") or "")
            if kind is None:
                continue
            if not getattr(verification, "valid", False):
                logger.debug("signaling: dropping unverified %s from %s",
                             env.subject, getattr(env, "from_fqid", "?"))
                continue
            if getattr(env, "to_fqid", None) != me:
                continue
            try:
                data = json.loads(env.body)
            except (json.JSONDecodeError, ValueError):
                logger.debug("signaling: dropping unparseable %s body", env.subject)
                continue
            out.append({
                "from_fqid": env.from_fqid,
                "kind": kind,
                "payload": data.get("payload"),
                "id": getattr(env, "id", None),
            })
        return out
