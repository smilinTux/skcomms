"""Signaling channel protocol + dual-path selection (sub-project B).

Both signaling backends — the sovereign :class:`MailboxSignaling` (signed envelopes,
always available) and the optional broker fast path — implement the same minimal
interface so a :class:`P2PConnector` can drive either. ``select_signaling`` encodes
the "if you need one, get two" doctrine: prefer the low-latency broker when it is
reachable, otherwise fall back to the always-available mailbox. No single point of
failure.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class SignalingChannel(Protocol):
    """Minimal poll-based signaling interface used by :class:`P2PConnector`."""

    def send_signal(self, to_fqid: str, kind: str, payload: dict) -> dict:
        """Deliver an 'offer'|'answer'|'ice' signal to ``to_fqid``."""
        ...

    def poll_signals(self) -> list:
        """Return verified inbound signals addressed to us (cumulative; caller de-dups)."""
        ...


def select_signaling(
    mailbox: SignalingChannel,
    broker: Optional[object] = None,
    *,
    prefer_broker: bool = True,
) -> SignalingChannel:
    """Choose the signaling channel to use right now.

    Args:
        mailbox: the always-available sovereign backend (the safe default).
        broker: an optional fast-path backend exposing ``is_reachable() -> bool``
            plus the :class:`SignalingChannel` interface.
        prefer_broker: when False, always use the mailbox (e.g. sovereignty-locked).

    Returns:
        The broker when ``prefer_broker`` and it reports reachable; else the mailbox.
    """
    if broker is not None and prefer_broker:
        try:
            if broker.is_reachable():
                return broker  # type: ignore[return-value]
        except Exception:  # noqa: BLE001 — an unreachable/raising broker just yields mailbox
            pass
    return mailbox
