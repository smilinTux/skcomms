"""Operator surface over the P1 consent gate (skfed-consent-design gate 5).

This module is the **thin, stateful facade** a ``skcomms consent ...`` CLI and an
``/api/v1/consent`` endpoint call to drive the recipient-side message-request
quarantine. It owns NO new persistence — every function constructs the existing P1
primitives (:class:`skcomms.consent.RequestQueue` /
:class:`skcomms.consent.ContactStore`) fresh against the current ``SKCOMMS_HOME``,
so a brand-new process (a one-shot CLI invocation, a stateless API worker) sees the
exact state the inbound gate wrote. The SQLite stores are the single source of
truth; this layer adds only operator verbs.

Mapping onto the settled design (``docs/skfed-consent-design.md``):

* :func:`list_requests` — review the no-notify quarantine queue (Signal Message
  Request semantics: quiet by default, the operator reviews on their own time).
* :func:`accept_request` — promote an unknown first-contact to a known contact and
  clear its queued knock (the "issue a token / promote" step of gate 5).
* :func:`decline_request` / :func:`block_sender` — drop the knock, optionally
  block (MSC4155 per-sender block semantics — and blocks stay visible/reviewable).
* :func:`list_known` — the accepted-contact roster.
* :func:`unblock` — lift a block, returning the sender to UNKNOWN (re-quarantined
  on next contact, NOT auto-trusted).

The :func:`unblock` verb is the one operation the P1 primitive does not expose
(``ContactStore`` has ``accept``/``block`` but no neutral clear). Rather than edit
the shared primitive, it deletes the blocked row directly from the same
``contacts.db`` the store owns, reusing :func:`skcomms.consent._consent_dir` for the
path so it stays bound to the store's layout.
"""
from __future__ import annotations

import sqlite3
from typing import Optional

from .consent import ContactStore, RequestQueue, _consent_dir


def list_requests(agent: str) -> list[dict]:
    """Return the agent's quarantined first-contact knocks, oldest first.

    Args:
        agent: The recipient agent whose request queue to read.

    Returns:
        A list of ``{"sender", "envelope_id", "received_at"}`` dicts — exactly the
        operator-surface shape the CLI/API renders. Empty when nothing is queued.
    """
    return [
        {
            "sender": r.sender,
            "envelope_id": r.envelope_id,
            "received_at": r.received_at,
        }
        for r in RequestQueue(agent).list_requests()
    ]


def accept_request(agent: str, sender: str) -> dict:
    """Accept a first-contact request: promote *sender* to known + clear its queue.

    Idempotent and safe even if no knock is currently queued (the promotion still
    happens; clearing an empty queue is a no-op).

    Args:
        agent: The recipient agent.
        sender: The sender FQID to promote.

    Returns:
        A small status dict for the CLI/API response.
    """
    store = ContactStore(agent)
    RequestQueue(agent).accept_request(sender, store=store)
    return {"agent": agent, "sender": sender, "result": "accepted"}


def decline_request(agent: str, sender: str, *, block: bool = False) -> dict:
    """Decline a first-contact request: clear *sender*'s queued knocks.

    Args:
        agent: The recipient agent.
        sender: The sender FQID to decline.
        block: When ``True``, also block the sender so future traffic is dropped
            (gate 5 → DROP). When ``False`` the sender simply returns to UNKNOWN.

    Returns:
        A small status dict for the CLI/API response.
    """
    store = ContactStore(agent)
    RequestQueue(agent).decline_request(sender, store=store, block=block)
    return {
        "agent": agent,
        "sender": sender,
        "result": "blocked" if block else "declined",
    }


def block_sender(agent: str, sender: str) -> dict:
    """Block *sender* outright (no queued knock required); its traffic is dropped.

    Args:
        agent: The recipient agent.
        sender: The sender FQID to block.

    Returns:
        A small status dict for the CLI/API response.
    """
    ContactStore(agent).block(sender)
    return {"agent": agent, "sender": sender, "result": "blocked"}


def list_known(agent: str) -> list[str]:
    """Return the agent's accepted-contact roster (FQIDs).

    Args:
        agent: The recipient agent.

    Returns:
        The list of known/accepted sender FQIDs.
    """
    return ContactStore(agent).list_known()


def unblock(agent: str, sender: str) -> dict:
    """Lift a block on *sender*, returning it to UNKNOWN (not auto-trusted).

    The P1 ``ContactStore`` has no neutral clear, so this removes the blocked row
    from the same ``contacts.db`` the store owns. A subsequently re-contacting
    sender is quarantined again (it is NOT promoted to known). Idempotent: a no-op
    when the sender is not currently blocked.

    Args:
        agent: The recipient agent.
        sender: The sender FQID to unblock.

    Returns:
        A small status dict for the CLI/API response.
    """
    # Ensure the store/table exist (also the documented owner of contacts.db).
    ContactStore(agent)
    db = _consent_dir(agent) / "contacts.db"
    with sqlite3.connect(str(db)) as c:
        c.execute(
            "DELETE FROM contacts WHERE fqid=? AND state='blocked'", (sender,)
        )
    return {"agent": agent, "sender": sender, "result": "unblocked"}


__all__ = [
    "list_requests",
    "accept_request",
    "decline_request",
    "block_sender",
    "list_known",
    "unblock",
]
