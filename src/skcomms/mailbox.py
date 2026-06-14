"""FQID-aware mailbox — send / inbox / peers over the ~/.skcapstone/skcomms tree (T6).

Coord task ``ff0b2c15``. This is the canonical message-passing layer:
messages are Envelope v1 (:mod:`skcomms.envelope`), addressed by FQID,
signed (:mod:`skcomms.signing`), and dropped into the realm message tree
(:mod:`skcomms.home`) — the sender's ``outbox`` plus the recipient peer's
``inbox`` (which Syncthing replicates to the peer in T7/T8).

No live transports here: everything is filesystem + PGP, so it is fully
testable against a tmp ``SKCOMMS_HOME`` with in-process keys.

Key loading (:func:`_load_signer` / :func:`_load_verifier_key`) reads the
agent's CapAuth PGP profile from disk; tests monkeypatch these to inject
in-process keys.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from .envelope import Envelope, SignedEnvelope
from .home import peer_inbox, scaffold, skcomms_home
from .identity import resolve_self_identity
from .signing import EnvelopeSigner, EnvelopeVerifier, VerificationResult

logger = logging.getLogger("skcomms.mailbox")


# ---------------------------------------------------------------------------
# Key loading (CapAuth PGP profile) — monkeypatched in tests
# ---------------------------------------------------------------------------


def _agent_identity_dir(agent: str) -> Path:
    """Path to the agent's CapAuth identity dir.

    Canonical location is ``~/.skcapstone/agents/<agent>/capauth/identity``
    (where provisioning + pairing keep the per-agent keypair). Falls back to
    the legacy bare ``identity`` dir for older layouts. The previous bare-only
    path silently missed every agent's real key and fell through to the
    operator key under ``~/.capauth`` — signing agent messages as the operator
    and breaking signature verification fleet-wide.
    """
    base = Path.home() / ".skcapstone" / "agents" / agent
    capauth_dir = base / "capauth" / "identity"
    if capauth_dir.exists():
        return capauth_dir
    return base / "identity"


def _load_signer(agent: str) -> EnvelopeSigner:
    """Load the signing key for *agent* from its CapAuth profile.

    Looks for ``private.asc`` under the agent identity dir, then under the
    classic ``~/.capauth/identity/`` location.

    Raises:
        FileNotFoundError: If no private key can be located.
    """
    candidates = [
        _agent_identity_dir(agent) / "private.asc",
        _agent_identity_dir(agent) / "agent.private.asc",
        Path.home() / ".capauth" / "identity" / "private.asc",
    ]
    for path in candidates:
        if path.exists():
            passphrase = os.environ.get("SKCOMMS_KEY_PASSPHRASE", "")
            return EnvelopeSigner(path.read_text(encoding="utf-8"), passphrase)
    raise FileNotFoundError(
        f"no PGP private key for {agent!r}; looked in {[str(c) for c in candidates]}"
    )


def _load_verifier_key(fqid: str) -> Optional[str]:
    """Load the public key armor for a peer FQID (or self).

    Resolves the agent component of *fqid* and looks for ``public.asc`` under
    the agent's CapAuth identity dir or a peers store. Returns ``None`` when
    no key is found (verification then reports an unknown signer).
    """
    agent = fqid.split("@", 1)[0] if "@" in fqid else fqid
    candidates = [
        _agent_identity_dir(agent) / "public.asc",
        _agent_identity_dir(agent) / "agent.pub",
        Path.home() / ".capauth" / "identity" / "public.asc",
        skcomms_home() / "peers" / f"{fqid}.asc",
    ]
    for path in candidates:
        if path.exists():
            return path.read_text(encoding="utf-8")
    return None


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------


def build_envelope(
    from_fqid: str,
    to_fqid: str,
    body: str,
    *,
    content_type: str = "text/plain",
    subject: Optional[str] = None,
    thread_id: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> Envelope:
    """Construct an Envelope v1 from the given fields."""
    return Envelope(
        from_fqid=from_fqid,
        to_fqid=to_fqid,
        body=body,
        content_type=content_type,
        subject=subject,
        thread_id=thread_id,
        reply_to=reply_to,
    )


def send_message(
    to_fqid: str,
    message: str,
    *,
    agent: Optional[str] = None,
    subject: Optional[str] = None,
    thread_id: Optional[str] = None,
    reply_to: Optional[str] = None,
) -> dict:
    """Build, sign, and deposit an Envelope v1 for *to_fqid*.

    The signed envelope is written to the sender's ``outbox`` (local record)
    and to the recipient peer's ``inbox`` (the Syncthing drop path).

    Args:
        to_fqid: Recipient FQID (``<agent>@<operator>.<realm>``).
        message: The message body.
        agent: Override the sending agent (defaults to resolved identity).
        subject/thread_id/reply_to: Optional envelope metadata.

    Returns:
        Dict with ``id``, ``from_fqid``, ``to_fqid``, ``outbox_path``,
        ``peer_inbox_path``.

    Raises:
        ValueError: If *to_fqid* is not a valid FQID.
    """
    ident = resolve_self_identity(agent)
    from_fqid = ident.get("fqid")
    if not from_fqid:
        raise ValueError("cannot resolve sender fqid (cluster.json missing?)")

    # Validate recipient + resolve its inbox before doing any work.
    peer_path_dir = peer_inbox(to_fqid)

    tree = scaffold(agent=agent)
    signer = _load_signer(ident.get("agent") or from_fqid.split("@", 1)[0])

    env = build_envelope(
        from_fqid,
        to_fqid,
        message,
        subject=subject,
        thread_id=thread_id,
        reply_to=reply_to,
    )
    signed = signer.sign(env)
    data = signed.to_bytes()
    fname = f"{env.created_at.replace(':', '').replace('.', '')}-{env.id}.json"

    outbox_path = tree["outbox"] / fname
    outbox_path.write_bytes(data)

    peer_path_dir.mkdir(parents=True, exist_ok=True)
    peer_inbox_path = peer_path_dir / fname
    peer_inbox_path.write_bytes(data)

    logger.debug("sent %s -> %s (%s)", from_fqid, to_fqid, env.id)
    return {
        "id": env.id,
        "from_fqid": from_fqid,
        "to_fqid": to_fqid,
        "outbox_path": str(outbox_path),
        "peer_inbox_path": str(peer_inbox_path),
    }


# ---------------------------------------------------------------------------
# inbox
# ---------------------------------------------------------------------------


def read_inbox(agent: Optional[str] = None) -> list[tuple[Envelope, VerificationResult]]:
    """Read + verify all SignedEnvelopes in this agent's inbox.

    Each inbox file is parsed; its signature is verified against the
    sender's public key (loaded via :func:`_load_verifier_key`). Returns
    ``(envelope, verification)`` pairs sorted by file name (chronological).

    Args:
        agent: Override the agent whose inbox to read.

    Returns:
        List of ``(Envelope, VerificationResult)`` tuples.
    """
    tree = scaffold(agent=agent)
    inbox: Path = tree["inbox"]
    results: list[tuple[Envelope, VerificationResult]] = []

    for path in sorted(inbox.glob("*.json")):
        try:
            signed = SignedEnvelope.from_bytes(path.read_bytes())
        except Exception as exc:
            logger.warning("unparseable inbox file %s: %s", path, exc)
            continue

        verifier = EnvelopeVerifier()
        pub = _load_verifier_key(signed.envelope.from_fqid)
        if pub:
            verifier.add_key(signed.envelope.from_fqid, pub)
        results.append((signed.envelope, verifier.verify(signed)))

    return results


# ---------------------------------------------------------------------------
# peers
# ---------------------------------------------------------------------------


def list_peers(agent: Optional[str] = None) -> list[dict]:
    """List known peers discovered in the ~/.skcapstone/skcomms realm tree.

    A peer is any ``<realm>/<operator>/<agent>`` directory other than this
    agent's own. Useful for routing and discovery before real Syncthing
    peer wiring (T7/T8) lands.

    Args:
        agent: Override this agent's identity (excluded from the result).

    Returns:
        List of dicts with ``fqid``, ``realm``, ``operator``, ``agent``,
        ``inbox`` (path), and ``messages`` (inbox message count).
    """
    ident = resolve_self_identity(agent)
    self_fqid = ident.get("fqid")
    home = skcomms_home()
    peers: list[dict] = []

    if not home.exists():
        return peers

    for realm_dir in sorted(p for p in home.iterdir() if p.is_dir()):
        for op_dir in sorted(p for p in realm_dir.iterdir() if p.is_dir()):
            for agent_dir in sorted(p for p in op_dir.iterdir() if p.is_dir()):
                fqid = f"{agent_dir.name}@{op_dir.name}.{realm_dir.name}"
                if fqid == self_fqid:
                    continue
                inbox = agent_dir / "inbox"
                count = len(list(inbox.glob("*.json"))) if inbox.exists() else 0
                peers.append(
                    {
                        "fqid": fqid,
                        "realm": realm_dir.name,
                        "operator": op_dir.name,
                        "agent": agent_dir.name,
                        "inbox": str(inbox),
                        "messages": count,
                    }
                )
    return peers
