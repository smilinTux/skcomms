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

import json
import logging
import os
from pathlib import Path
from typing import Optional

from .cluster import get_operator, get_realm
from .crypto import PQDM_SCHEME, CryptoError, EnvelopeCrypto
from .envelope import Envelope, SignedEnvelope
from .home import peer_inbox, scaffold, skcomms_home
from .identity import resolve_self_identity
from .models import MessageEnvelope, MessagePayload
from .signing import EnvelopeSigner, EnvelopeVerifier, VerificationResult

logger = logging.getLogger("skcomms.mailbox")


# ---------------------------------------------------------------------------
# At-rest encryption of the inbox drop (HIGH — plaintext-in-Syncthing-inbox)
# ---------------------------------------------------------------------------
#
# The recipient's ``inbox/`` directory is replicated by Syncthing to the peer,
# so a signed-but-unencrypted envelope leaves every message body in cleartext
# on disk and in transit-at-rest. We seal the ENTIRE SignedEnvelope to the
# recipient's public key before it touches the inbox, and unseal it on read.
# The sender's ``outbox/`` record lives in the SAME replicated tree (the
# operator subtree is published Send-Only to every peer, see
# docs/SYNCTHING_TOPOLOGY.md section 2), so it is sealed too, to the sender's
# OWN key, and read back via read_outbox().
#
# The seal reuses the vetted, fail-closed PGP primitive in
# :class:`skcomms.crypto.EnvelopeCrypto` (``encrypt_payload`` /
# ``decrypt_payload``) — we do NOT roll our own crypto. The signed-envelope
# JSON is carried as the ``content`` of a throwaway :class:`MessageEnvelope`
# payload; the ciphertext is then persisted inside a small self-describing
# JSON wrapper so ``read_inbox`` can recognise + reverse it.

#: Wire marker for a sealed at-rest inbox file. Present as a top-level JSON key
#: so a sealed drop is trivially distinguishable from a legacy plaintext
#: SignedEnvelope (which has an ``envelope`` key, never this one).
AT_REST_MARKER = "skcomms_sealed_at_rest"
AT_REST_SCHEME = "pgp-v1"


def _is_already_sealed(body: str) -> bool:
    """Whether *body* is already ciphertext from an upstream layer.

    Idempotency guard (requirement 3): a body that arrives already sealed by an
    upstream layer — the skchat DM ratchet (``pqdm1:`` hybrid tokens) or a
    classical PGP-armored blob — is confidential on its own. Re-encrypting it at
    the mailbox layer would be wasted work AND, more importantly, would render
    the outer signed envelope opaque even to a recipient who only holds the
    ratchet key. In that case we sign + drop the SignedEnvelope WITHOUT the
    at-rest PGP wrap; the body is already unreadable on disk.

    Detection is conservative: only the two seal formats this codebase actually
    emits are recognised (``pqdm1:`` and ``-----BEGIN PGP MESSAGE-----``). Any
    other body is treated as plaintext and IS sealed. This assumption is
    documented in the commit body — if a future upstream layer introduces a new
    seal format, extend this predicate rather than let plaintext through.
    """
    if not body:
        return False
    b = body.lstrip()
    return b.startswith(PQDM_SCHEME) or b.startswith("-----BEGIN PGP MESSAGE-----")


def _seal_for_recipient(signed: SignedEnvelope, recipient_pub_armor: str) -> bytes:
    """Encrypt a SignedEnvelope to *recipient_pub_armor*, fail-closed.

    Returns the bytes to write to the inbox: a JSON wrapper carrying the PGP
    ciphertext of the signed-envelope JSON. Reuses
    :meth:`EnvelopeCrypto.encrypt_payload`, which raises
    :class:`~skcomms.crypto.CryptoError` if encryption was requested but could
    not be performed — so we never fall back to plaintext.

    Raises:
        CryptoError: If PGP is unavailable, the recipient key is missing/unusable,
            or encryption otherwise fails (confidentiality could not be provided).
    """
    if not recipient_pub_armor or not recipient_pub_armor.strip():
        raise CryptoError(
            "no recipient public key for at-rest inbox encryption — refusing "
            "to write plaintext to the Syncthing-replicated inbox"
        )

    crypto = EnvelopeCrypto(private_key_armor="", passphrase="")
    if not crypto._pgp_available:
        raise CryptoError(
            "PGP backend unavailable — refusing to write plaintext to the "
            "Syncthing-replicated inbox"
        )

    # Carry the full signed-envelope JSON as the payload content and let the
    # vetted, fail-closed primitive PGP-encrypt it to the recipient.
    carrier = MessageEnvelope(
        sender=signed.envelope.from_fqid,
        recipient=signed.envelope.to_fqid,
        payload=MessagePayload(content=signed.to_bytes().decode("utf-8")),
    )
    encrypted = crypto.encrypt_payload(carrier, recipient_pub_armor)
    if not encrypted.payload.encrypted:
        # encrypt_payload's graceful-degradation path returns unchanged (PGP
        # missing / empty key). We already guarded both above, so reaching here
        # means the seal silently no-op'd — treat as a hard failure, never leak.
        raise CryptoError(
            "at-rest encryption did not seal the payload — refusing to write "
            "plaintext to the Syncthing-replicated inbox"
        )

    wrapper = {
        AT_REST_MARKER: AT_REST_SCHEME,
        "to_fqid": signed.envelope.to_fqid,
        "from_fqid": signed.envelope.from_fqid,
        "ciphertext": encrypted.payload.content,
    }
    return json.dumps(wrapper, indent=2).encode("utf-8")


def _unseal_at_rest(data: bytes, crypto: Optional[EnvelopeCrypto]) -> SignedEnvelope:
    """Reverse :func:`_seal_for_recipient` into a SignedEnvelope.

    If *data* is a plaintext SignedEnvelope (legacy drop, or an idempotent
    already-sealed-body drop), it is parsed directly. If it is an at-rest PGP
    wrapper, *crypto* (the reader's own key) decrypts it first.

    Raises:
        ValueError / CryptoError: on malformed or undecryptable input.
    """
    try:
        obj = json.loads(data)
    except Exception:
        # Not JSON at all — let SignedEnvelope surface the parse error.
        return SignedEnvelope.from_bytes(data)

    if not (isinstance(obj, dict) and obj.get(AT_REST_MARKER)):
        # Plaintext SignedEnvelope (legacy or idempotent already-sealed-body).
        return SignedEnvelope.from_bytes(data)

    if crypto is None:
        raise CryptoError("sealed inbox file but no reader key available to open it")

    carrier = MessageEnvelope(
        sender=obj.get("from_fqid", ""),
        recipient=obj.get("to_fqid", ""),
        payload=MessagePayload(content=obj["ciphertext"], encrypted=True),
    )
    opened = crypto.decrypt_payload(carrier)
    if opened.payload.encrypted:
        raise CryptoError("failed to decrypt sealed inbox file")
    return SignedEnvelope.from_bytes(opened.payload.content.encode("utf-8"))


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


def _load_private_armor(agent: str) -> Optional[str]:
    """Load the reader's own ASCII-armored PGP private key.

    Mirrors :func:`_load_signer`'s candidate search, but returns the raw armor
    so the at-rest inbox unsealer can build an :class:`EnvelopeCrypto` to
    decrypt drops addressed to this agent. Returns ``None`` when no key is
    found (a sealed inbox file then reports honestly as undecryptable).
    """
    candidates = [
        _agent_identity_dir(agent) / "private.asc",
        _agent_identity_dir(agent) / "agent.private.asc",
        Path.home() / ".capauth" / "identity" / "private.asc",
    ]
    for path in candidates:
        if path.exists():
            return path.read_text(encoding="utf-8")
    return None


def _load_recipient_key(to_fqid: str) -> Optional[str]:
    """Load the public key to ENCRYPT the at-rest inbox drop to, fail-closed.

    This is deliberately stricter than :func:`_load_verifier_key`. The verifier
    path may fall back to the local operator key (``~/.capauth/identity/``) for
    ANY fqid, which is fine for signature checks (a wrong key just reports an
    invalid signature). For encryption that fallback is dangerous: a send to a
    REMOTE operator's agent would silently seal the message to the LOCAL
    operator's key, a key the recipient does not hold. The message would be
    undecryptable at the far end and, worse, readable by the wrong party here.

    Resolution order:

    1. The recipient agent's own CapAuth identity dir, but ONLY when the
       fqid's ``operator.realm`` matches this box's cluster identity (same-box
       agents). A bare agent name (no ``@``) addresses a same-box agent by
       construction and qualifies too. Without this gate, a remote fqid whose
       AGENT NAME collides with a local agent (``lumina@stranger.otherrealm``
       on a box with local agent ``lumina``) would silently seal to the LOCAL
       agent's key: undecryptable by the real recipient, readable by the
       wrong local party.
    2. The pinned peer key store ``<home>/peers/<fqid>.asc`` (remote peers,
       TOFU-pinned via ``skcomms peers add``), keyed by FULL fqid so it can
       never collide across operators.
    3. The local operator key, gated on the same ``operator.realm`` match
       (legacy same-operator layouts where agents share the operator keypair).
       A remote-operator fqid NEVER falls back to the local operator key.

    Returns ``None`` when no plausible recipient key exists; the caller then
    refuses to write (never a plaintext or wrong-key fallback).
    """
    if "@" in to_fqid:
        agent, suffix = to_fqid.split("@", 1)
        same_box = suffix == f"{get_operator()}.{get_realm()}"
    else:
        agent = to_fqid
        same_box = True

    candidates: list[Path] = []
    if same_box:
        # Local-agent keys are addressed by bare agent name, so they are only
        # trustworthy for fqids that actually live on this box.
        candidates.extend(
            [
                _agent_identity_dir(agent) / "public.asc",
                _agent_identity_dir(agent) / "agent.pub",
            ]
        )
    candidates.append(skcomms_home() / "peers" / f"{to_fqid}.asc")
    if same_box and "@" in to_fqid:
        candidates.append(Path.home() / ".capauth" / "identity" / "public.asc")

    for path in candidates:
        if path.exists():
            return path.read_text(encoding="utf-8")
    return None


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

    The signed envelope is written to the sender's ``outbox`` (local record,
    sealed to the sender's own key) and to the recipient peer's ``inbox``
    (the Syncthing drop path, sealed to the recipient's key). Both locations
    live inside the Syncthing-replicated realm tree, so neither is ever
    written in plaintext (fail closed on any sealing error).

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

    # Pin the sending agent ONCE from the resolved identity and reuse it for
    # every per-agent path/key below. Passing the raw ``agent`` (often None)
    # back into scaffold() would let home.py re-resolve independently against
    # the ambient SKAGENT env, so the outbox could land under a different agent
    # dir than the signer/reader use. read_outbox(agent=X) would then miss the
    # record. Resolve here, scope everything to it.
    resolved_agent = ident.get("agent") or from_fqid.split("@", 1)[0]

    # Validate recipient + resolve its inbox before doing any work.
    peer_path_dir = peer_inbox(to_fqid)

    tree = scaffold(agent=resolved_agent)
    signer = _load_signer(resolved_agent)

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

    # Both drops land inside the Syncthing-replicated realm tree (see
    # docs/SYNCTHING_TOPOLOGY.md section 2: the operator subtree, INCLUDING the
    # sender's own outbox/, is published Send-Only to every peer). So BOTH the
    # peer inbox drop and the local outbox record must be sealed at rest,
    # unless the body is already sealed upstream (idempotency; see
    # _is_already_sealed). FAIL CLOSED: all sealing is done FIRST so any
    # encryption failure raises before we persist ANYTHING (no half-sent
    # plaintext left behind).
    if _is_already_sealed(message):
        logger.debug("body already sealed upstream, skipping at-rest wrap for %s", env.id)
        inbox_bytes = data
        outbox_bytes = data
    else:
        # Inbox drop: sealed to the RECIPIENT. _load_recipient_key never falls
        # back to the local operator key for a remote-operator fqid, so a
        # missing peer key fails the send here instead of sealing to a key the
        # recipient does not hold.
        recipient_pub = _load_recipient_key(to_fqid)
        inbox_bytes = _seal_for_recipient(signed, recipient_pub)
        # Outbox record: sealed to the SENDER's own key (derived from the
        # signing key just used, so it can never resolve to a different key).
        # Escape hatch for debugging legacy deploys:
        # SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT=1 keeps the old readable record.
        if os.environ.get("SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT") == "1":
            # Loud on purpose: a forgotten env var silently writes plaintext
            # into the peer-replicated tree, so every send says so in the logs.
            logger.warning(
                "SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT=1 active: writing PLAINTEXT "
                "outbox record %s into the Syncthing-replicated tree (debug "
                "escape hatch; unset the env var when done)",
                env.id,
            )
            outbox_bytes = data
        else:
            outbox_bytes = _seal_for_recipient(signed, signer.public_key_armor)

    # Sender's own local record (readable back via read_outbox).
    outbox_path = tree["outbox"] / fname
    outbox_path.write_bytes(outbox_bytes)

    peer_path_dir.mkdir(parents=True, exist_ok=True)
    peer_inbox_path = peer_path_dir / fname
    peer_inbox_path.write_bytes(inbox_bytes)

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


def _read_sealed_dir(
    directory: Path, reader_crypto: Optional[EnvelopeCrypto]
) -> list[tuple[Envelope, VerificationResult]]:
    """Read + verify all (possibly at-rest sealed) SignedEnvelopes in *directory*.

    Shared engine behind :func:`read_inbox` and :func:`read_outbox`. Each file
    is unsealed with *reader_crypto* when it carries the at-rest wrapper, then
    its signature is verified against the sender's public key (loaded via
    :func:`_load_verifier_key`). Returns ``(envelope, verification)`` pairs
    sorted by file name (chronological).
    """
    results: list[tuple[Envelope, VerificationResult]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            signed = _unseal_at_rest(path.read_bytes(), reader_crypto)
        except Exception as exc:
            logger.warning("unparseable/undecryptable mailbox file %s: %s", path, exc)
            continue

        verifier = EnvelopeVerifier()
        pub = _load_verifier_key(signed.envelope.from_fqid)
        if pub:
            verifier.add_key(signed.envelope.from_fqid, pub)
        results.append((signed.envelope, verifier.verify(signed)))
    return results


def _reader_crypto_for(agent: Optional[str]) -> Optional[EnvelopeCrypto]:
    """Build a decrypter from THIS agent's own private key.

    At-rest sealed drops (see :func:`send_message`) are opened with the
    reader's own key. Reader identity resolves the same way ``scaffold()``
    does when *agent* is None. Returns ``None`` when no key is found (a
    sealed file then reports honestly as undecryptable).
    """
    reader = agent or (resolve_self_identity(agent).get("agent") or "")
    priv_armor = _load_private_armor(reader) if reader else None
    if not priv_armor:
        return None
    passphrase = os.environ.get("SKCOMMS_KEY_PASSPHRASE", "")
    return EnvelopeCrypto(private_key_armor=priv_armor, passphrase=passphrase)


def read_inbox(agent: Optional[str] = None) -> list[tuple[Envelope, VerificationResult]]:
    """Read + verify all SignedEnvelopes in this agent's inbox.

    Args:
        agent: Override the agent whose inbox to read.

    Returns:
        List of ``(Envelope, VerificationResult)`` tuples, chronological.
    """
    tree = scaffold(agent=agent)
    return _read_sealed_dir(tree["inbox"], _reader_crypto_for(agent))


def read_outbox(agent: Optional[str] = None) -> list[tuple[Envelope, VerificationResult]]:
    """Read + verify this agent's own sent-message records.

    The outbox record is sealed at rest to the sender's own key (it lives in
    the Syncthing-published operator subtree; see :func:`send_message`), so
    this is the supported way to read back what was sent.

    Args:
        agent: Override the agent whose outbox to read.

    Returns:
        List of ``(Envelope, VerificationResult)`` tuples, chronological.
    """
    tree = scaffold(agent=agent)
    return _read_sealed_dir(tree["outbox"], _reader_crypto_for(agent))


# ---------------------------------------------------------------------------
# legacy plaintext outbox migration (housekeeping sweep)
# ---------------------------------------------------------------------------


def reseal_outbox_plaintext(home: Optional[Path] = None) -> dict:
    """Re-seal (or purge) legacy PLAINTEXT outbox records in the local tree.

    Records written before the at-rest outbox seal landed are plaintext
    SignedEnvelopes sitting in the Syncthing-published operator subtree, and
    they stay readable until age-based pruning removes them. This sweep closes
    that window: it walks every agent outbox under THIS box's own
    ``<realm>/<operator>/`` subtree (never a peer's mirrored subtree, which
    Syncthing would fight us over) and, for each legacy plaintext record:

      * re-seals it to the sending agent's own key (resolved via the strict
        :func:`_load_recipient_key`, atomic tmp-then-rename, original mtime
        preserved so age-based pruning stays honest), or
      * purges it when no local key resolves (fail closed: a plaintext record
        we cannot seal does not get to keep sitting in the replicated tree).

    Skipped without touching: already-sealed at-rest wrappers, records whose
    BODY is already ciphertext from an upstream layer (the idempotent design,
    see :func:`_is_already_sealed`), and unparseable files (pruning ages those
    out). When ``SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT=1`` is active the sweep is a
    no-op (the operator explicitly asked for readable records) and warns.

    Args:
        home: Override the skcomms home root (defaults to
            :func:`skcomms.home.skcomms_home`, which honors ``SKCOMMS_HOME``).

    Returns:
        dict: ``{"resealed": int, "purged": int}`` counts for the sweep.
    """
    result = {"resealed": 0, "purged": 0}

    if os.environ.get("SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT") == "1":
        logger.warning(
            "SKCOMMS_MAILBOX_OUTBOX_PLAINTEXT=1 active: skipping the legacy "
            "plaintext outbox re-seal sweep (records stay readable on disk)"
        )
        return result

    root = home if home is not None else skcomms_home()
    op_root = root / get_realm() / get_operator()
    if not op_root.is_dir():
        return result

    for agent_dir in sorted(p for p in op_root.iterdir() if p.is_dir()):
        outbox = agent_dir / "outbox"
        if not outbox.is_dir():
            continue
        for record in sorted(outbox.glob("*.json")):
            if record.name.startswith("."):
                continue
            try:
                raw = record.read_bytes()
            except OSError as exc:
                logger.warning("cannot read outbox record %s: %s", record, exc)
                continue

            try:
                obj = json.loads(raw)
            except Exception:
                continue  # not JSON; pruning ages it out
            if isinstance(obj, dict) and obj.get(AT_REST_MARKER):
                continue  # already sealed at rest

            try:
                signed = SignedEnvelope.from_bytes(raw)
            except Exception:
                continue  # not a mailbox record we understand
            if _is_already_sealed(signed.envelope.body):
                continue  # body is ciphertext on its own (idempotent design)

            # Legacy plaintext record. Seal to the sending agent's own key,
            # or purge when no key resolves (never leave plaintext behind).
            try:
                pub = _load_recipient_key(signed.envelope.from_fqid)
                if pub:
                    sealed = _seal_for_recipient(signed, pub)
                    stat = record.stat()
                    tmp = record.with_name(f".{record.name}.reseal.tmp")
                    tmp.write_bytes(sealed)
                    os.utime(tmp, (stat.st_atime, stat.st_mtime))
                    tmp.replace(record)
                    result["resealed"] += 1
                else:
                    record.unlink()
                    result["purged"] += 1
                    logger.warning(
                        "purged legacy plaintext outbox record %s "
                        "(no local key to re-seal it to)",
                        record,
                    )
            except Exception as exc:
                logger.warning("failed to re-seal outbox record %s: %s", record, exc)

    if result["resealed"] or result["purged"]:
        logger.info(
            "Re-seal sweep: %d legacy plaintext outbox record(s) sealed, %d purged",
            result["resealed"],
            result["purged"],
        )
    return result


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
