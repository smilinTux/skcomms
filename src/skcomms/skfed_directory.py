"""SKFed sovereign per-realm discovery directory (model + persistence).

A realm directory maps every ``<agent>@<operator>.<realm>`` FQID in a realm to
its *live* endpoints — the federation inbox URL, the hybrid-prekey URL, an
optional DID, and capability tags. The whole directory is CapAuth-signed by the
realm **operator** (:class:`skcomms.signing.EnvelopeSigner`), so a sender can:

    1. fetch the realm directory (``GET /.well-known/skfed/directory``),
    2. verify its signature against the operator identity,
    3. look up the recipient agent's entry,
    4. deliver — with **NO local peer config**.

Because the directory is just a signed file served over the existing public
:443 funnel, **anyone can run their own realm directory**: stand up the service,
hold the operator key, let agents announce themselves. This module is the lib
half (model + sign/verify + persistence + self-announce); :mod:`skcomms.api`
serves it and gates announcements; :mod:`skcomms.skfed_resolve` consumes it.

Persisted at ``skcomms_home()/skfed/directory.json``.

Wire format (``to_bytes``/``from_bytes``) is the pydantic JSON of
:class:`SignedDirectory`. The signature covers a stable canonical serialization
of ``{realm, operator, signed_at, entries}`` (see :meth:`SignedDirectory.signing_bytes`)
— ``sig`` / ``signer_fingerprint`` are excluded from what they sign.

Follow-ups (noted, not built here): the live ``chef.skworld`` directory instance
+ DNS ``_skfed._tcp.skworld`` SRV/TXT records, and a Nostr secondary (publish the
signed directory as a replaceable event for censorship-resistant discovery).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .cluster import get_operator, get_realm
from .home import skcomms_home
from .signing import EnvelopeSigner, EnvelopeVerifier

logger = logging.getLogger("skcomms.skfed_directory")

SKFED_DIR_NAME = "skfed"
DIRECTORY_FILE = "directory.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DirectoryEntry(BaseModel):
    """A single agent's live endpoints within a realm directory.

    Attributes:
        fqid: ``<agent>@<operator>.<realm>`` handle this entry resolves.
        inbox_url: Reachable federation S2S inbox (``/api/v1/inbox``).
        prekey_url: Reachable hybrid-prekey bundle URL (``/api/v1/prekey``),
            if published. ``None`` when the agent advertises no prekey.
        did: Optional decentralized identifier for the agent.
        caps: Capability tags the agent advertises (e.g. ``dm``, ``files``).
        updated_at: UTC ISO-8601 of the last announcement for this entry.
    """

    fqid: str
    inbox_url: str
    prekey_url: Optional[str] = None
    did: Optional[str] = None
    caps: list[str] = Field(default_factory=list)
    updated_at: str = Field(default_factory=_utc_now_iso)


class SignedDirectory(BaseModel):
    """A realm directory plus the operator's CapAuth signature over it.

    Attributes:
        realm: The realm this directory is authoritative for.
        operator: The operator identity that signs the directory (the key
            registered under this label in a verifier).
        entries: Per-agent :class:`DirectoryEntry` records.
        signed_at: UTC ISO-8601 of when the directory was last (re-)signed.
        sig: ASCII-armored PGP detached signature over :meth:`signing_bytes`.
        signer_fingerprint: 40-char hex fingerprint of the signing key.
    """

    realm: str
    operator: str
    entries: list[DirectoryEntry] = Field(default_factory=list)
    signed_at: str = Field(default_factory=_utc_now_iso)
    sig: str = ""
    signer_fingerprint: str = ""

    # -- canonicalization ---------------------------------------------------

    def signing_bytes(self) -> bytes:
        """Stable bytes the signature covers: ``{realm, operator, signed_at, entries}``.

        Entries are sorted by fqid and keys are sorted/compact so the bytes are
        deterministic regardless of insertion order. ``sig`` /
        ``signer_fingerprint`` are excluded (they are *about* the signature).
        """
        payload = {
            "realm": self.realm,
            "operator": self.operator,
            "signed_at": self.signed_at,
            "entries": [
                e.model_dump(mode="json")
                for e in sorted(self.entries, key=lambda x: x.fqid)
            ],
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    # -- build / sign / verify ---------------------------------------------

    @classmethod
    def build(
        cls,
        *,
        realm: str,
        operator: str,
        entries: list[DirectoryEntry],
        signer: EnvelopeSigner,
        signed_at: Optional[str] = None,
    ) -> "SignedDirectory":
        """Construct a directory and CapAuth-sign it with *signer*.

        Args:
            realm: Realm name.
            operator: Operator identity label (the verifier key label).
            entries: Directory entries to include.
            signer: The operator's :class:`~skcomms.signing.EnvelopeSigner`.
            signed_at: Override the signing timestamp (defaults to now).

        Returns:
            SignedDirectory: with ``sig`` + ``signer_fingerprint`` populated.
        """
        sd = cls(
            realm=realm,
            operator=operator,
            entries=list(entries),
            signed_at=signed_at or _utc_now_iso(),
        )
        sd.signer_fingerprint = signer.fingerprint
        sd.sig = signer.sign_bytes(sd.signing_bytes())
        return sd

    def verify(self, verifier: EnvelopeVerifier) -> bool:
        """Verify the operator signature against a preloaded *verifier*.

        The verifier must hold the operator's public key (registered under the
        ``operator`` label and/or the ``signer_fingerprint``). Fails closed.

        Returns:
            bool: ``True`` only if the operator validly signed this directory.
        """
        if not self.sig:
            return False
        return verifier.verify_bytes(
            self.signing_bytes(),
            self.sig,
            identity=self.operator,
            fingerprint=self.signer_fingerprint or None,
        )

    # -- mutation -----------------------------------------------------------

    def upsert(self, entry: DirectoryEntry) -> None:
        """Insert *entry*, or replace the existing entry with the same fqid.

        Mutates ``entries`` in place (does NOT re-sign — call :meth:`build` /
        :func:`upsert_entry` to produce a freshly signed directory).
        """
        for i, existing in enumerate(self.entries):
            if existing.fqid == entry.fqid:
                self.entries[i] = entry
                return
        self.entries.append(entry)

    def get(self, fqid: str) -> Optional[DirectoryEntry]:
        """Return the entry for *fqid*, or ``None``."""
        for e in self.entries:
            if e.fqid == fqid:
                return e
        return None

    # -- wire format --------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize the signed directory to pretty UTF-8 JSON bytes."""
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedDirectory":
        """Deserialize a signed directory from UTF-8 JSON bytes."""
        return cls.model_validate_json(data)


# ---------------------------------------------------------------------------
# Persistence (skcomms_home()/skfed/directory.json)
# ---------------------------------------------------------------------------


def directory_path() -> Path:
    """Path to this realm's persisted signed directory."""
    return skcomms_home() / SKFED_DIR_NAME / DIRECTORY_FILE


def load_directory() -> Optional[SignedDirectory]:
    """Load the persisted realm directory, or ``None`` if absent/unreadable."""
    path = directory_path()
    if not path.exists():
        return None
    try:
        return SignedDirectory.from_bytes(path.read_bytes())
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("failed to load realm directory at %s: %s", path, exc)
        return None


def save_directory(sd: SignedDirectory) -> Path:
    """Atomically persist the signed directory; returns the written path."""
    path = directory_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{DIRECTORY_FILE}.tmp"
    tmp.write_bytes(sd.to_bytes())
    tmp.replace(path)
    return path


def upsert_entry(
    entry: DirectoryEntry,
    *,
    signer: EnvelopeSigner,
    realm: Optional[str] = None,
    operator: Optional[str] = None,
) -> SignedDirectory:
    """Upsert *entry* into the persisted directory, re-sign, and persist.

    Loads the existing directory (or starts an empty one for this realm),
    upserts the entry, rebuilds a freshly signed :class:`SignedDirectory` with
    *signer*, writes it to disk, and returns it.

    Args:
        entry: The agent endpoint record to insert/replace.
        signer: The operator/node signing key (re-signs the whole directory).
        realm: Realm name for a brand-new directory (defaults to cluster realm).
        operator: Operator label for a brand-new directory (defaults to cluster).

    Returns:
        SignedDirectory: the freshly signed, persisted directory.
    """
    sd = load_directory()
    if sd is None:
        sd = SignedDirectory(
            realm=realm or get_realm(),
            operator=operator or get_operator(),
            entries=[],
        )
    sd.upsert(entry)
    signed = SignedDirectory.build(
        realm=sd.realm, operator=sd.operator, entries=sd.entries, signer=signer
    )
    save_directory(signed)
    return signed


# ---------------------------------------------------------------------------
# Node signer + self-announce
# ---------------------------------------------------------------------------


def load_node_signer(agent: Optional[str] = None) -> EnvelopeSigner:
    """Load this node's directory-signing key (the operator/node CapAuth key).

    Reuses :func:`skcomms.mailbox._load_signer` (the proven per-agent CapAuth
    key loader). Split into its own function so the API layer + self-announce
    have a single, monkeypatchable seam.

    Raises:
        FileNotFoundError: if no private key is available for *agent*.
    """
    from .identity import resolve_self_identity
    from .mailbox import _load_signer

    if agent is None:
        agent = resolve_self_identity().get("agent") or "local"
    return _load_signer(agent)


def publish_self_to_realm_directory(
    fqid: str,
    inbox_url: str,
    prekey_url: Optional[str] = None,
    *,
    did: Optional[str] = None,
    caps: Optional[list[str]] = None,
    agent: Optional[str] = None,
    signer: Optional[EnvelopeSigner] = None,
    realm: Optional[str] = None,
    operator: Optional[str] = None,
) -> SignedDirectory:
    """Self-announce: upsert THIS agent's endpoints into the local realm directory.

    The helper an agent daemon calls on startup when it co-hosts (or is) the
    realm directory: it stamps a fresh :class:`DirectoryEntry` for *fqid* and
    re-signs the directory with the node key. (For an agent on a *different*
    node, the daemon instead POSTs a signed announce to
    ``/api/v1/skfed/announce`` — same upsert, remote.)

    Args:
        fqid: This agent's ``<agent>@<operator>.<realm>`` handle.
        inbox_url: This agent's reachable federation inbox URL.
        prekey_url: This agent's reachable hybrid-prekey URL, if any.
        did: Optional DID to advertise.
        caps: Optional capability tags.
        agent: Short agent name for key loading (defaults to resolved identity).
        signer: Override the node signer (defaults to :func:`load_node_signer`).
        realm / operator: Override realm/operator for a brand-new directory.

    Returns:
        SignedDirectory: the freshly signed, persisted directory.
    """
    signer = signer or load_node_signer(agent)
    entry = DirectoryEntry(
        fqid=fqid,
        inbox_url=inbox_url,
        prekey_url=prekey_url,
        did=did,
        caps=list(caps or []),
        updated_at=_utc_now_iso(),
    )
    return upsert_entry(entry, signer=signer, realm=realm, operator=operator)
