"""Identity and trust-state backup/restore (coord ``7d5344f2``).

A wiped machine bricks federation even when every message-path fix is in
place: the CapAuth signing/decryption key lives outside the repo at
``~/.capauth/identity/private.asc`` (or the per-agent
``~/.skcapstone/agents/<agent>/capauth/identity/`` layout), and if that key
is REGENERATED instead of restored, every remote peer's TOFU store
hard-CONFLICTs the new fingerprint. The node is then rejected fleet-wide
until each peer manually re-pins.

This module owns the canonical backup set and the backup/restore/check
primitives behind the ``skcomms identity`` CLI verbs:

Backup set (roles):
    - ``capauth-private-key``   ``~/.capauth/identity/private.asc`` (secret)
    - ``capauth-public-key``    ``~/.capauth/identity/public.asc``
    - ``capauth-profile``       ``~/.capauth/identity/profile.json``
    - ``agent-capauth-*``       ``~/.skcapstone/agents/<agent>/capauth/identity/{private.asc,public.asc,profile.json}``
    - ``agent-pubkey``          ``~/.skcapstone/agents/<agent>/identity/agent.pub``
    - ``cluster``               ``~/.skcapstone/cluster.json``
    - ``tofu-store``            ``$SKCOMMS_HOME/known_fingerprints.json``
    - ``peers``                 ``$SKCOMMS_HOME/peers.json``
    - ``outbox-pending``        ``$SKCOMMS_HOME/outbox/pending/*.json``

Archives are ``.tar.gz`` files created with mode 0600, containing a
``MANIFEST.json`` (version, timestamps, per-file sha256) plus the payload
files. Members are addressed by logical root (``home`` or ``skcomms_home``)
and a relative path, so a backup restores correctly on a machine with a
different username or SKCOMMS_HOME.

Fail-closed properties:
    - ``create_backup`` refuses to produce an archive with no private key
      (that archive could never restore crypto) unless ``allow_partial``.
    - ``restore_backup`` verifies every payload sha256 against the manifest
      and rejects the whole archive on any mismatch or path traversal.
      That is an INTEGRITY check (corruption, truncation, bit rot), not
      authenticity: the manifest itself is unsigned, so an attacker who can
      rewrite the archive rewrites manifest and payload consistently. Treat
      the backup media as trusted; archive signing (capauth-signed manifest)
      is planned hardening, see SOP.md section 11.
    - ``restore_backup`` never overwrites an existing DIFFERING file unless
      ``force`` is set; identical files are skipped silently.
    - ``enforce_identity_gate`` raises :class:`IdentityMissingError` when
      ``SKCOMMS_REQUIRE_IDENTITY`` is truthy and no private key is present,
      so a gated daemon exits nonzero instead of coming up green with dead
      crypto.

Runbook: SOP.md section 11 (backup/restore ordering + key-loss re-pin).
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import secrets
import socket
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .home import skcomms_home

logger = logging.getLogger("skcomms.trustbackup")

MANIFEST_NAME = "MANIFEST.json"
MANIFEST_VERSION = 1

#: Logical roots. Archive members carry (root, relpath) so restore resolves
#: against the TARGET machine's home / SKCOMMS_HOME, not the source paths.
ROOT_HOME = "home"
ROOT_SKCOMMS = "skcomms_home"

#: Env gate: when truthy, a missing CapAuth private key is FATAL at daemon
#: startup (nonzero exit) instead of a loud warning + degraded health.
REQUIRE_IDENTITY_ENV = "SKCOMMS_REQUIRE_IDENTITY"

_TRUTHY = {"1", "true", "yes", "on"}


class TrustBackupError(Exception):
    """Raised when a backup or restore operation must fail closed."""


class IdentityMissingError(TrustBackupError):
    """Raised by the identity gate when the CapAuth private key is absent
    and ``SKCOMMS_REQUIRE_IDENTITY`` demands a hard failure."""


@dataclass
class BackupItem:
    """One file in the canonical identity/trust backup set.

    Attributes:
        role: Stable role token (``capauth-private-key``, ``tofu-store``, ...).
        root: Logical root (:data:`ROOT_HOME` or :data:`ROOT_SKCOMMS`).
        relpath: Path relative to the logical root (POSIX separators).
        secret: Whether the file is key material (restored with mode 0600).
    """

    role: str
    root: str
    relpath: str
    secret: bool = False

    def resolve(self) -> Path:
        """Absolute path of this item on the current machine."""
        base = skcomms_home() if self.root == ROOT_SKCOMMS else Path.home()
        return base / self.relpath

    @property
    def member(self) -> str:
        """Archive member name (``<root>/<relpath>``)."""
        return f"{self.root}/{self.relpath}"


def _resolve_agent(agent: Optional[str] = None) -> str:
    """Short agent name for per-agent path construction."""
    if agent:
        return agent
    try:
        from .identity import resolve_self_identity

        ident = resolve_self_identity()
        fqid = ident.get("fqid")
        if fqid and "@" in fqid:
            return fqid.split("@", 1)[0]
        name = ident.get("agent")
        if name:
            return str(name)
    except Exception as exc:  # noqa: BLE001
        logger.debug("agent resolution failed: %s", exc)
    return os.environ.get("SKAGENT") or "local"


def backup_set(agent: Optional[str] = None) -> list[BackupItem]:
    """The canonical identity + trust-state backup set for *agent*.

    Returns every item in the set whether or not it exists on disk (callers
    check :meth:`BackupItem.resolve`). Pending-outbox entries are expanded
    from the live directory, so only existing files appear for that role.
    """
    name = _resolve_agent(agent)
    agent_prefix = f".skcapstone/agents/{name}"

    items = [
        BackupItem("capauth-private-key", ROOT_HOME, ".capauth/identity/private.asc", secret=True),
        BackupItem("capauth-public-key", ROOT_HOME, ".capauth/identity/public.asc"),
        BackupItem("capauth-profile", ROOT_HOME, ".capauth/identity/profile.json"),
        BackupItem(
            "agent-capauth-private-key",
            ROOT_HOME,
            f"{agent_prefix}/capauth/identity/private.asc",
            secret=True,
        ),
        BackupItem(
            "agent-capauth-public-key",
            ROOT_HOME,
            f"{agent_prefix}/capauth/identity/public.asc",
        ),
        BackupItem(
            "agent-capauth-profile",
            ROOT_HOME,
            f"{agent_prefix}/capauth/identity/profile.json",
        ),
        BackupItem("agent-pubkey", ROOT_HOME, f"{agent_prefix}/identity/agent.pub"),
        BackupItem("cluster", ROOT_HOME, ".skcapstone/cluster.json"),
        BackupItem("tofu-store", ROOT_SKCOMMS, "known_fingerprints.json"),
        BackupItem("peers", ROOT_SKCOMMS, "peers.json"),
    ]

    pending = skcomms_home() / "outbox" / "pending"
    if pending.is_dir():
        for entry in sorted(pending.glob("*.json")):
            items.append(
                BackupItem("outbox-pending", ROOT_SKCOMMS, f"outbox/pending/{entry.name}")
            )
    return items


_PRIVATE_KEY_ROLES = ("capauth-private-key", "agent-capauth-private-key")


def private_key_paths(agent: Optional[str] = None) -> list[Path]:
    """The candidate CapAuth private-key paths for *agent*.

    Order matters and mirrors :func:`skcomms.core.resolve_signing_capauth_dir`:
    the per-agent layout wins when its key exists, then the consolidated
    operator layout at ``~/.skcapstone/capauth``, then the legacy operator
    layout at ``~/.capauth`` as the final fallback.
    """
    name = _resolve_agent(agent)
    return [
        Path.home()
        / ".skcapstone"
        / "agents"
        / name
        / "capauth"
        / "identity"
        / "private.asc",
        Path.home() / ".skcapstone" / "capauth" / "identity" / "private.asc",
        Path.home() / ".capauth" / "identity" / "private.asc",
    ]


def private_key_present(agent: Optional[str] = None) -> bool:
    """O(1) probe: is any CapAuth private key on disk?

    This is the health-path check. It stats exactly two paths and NEVER
    walks the backup set: :func:`backup_set` expands every pending-outbox
    entry (glob + sort + stat), and a degraded node can hold 100k+ pending
    files, so putting that on the liveness probe would time out the probe
    and restart-loop exactly the node this feature is meant to surface.
    """
    return any(p.is_file() for p in private_key_paths(agent))


def identity_check(agent: Optional[str] = None) -> dict:
    """Report presence of every item in the backup set.

    The single most important bit is ``private_key_present``: without a
    CapAuth private key this node cannot sign or decrypt anything, and a
    freshly REGENERATED key would TOFU-CONFLICT on every remote peer.

    Returns:
        Dict with ``ok`` (private key present), ``private_key_present``,
        ``agent``, ``items`` (per-item presence), and ``missing`` roles.
    """
    items = backup_set(agent)
    report = []
    missing = []
    private_key_present = False
    for item in items:
        path = item.resolve()
        present = path.is_file()
        if present and item.role in _PRIVATE_KEY_ROLES:
            private_key_present = True
        if not present and item.role != "outbox-pending":
            missing.append(item.role)
        report.append(
            {
                "role": item.role,
                "path": str(path),
                "present": present,
                "secret": item.secret,
            }
        )
    return {
        "ok": private_key_present,
        "private_key_present": private_key_present,
        "agent": _resolve_agent(agent),
        "items": report,
        "missing": missing,
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _open_private_tmp(dest: Path, mode: int) -> tuple[Path, int]:
    """Open a fresh unpredictable temp file next to *dest*, fail closed.

    The name carries a random token and the open uses ``O_EXCL``, so a
    pre-planted file or symlink at a guessable ``.tmp`` name can never be
    followed or overwritten.
    """
    tmp = dest.with_name(f"{dest.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    return tmp, fd


def _mkdir_private(directory: Path) -> None:
    """``mkdir -p`` that creates every MISSING component with mode 0700.

    Restored trees hold key material; capauth provisioning keeps its
    identity dirs private, so restore must never recreate them looser
    (default-umask 0755 leaks directory listings). Existing directories
    are left untouched.
    """
    missing: list[Path] = []
    current = directory
    while not current.exists() and current != current.parent:
        missing.append(current)
        current = current.parent
    for path in reversed(missing):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass


def create_backup(
    dest: Path | str,
    agent: Optional[str] = None,
    allow_partial: bool = False,
) -> dict:
    """Create an identity + trust-state backup archive at *dest*.

    Fail-closed: refuses to write an archive that contains NO private key
    (it could never restore crypto on a wiped machine) unless
    *allow_partial* is set explicitly.

    Args:
        dest: Output ``.tar.gz`` path (created with mode 0600).
        agent: Short agent name; ``None`` resolves the running agent.
        allow_partial: Permit an archive without any private key.

    Returns:
        Dict with ``archive``, ``count``, ``roles``, ``manifest``.

    Raises:
        TrustBackupError: No private key found and *allow_partial* is False,
            or nothing at all to back up.
    """
    dest = Path(dest).expanduser()
    items = [i for i in backup_set(agent) if i.resolve().is_file()]
    if not items:
        raise TrustBackupError("nothing to back up: no identity or trust-state files found")

    has_private = any(i.role in _PRIVATE_KEY_ROLES for i in items)
    if not has_private and not allow_partial:
        raise TrustBackupError(
            "refusing to create a backup without a CapAuth private key "
            "(it could never restore crypto); pass allow_partial to override"
        )

    manifest: dict = {
        "version": MANIFEST_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "agent": _resolve_agent(agent),
        "files": {},
    }
    payloads: list[tuple[BackupItem, bytes]] = []
    for item in items:
        data = item.resolve().read_bytes()
        payloads.append((item, data))
        manifest["files"][item.member] = {
            "role": item.role,
            "root": item.root,
            "relpath": item.relpath,
            "secret": item.secret,
            "sha256": _sha256(data),
            "size": len(data),
        }

    dest.parent.mkdir(parents=True, exist_ok=True)
    # Create with restrictive permissions BEFORE any key byte is written;
    # unpredictable name + O_EXCL so nothing pre-planted can be followed.
    tmp, fd = _open_private_tmp(dest, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            with tarfile.open(fileobj=fh, mode="w:gz") as tar:
                mdata = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
                info = tarfile.TarInfo(MANIFEST_NAME)
                info.size = len(mdata)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(mdata))
                for item, data in payloads:
                    info = tarfile.TarInfo(item.member)
                    info.size = len(data)
                    info.mode = 0o600 if item.secret else 0o644
                    tar.addfile(info, io.BytesIO(data))
        tmp.replace(dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    logger.info("identity backup written: %s (%d files)", dest, len(payloads))
    return {
        "archive": str(dest),
        "count": len(payloads),
        "roles": sorted({i.role for i in items}),
        "manifest": manifest,
    }


def _safe_relpath(relpath: str) -> str:
    """Validate a manifest relpath against traversal. Fail closed.

    Raises:
        TrustBackupError: On absolute paths, ``..`` components, backslashes,
            or NUL bytes.
    """
    if not relpath or relpath.startswith("/") or "\\" in relpath or "\x00" in relpath:
        raise TrustBackupError(f"unsafe path in backup manifest: {relpath!r}")
    for part in relpath.split("/"):
        if part in ("", ".", ".."):
            raise TrustBackupError(f"unsafe path in backup manifest: {relpath!r}")
    return relpath


def restore_backup(
    archive: Path | str,
    force: bool = False,
    dry_run: bool = False,
) -> dict:
    """Restore an identity + trust-state backup archive on this machine.

    Every payload is verified against the manifest sha256 BEFORE anything is
    written; a single mismatch rejects the whole archive. This detects
    corruption only (the manifest is unsigned, so it is no defense against
    an attacker who controls the archive). Destination paths
    resolve against the TARGET machine's home and SKCOMMS_HOME. Existing
    files with different content are conflicts: they are left untouched
    unless *force* is set (fail closed; a restore never silently clobbers a
    live identity).

    Run this BEFORE the daemon's first start on a rebuilt machine. See
    SOP.md section 11 for the full ordering.

    Args:
        archive: The ``.tar.gz`` produced by :func:`create_backup`.
        force: Overwrite existing files whose content differs.
        dry_run: Verify and report without writing anything.

    Returns:
        Dict with ``ok`` (no unresolved conflicts), ``restored``,
        ``skipped_same``, ``conflicts`` lists and the ``manifest``.

    Raises:
        TrustBackupError: Missing/invalid manifest, checksum mismatch,
            unsafe member path, or unsupported manifest version.
    """
    archive = Path(archive).expanduser()
    if not archive.is_file():
        raise TrustBackupError(f"backup archive not found: {archive}")

    with tarfile.open(archive, mode="r:gz") as tar:
        try:
            mf = tar.extractfile(MANIFEST_NAME)
        except KeyError:
            mf = None
        if mf is None:
            raise TrustBackupError(f"no {MANIFEST_NAME} in archive: not a skcomms identity backup")
        try:
            manifest = json.loads(mf.read().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TrustBackupError(f"corrupt manifest: {exc}") from exc
        if manifest.get("version") != MANIFEST_VERSION:
            raise TrustBackupError(
                f"unsupported backup manifest version: {manifest.get('version')!r}"
            )

        files = manifest.get("files") or {}
        if not files:
            raise TrustBackupError("backup manifest lists no files")

        # Phase 1: read + verify EVERYTHING before writing ANYTHING.
        staged: list[tuple[dict, Path, bytes]] = []
        for member, meta in sorted(files.items()):
            root = meta.get("root")
            if root not in (ROOT_HOME, ROOT_SKCOMMS):
                raise TrustBackupError(f"unknown backup root {root!r} for {member}")
            relpath = _safe_relpath(str(meta.get("relpath") or ""))
            try:
                fobj = tar.extractfile(member)
            except KeyError:
                fobj = None
            if fobj is None:
                raise TrustBackupError(f"archive missing payload member: {member}")
            data = fobj.read()
            if _sha256(data) != meta.get("sha256"):
                raise TrustBackupError(f"checksum mismatch for {member}: archive is corrupt")
            base = skcomms_home() if root == ROOT_SKCOMMS else Path.home()
            staged.append((meta, base / relpath, data))

    restored: list[str] = []
    skipped_same: list[str] = []
    conflicts: list[str] = []
    for meta, dest, data in staged:
        if dest.exists():
            try:
                current = dest.read_bytes()
            except OSError:
                current = None
            if current == data:
                skipped_same.append(str(dest))
                continue
            if not force:
                conflicts.append(str(dest))
                logger.warning(
                    "restore conflict (existing file differs, use force to overwrite): %s",
                    dest,
                )
                continue
        if not dry_run:
            _mkdir_private(dest.parent)
            mode = 0o600 if meta.get("secret") else 0o644
            tmp, fd = _open_private_tmp(dest, mode)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            tmp.replace(dest)
        restored.append(str(dest))

    ok = not conflicts
    logger.info(
        "identity restore from %s: %d restored, %d same, %d conflicts%s",
        archive,
        len(restored),
        len(skipped_same),
        len(conflicts),
        " (dry run)" if dry_run else "",
    )
    return {
        "ok": ok,
        "dry_run": dry_run,
        "restored": restored,
        "skipped_same": skipped_same,
        "conflicts": conflicts,
        "manifest": manifest,
    }


def require_identity_enabled(env: Optional[dict] = None) -> bool:
    """Whether the ``SKCOMMS_REQUIRE_IDENTITY`` hard gate is enabled."""
    source = env if env is not None else os.environ
    return str(source.get(REQUIRE_IDENTITY_ENV, "")).strip().lower() in _TRUTHY


def enforce_identity_gate(agent: Optional[str] = None) -> dict:
    """Startup gate: fail loudly when the CapAuth private key is absent.

    Called by the daemon/serve entrypoints before binding. When the key is
    missing this logs an ERROR (never a quiet INFO), and if
    ``SKCOMMS_REQUIRE_IDENTITY`` is truthy it raises so the process exits
    nonzero instead of coming up with a green /health and dead crypto.

    Returns:
        The :func:`identity_check` report (callers can surface it).

    Raises:
        IdentityMissingError: Key absent and the hard gate is enabled.
    """
    check = identity_check(agent)
    if not check["private_key_present"]:
        msg = (
            "CapAuth private key ABSENT: envelope signing and decryption are dead. "
            "Restore the identity backup BEFORE starting the daemon "
            "(skcomms identity restore <archive>); regenerating the key will "
            "TOFU-CONFLICT on every remote peer. See SOP.md section 11."
        )
        logger.error(msg)
        if require_identity_enabled():
            raise IdentityMissingError(msg)
    return check
