"""SKFed P7/A4 — sandboxed file tools for the sk-access plane.

These callables give an agent **read / write / patch / list / stat** access to
files **on this node**, but only within an explicit *exposed-root allowlist* and
never to anything matching the *secrets hard-deny* list. This is the security
boundary for the whole access plane, so path validation is deliberately
paranoid:

* Every path is **resolved + canonicalized** (``Path.resolve()`` follows
  symlinks and collapses ``..``) before any allowlist check. The check is done
  against the *resolved real path*, so ``..`` traversal, absolute paths outside
  the roots, and symlinks that point outside an allowed root are all rejected.
* The allowed roots themselves are resolved once at config time, so a symlinked
  root is compared by its real target.
* A **hard-deny** list refuses secrets (``~/.ssh``, ``*.key``, ``*.pem``,
  ``*.p12``, capauth identity dirs, ``cot-pki``, ``known_hosts``, ``.env`` …)
  *even when they sit under an allowed root*.

The module is **standalone**: importing ``mcp`` is optional and only needed for
:func:`register`. The plain callables (``file_read`` … ``list_roots``) work with
no MCP runtime, which is what the tests exercise.

Tool callables (all path-validated first):

* :func:`file_read` ``-> {content, size, sha, binary, encoding, path}``
* :func:`file_write` (scope=write)
* :func:`file_patch` — apply a unified diff (scope=write)
* :func:`file_list` ``-> [{name, type, size, mtime}]``
* :func:`file_stat`
* :func:`list_roots` ``-> [allowed roots]``

Every mutation (write/patch) is appended to an **audit log**. Reads are logged
at DEBUG level only.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger("skcomms.access.files")

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AccessError(Exception):
    """Base class for access-plane file errors."""


class PathDeniedError(AccessError):
    """Raised when a path fails the allowlist / hard-deny / canonicalization
    check. The security boundary speaks through this exception."""


class FileTooLargeError(AccessError):
    """Raised when a read/write would exceed the configured size cap."""


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Read/write payload size cap (bytes). Large files are refused rather than
# silently truncated — callers should range-fetch (P7 open question) instead.
DEFAULT_MAX_BYTES = 8 * 1024 * 1024  # 8 MiB

# Secrets that are HARD-DENIED even under an allowed root.
#
# Two kinds of rule:
#   * glob patterns matched against the basename AND the full path (so
#     ``*.pem`` catches any .pem anywhere, and ``*/.ssh/*`` catches the dir).
#   * directory names: if any path component equals one of these, deny.
DEFAULT_DENY_GLOBS: tuple[str, ...] = (
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.pgp",
    "*.asc",  # PGP armored keys/signatures
    "*.gpg",
    "*.jks",
    "*.keystore",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "*.ppk",
    "known_hosts",
    "authorized_keys",
    ".env",
    ".env.*",
    "*.env",
    "secring.*",
    "*.private",
)

# Any path component (directory or file name) equal to one of these is denied.
DEFAULT_DENY_COMPONENTS: tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    ".pki",
    "cot-pki",
    "pki",
    "secrets",
    ".secrets",
    "private-keys",
    "private_keys",
    "capauth",  # capauth identity dirs (keys live here)
    ".capauth",
    "identity",  # capauth/identity key dirs
    "keys",
    ".aws",
    ".gcloud",
    ".kube",
)

# Substrings that, if present anywhere in the lowercased resolved path, deny.
# Cheap belt-and-suspenders against odd nestings of the dirs above.
DEFAULT_DENY_SUBSTRINGS: tuple[str, ...] = (
    "/.ssh/",
    "/cot-pki/",
    "/.gnupg/",
)


def _default_roots() -> list[str]:
    """Sensible default exposed roots: ``~/clawd`` and the running agent's
    skcapstone home. Resolved later by :class:`FileAccess`."""
    home = Path.home()
    agent = (
        os.environ.get("SKAGENT")
        or os.environ.get("SKCAPSTONE_AGENT")
        or os.environ.get("SKMEMORY_AGENT")
        or "lumina"
    ).strip()
    roots = [str(home / "clawd")]
    agent_home = home / ".skcapstone" / "agents" / agent
    roots.append(str(agent_home))
    return roots


def _default_audit_log() -> str:
    return str(Path.home() / ".skcapstone" / "skcomms" / "logs" / "access-files-audit.log")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class FileAccessConfig:
    """Configuration for :class:`FileAccess`.

    Attributes:
        roots: Exposed-root allowlist. Files are only reachable under one of
            these (after symlink resolution).
        max_bytes: Size cap for read/write payloads.
        deny_globs: Glob patterns denied (matched on basename and full path).
        deny_components: Path components (dir/file names) that are denied.
        deny_substrings: Lowercased substrings denied anywhere in the path.
        audit_log: Path to the append-only audit log.
        identity: Identity string recorded in audit entries (defaults to
            ``SKAGENT``).
    """

    roots: list[str] = field(default_factory=_default_roots)
    max_bytes: int = DEFAULT_MAX_BYTES
    deny_globs: tuple[str, ...] = DEFAULT_DENY_GLOBS
    deny_components: tuple[str, ...] = DEFAULT_DENY_COMPONENTS
    deny_substrings: tuple[str, ...] = DEFAULT_DENY_SUBSTRINGS
    audit_log: str = field(default_factory=_default_audit_log)
    identity: Optional[str] = None


# ---------------------------------------------------------------------------
# The access engine
# ---------------------------------------------------------------------------


class FileAccess:
    """Sandboxed file operations bound to an exposed-root allowlist.

    All public ``file_*`` methods validate the path first via
    :meth:`_resolve_checked`, which is the single security choke point.
    """

    def __init__(self, config: Optional[FileAccessConfig] = None):
        self.config = config or FileAccessConfig()
        # Resolve + canonicalize each root ONCE. We use strict=False because a
        # root may not exist yet, but we still want symlinks/.. collapsed.
        self._roots: list[Path] = []
        for r in self.config.roots:
            p = Path(r).expanduser()
            try:
                rp = p.resolve(strict=False)
            except (OSError, RuntimeError):  # pragma: no cover - exotic FS
                continue
            self._roots.append(rp)
        if not self._roots:
            logger.warning("FileAccess started with NO exposed roots; all paths denied")
        self._identity = self.config.identity or (
            os.environ.get("SKAGENT")
            or os.environ.get("SKCAPSTONE_AGENT")
            or os.environ.get("SKMEMORY_AGENT")
            or "unknown"
        )

    # -- security boundary --------------------------------------------------

    @property
    def roots(self) -> list[Path]:
        return list(self._roots)

    def _under_root(self, resolved: Path) -> bool:
        """True iff ``resolved`` is one of the roots or strictly inside one.

        ``resolved`` MUST already be canonicalized (symlinks + ``..`` removed).
        """
        for root in self._roots:
            if resolved == root:
                return True
            # is_relative_to (py3.9+) compares purely lexically, which is safe
            # because both paths are already real/canonical.
            try:
                if resolved.is_relative_to(root):
                    return True
            except AttributeError:  # pragma: no cover - py<3.9
                try:
                    resolved.relative_to(root)
                    return True
                except ValueError:
                    pass
        return False

    def _denied_secret(self, resolved: Path, raw: Path) -> Optional[str]:
        """Return a reason string if the path hits the secrets hard-deny list,
        else None. Checks BOTH the resolved real path and the raw requested
        path so a symlink *named* innocently but pointing at a secret — or a
        secret reached through a symlinked dir — is still caught."""
        candidates = {resolved, raw}
        for cand in candidates:
            low = str(cand).lower()
            parts = [p.lower() for p in cand.parts]
            name = cand.name.lower()

            # Substring rules.
            for sub in self.config.deny_substrings:
                if sub in low:
                    return f"matches denied substring {sub!r}"

            # Component rules (any directory/file name in the path).
            for comp in self.config.deny_components:
                if comp.lower() in parts:
                    return f"path component {comp!r} is a secrets dir"

            # Glob rules — match against basename and the full path.
            for pat in self.config.deny_globs:
                pl = pat.lower()
                if fnmatch.fnmatch(name, pl) or fnmatch.fnmatch(low, pl) or fnmatch.fnmatch(
                    low, "*/" + pl
                ):
                    return f"matches secrets pattern {pat!r}"
        return None

    def _resolve_checked(self, path: str, *, must_exist: bool = False) -> Path:
        """Resolve ``path`` to a real canonical Path and enforce the boundary.

        Order of checks (fail closed):
          1. Reject empty / null-byte paths.
          2. Expand ``~`` and canonicalize (``resolve`` follows symlinks + ``..``).
             For a path that doesn't exist yet (write target), we resolve its
             parent and re-attach the final component, so a write can't be
             tricked by a non-existent intermediate.
          3. Reject if not under any exposed root (post-resolution).
          4. Reject if it hits the secrets hard-deny list.

        Returns the resolved :class:`Path`. Raises :class:`PathDeniedError`.
        """
        if not path or "\x00" in path:
            raise PathDeniedError("empty or null-byte path")

        raw = Path(path).expanduser()

        # Canonicalize. For existing paths resolve() handles everything; for
        # not-yet-existing targets we resolve the deepest existing ancestor and
        # rebuild, so symlinked parents are still followed and validated.
        try:
            resolved = raw.resolve(strict=must_exist)
        except FileNotFoundError as exc:
            raise PathDeniedError(f"path does not exist: {path}") from exc
        except (OSError, RuntimeError) as exc:  # symlink loop, etc.
            raise PathDeniedError(f"cannot resolve path: {exc}") from exc

        if not resolved.is_absolute():  # defensive; resolve() returns absolute
            raise PathDeniedError("path did not resolve to an absolute path")

        # Allowlist check on the REAL resolved path.
        if not self._under_root(resolved):
            raise PathDeniedError(
                f"path escapes exposed roots: {resolved} not under {self._roots}"
            )

        # Hard-deny secrets (checked on both raw + resolved).
        reason = self._denied_secret(resolved, raw)
        if reason is not None:
            raise PathDeniedError(f"secrets hard-deny: {reason} ({resolved})")

        return resolved

    # -- audit --------------------------------------------------------------

    def _audit(self, action: str, path: Path, *, extra: Optional[dict] = None) -> None:
        """Append a JSON line to the audit log for a mutation."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "identity": self._identity,
            "action": action,
            "path": str(path),
        }
        if extra:
            entry.update(extra)
        try:
            log_path = Path(self.config.audit_log).expanduser()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            # Never let an audit-log failure block or mask the operation, but
            # do shout about it — a missing audit trail is a security event.
            logger.exception("FAILED to write audit log entry: %s", entry)

    # -- tools --------------------------------------------------------------

    def file_read(self, path: str) -> dict[str, Any]:
        """Read a file under an exposed root.

        Returns a dict with ``content`` (text, or base64 for binary), ``size``,
        ``sha`` (sha256 of the raw bytes), ``binary`` flag, ``encoding``
        (``"utf-8"`` or ``"base64"``), and the resolved ``path``.

        Raises :class:`PathDeniedError` for boundary violations and
        :class:`FileTooLargeError` if the file exceeds the size cap.
        """
        resolved = self._resolve_checked(path, must_exist=True)
        if not resolved.is_file():
            raise AccessError(f"not a regular file: {resolved}")
        size = resolved.stat().st_size
        if size > self.config.max_bytes:
            raise FileTooLargeError(
                f"file is {size} bytes, exceeds cap {self.config.max_bytes}"
            )
        raw = resolved.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        try:
            text = raw.decode("utf-8")
            binary = False
            content = text
            encoding = "utf-8"
        except UnicodeDecodeError:
            binary = True
            content = base64.b64encode(raw).decode("ascii")
            encoding = "base64"
        logger.debug("file_read %s (%d bytes, binary=%s)", resolved, size, binary)
        return {
            "path": str(resolved),
            "content": content,
            "size": size,
            "sha": sha,
            "binary": binary,
            "encoding": encoding,
        }

    def file_write(self, path: str, content: str, *, encoding: str = "utf-8") -> dict[str, Any]:
        """Create or overwrite a file within an exposed root (scope=write).

        ``encoding`` may be ``"utf-8"`` (default; ``content`` is text) or
        ``"base64"`` (``content`` is base64 of the raw bytes — for binary
        writes). The parent dir is created if missing (still inside a root).
        """
        resolved = self._resolve_checked(path, must_exist=False)

        if encoding == "base64":
            data = base64.b64decode(content)
        else:
            data = content.encode("utf-8")

        if len(data) > self.config.max_bytes:
            raise FileTooLargeError(
                f"write of {len(data)} bytes exceeds cap {self.config.max_bytes}"
            )

        # The parent dir must itself be inside a root (re-validate to defend
        # against a parent that is, e.g., a symlink created between checks).
        parent = resolved.parent
        if not self._under_root(parent):
            raise PathDeniedError(f"parent escapes exposed roots: {parent}")
        parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        self._audit("write", resolved, extra={"size": len(data), "sha": sha})
        return {"path": str(resolved), "size": len(data), "sha": sha, "written": True}

    def file_patch(self, path: str, unified_diff: str) -> dict[str, Any]:
        """Apply a unified diff to a file (scope=write).

        The diff is applied to the file's current contents; the result is
        written back atomically-ish (single write_bytes). Raises
        :class:`AccessError` if the diff doesn't apply cleanly.
        """
        resolved = self._resolve_checked(path, must_exist=True)
        if not resolved.is_file():
            raise AccessError(f"not a regular file: {resolved}")
        original = resolved.read_text("utf-8")
        patched = _apply_unified_diff(original, unified_diff)
        data = patched.encode("utf-8")
        if len(data) > self.config.max_bytes:
            raise FileTooLargeError(
                f"patched file of {len(data)} bytes exceeds cap {self.config.max_bytes}"
            )
        resolved.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        self._audit("patch", resolved, extra={"size": len(data), "sha": sha})
        return {"path": str(resolved), "size": len(data), "sha": sha, "patched": True}

    def file_list(self, dir: str) -> list[dict[str, Any]]:
        """List the immediate children of a directory under an exposed root.

        Returns ``[{name, type, size, mtime}]`` where ``type`` is ``"file"``,
        ``"dir"``, ``"symlink"``, or ``"other"``. Entries that would resolve
        outside the roots or hit the deny list are silently omitted (the
        directory listing must not become a side channel for denied paths).
        """
        resolved = self._resolve_checked(dir, must_exist=True)
        if not resolved.is_dir():
            raise AccessError(f"not a directory: {resolved}")
        out: list[dict[str, Any]] = []
        for entry in sorted(resolved.iterdir()):
            # Skip anything that fails the boundary (e.g. a symlink pointing
            # out, or a denied secret) so listing never reveals denied paths.
            try:
                self._resolve_checked(str(entry), must_exist=False)
            except (PathDeniedError, AccessError):
                continue
            try:
                st = entry.lstat()
            except OSError:
                continue
            if entry.is_symlink():
                typ = "symlink"
            elif entry.is_dir():
                typ = "dir"
            elif entry.is_file():
                typ = "file"
            else:
                typ = "other"
            out.append(
                {
                    "name": entry.name,
                    "type": typ,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                }
            )
        return out

    def file_stat(self, path: str) -> dict[str, Any]:
        """Stat a file/dir under an exposed root."""
        resolved = self._resolve_checked(path, must_exist=True)
        st = resolved.stat()
        if resolved.is_dir():
            typ = "dir"
        elif resolved.is_file():
            typ = "file"
        else:
            typ = "other"
        return {
            "path": str(resolved),
            "type": typ,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "ctime": st.st_ctime,
            "mode": oct(st.st_mode & 0o7777),
            "is_symlink": Path(path).expanduser().is_symlink(),
        }

    def list_roots(self) -> list[str]:
        """Return the exposed-root allowlist (resolved real paths)."""
        return [str(r) for r in self._roots]


# ---------------------------------------------------------------------------
# Unified-diff applier (no external deps)
# ---------------------------------------------------------------------------


def _apply_unified_diff(original: str, diff_text: str) -> str:
    """Apply a unified diff to ``original`` and return the patched text.

    Supports standard unified diff hunks (``@@ -l,s +l,s @@`` with ``' '``,
    ``'-'``, ``'+'`` lines). Validates context/removed lines against the
    source; raises :class:`AccessError` on mismatch so a bad diff never
    silently corrupts a file.
    """
    src_lines = original.splitlines(keepends=True)
    # Normalize: work on lines without keepends, track trailing newline.
    src = original.split("\n")
    # split("\n") on "a\nb\n" -> ["a","b",""]; the final "" represents the
    # trailing newline. We patch this list and rejoin with "\n".

    diff_lines = diff_text.split("\n")
    out: list[str] = []
    si = 0  # index into src
    i = 0
    n = len(diff_lines)
    applied_any = False

    while i < n:
        line = diff_lines[i]
        if line.startswith("--- ") or line.startswith("+++ "):
            i += 1
            continue
        if line.startswith("@@"):
            # Parse "@@ -start,count +start,count @@"
            try:
                header = line.split("@@")[1].strip()
                old_part = header.split(" ")[0]  # -start,count
                old_start = int(old_part[1:].split(",")[0])
            except (IndexError, ValueError) as exc:
                raise AccessError(f"malformed hunk header: {line!r}") from exc
            # Convert 1-based to 0-based; copy unchanged src up to the hunk.
            target = old_start - 1 if old_start > 0 else 0
            if target < si:
                raise AccessError("overlapping or out-of-order hunks")
            out.extend(src[si:target])
            si = target
            i += 1
            # Consume hunk body.
            while i < n:
                hl = diff_lines[i]
                if hl.startswith("@@") or hl.startswith("--- ") or hl.startswith("+++ "):
                    break
                if hl == "\\ No newline at end of file":
                    i += 1
                    continue
                if hl == "" and i == n - 1:
                    # trailing empty from split — end of diff
                    i += 1
                    continue
                tag = hl[:1]
                payload = hl[1:]
                if tag == " ":
                    if si >= len(src) or src[si] != payload:
                        raise AccessError(
                            f"context mismatch at src line {si + 1}: "
                            f"expected {payload!r}, got "
                            f"{src[si] if si < len(src) else '<EOF>'!r}"
                        )
                    out.append(src[si])
                    si += 1
                elif tag == "-":
                    if si >= len(src) or src[si] != payload:
                        raise AccessError(
                            f"removal mismatch at src line {si + 1}: "
                            f"expected {payload!r}, got "
                            f"{src[si] if si < len(src) else '<EOF>'!r}"
                        )
                    si += 1
                elif tag == "+":
                    out.append(payload)
                    applied_any = True
                else:
                    raise AccessError(f"unexpected diff line: {hl!r}")
                i += 1
            applied_any = True
            continue
        # Anything else outside a hunk (e.g. "diff --git", "index ...") -> skip.
        i += 1

    if not applied_any:
        raise AccessError("no hunks found in diff")

    out.extend(src[si:])
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Module-level convenience callables (default singleton)
# ---------------------------------------------------------------------------

_default_access: Optional[FileAccess] = None


def get_default_access() -> FileAccess:
    """Return (lazily creating) the process-wide default :class:`FileAccess`."""
    global _default_access
    if _default_access is None:
        _default_access = FileAccess()
    return _default_access


def set_default_access(access: FileAccess) -> None:
    """Override the process-wide default (used by the MCP server / tests)."""
    global _default_access
    _default_access = access


def file_read(path: str) -> dict[str, Any]:
    """Module-level :meth:`FileAccess.file_read` against the default access."""
    return get_default_access().file_read(path)


def file_write(path: str, content: str, *, encoding: str = "utf-8") -> dict[str, Any]:
    """Module-level :meth:`FileAccess.file_write` (scope=write)."""
    return get_default_access().file_write(path, content, encoding=encoding)


def file_patch(path: str, unified_diff: str) -> dict[str, Any]:
    """Module-level :meth:`FileAccess.file_patch` (scope=write)."""
    return get_default_access().file_patch(path, unified_diff)


def file_list(dir: str) -> list[dict[str, Any]]:
    """Module-level :meth:`FileAccess.file_list`."""
    return get_default_access().file_list(dir)


def file_stat(path: str) -> dict[str, Any]:
    """Module-level :meth:`FileAccess.file_stat`."""
    return get_default_access().file_stat(path)


def list_roots() -> list[str]:
    """Module-level :meth:`FileAccess.list_roots`."""
    return get_default_access().list_roots()


# ---------------------------------------------------------------------------
# MCP registration helper (import-guarded so the module works standalone)
# ---------------------------------------------------------------------------

# Tool metadata: (name, scope, summary, input schema). Consumed by register().
TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "file_read",
        "scope": "read",
        "description": (
            "Read a file on this node, scoped to the exposed-root allowlist. "
            "Returns content (text, or base64 for binary), size, sha256, and a "
            "binary flag. Refuses paths outside the roots or matching secrets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute path under an exposed root"}},
            "required": ["path"],
        },
    },
    {
        "name": "file_write",
        "scope": "write",
        "description": (
            "Create or overwrite a file within an exposed root (write scope). "
            "encoding may be 'utf-8' (text) or 'base64' (binary). Audited."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "encoding": {"type": "string", "enum": ["utf-8", "base64"], "default": "utf-8"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "file_patch",
        "scope": "write",
        "description": (
            "Apply a unified diff to a file within an exposed root (write scope). "
            "Validates context lines; fails if the diff does not apply. Audited."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "unified_diff": {"type": "string", "description": "A unified diff to apply"},
            },
            "required": ["path", "unified_diff"],
        },
    },
    {
        "name": "file_list",
        "scope": "read",
        "description": "List immediate children of a directory under an exposed root: [{name,type,size,mtime}].",
        "inputSchema": {
            "type": "object",
            "properties": {"dir": {"type": "string"}},
            "required": ["dir"],
        },
    },
    {
        "name": "file_stat",
        "scope": "read",
        "description": "Stat a file/dir under an exposed root: type, size, mtime, mode.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "list_roots",
        "scope": "read",
        "description": "List the exposed-root allowlist (resolved real paths) for this node.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
]


def callable_for(name: str, access: Optional[FileAccess] = None) -> Callable[..., Any]:
    """Return the bound callable for a tool name, against ``access`` (or the
    default singleton). Used by :func:`register` and by direct callers."""
    acc = access or get_default_access()
    mapping: dict[str, Callable[..., Any]] = {
        "file_read": acc.file_read,
        "file_write": acc.file_write,
        "file_patch": acc.file_patch,
        "file_list": acc.file_list,
        "file_stat": acc.file_stat,
        "list_roots": acc.list_roots,
    }
    if name not in mapping:
        raise KeyError(name)
    return mapping[name]


def register(server: Any, access: Optional[FileAccess] = None) -> list[str]:
    """Attach the file tools to an MCP ``server`` with correct scopes.

    This helper is intentionally **tolerant** of the host server's API so the
    A2 MCP skeleton can register us however it likes, in priority order:

    1. ``server.register_access_tool(name, fn, scope=..., description=..., input_schema=...)``
       — preferred custom hook the A2 skeleton can expose.
    2. ``server.add_tool(...)`` / ``server.tool(...)`` — generic adapters.
    3. Fallback: stash specs + callables on ``server._access_file_tools`` so the
       host can wire them itself.

    The import of ``mcp`` is **not** required here — we never import it — which
    keeps this module usable standalone. Returns the list of registered tool
    names.

    Args:
        server: The MCP server / registrar object from A2.
        access: Optional :class:`FileAccess`; defaults to the singleton.

    Returns:
        list[str]: Names of the tools that were registered.
    """
    acc = access or get_default_access()
    registered: list[str] = []

    for spec in TOOL_SPECS:
        name = spec["name"]
        fn = callable_for(name, acc)
        scope = spec["scope"]
        desc = spec["description"]
        schema = spec["inputSchema"]

        if hasattr(server, "register_access_tool"):
            server.register_access_tool(
                name, fn, scope=scope, description=desc, input_schema=schema
            )
            registered.append(name)
            continue

        if hasattr(server, "add_tool"):
            try:
                server.add_tool(
                    name=name, fn=fn, scope=scope, description=desc, input_schema=schema
                )
                registered.append(name)
                continue
            except TypeError:
                # Host has a different add_tool signature; fall through.
                pass

        # Generic fallback: stash for the host to wire.
        bucket = getattr(server, "_access_file_tools", None)
        if bucket is None:
            bucket = []
            try:
                setattr(server, "_access_file_tools", bucket)
            except (AttributeError, TypeError):  # pragma: no cover
                logger.warning("register(): cannot attach tools to server %r", server)
                break
        bucket.append({"name": name, "fn": fn, "scope": scope, "description": desc, "input_schema": schema})
        registered.append(name)

    logger.info("access.files.register attached %d tools: %s", len(registered), registered)
    return registered
