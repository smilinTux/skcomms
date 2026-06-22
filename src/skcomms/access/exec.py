"""SKFed P7/A7 — sandboxed exec tools for the sk-access plane (aligns skreach F2).

EXEC IS DANGEROUS. These tools let an agent **run a command on this node**, so
the whole module is built fail-closed:

* **Never granted by default.** The exec tools register with ``scope='exec'``;
  the access server denies any tool whose required scope the caller's identity
  has not been *explicitly* granted. The default grant is ``{READ}`` (see
  :meth:`AccessConfig.granted_scopes`), so exec is off until an operator opts an
  identity in.
* **cwd is confined to the exposed-root allowlist.** The working directory is
  validated with the *same* paranoid path resolver as the A4 file tools
  (:class:`skcomms.access.files.FileAccess`): ``..`` traversal, absolute paths
  outside the roots, and symlinks pointing out are all rejected, and secrets
  dirs are hard-denied. A command cannot ``cwd`` its way out of ``~/clawd``.
* **No shell by default.** Commands run as an argv list with ``shell=False``,
  so there is no shell to inject metacharacters into. A shell string is only
  honoured behind an explicit ``shell=True`` flag *and* only if the operator
  enabled ``allow_shell`` in config — and even then the denylist still applies.
* **Command allow/deny list.** A denylist refuses obviously-dangerous commands
  (``rm -rf /``, ``sudo``, ``reboot``, fork bombs, shell metacharacters in
  argv …) by default; an optional allowlist can restrict execs to a named set
  of binaries.
* **Output size cap + timeout.** stdout/stderr are captured with a byte cap
  (truncated, flagged) and the process is killed (process-group SIGKILL) if it
  outruns the timeout.
* **Every exec is audit-logged** (cmd, cwd, identity, exit, ts) to an
  append-only JSONL log.

The module is **standalone**: importing ``mcp`` is never required. The plain
callables (:func:`run`, :func:`status`) work with no MCP runtime, which is what
the tests exercise. :func:`register` / :func:`register_builtin_exec_tools` wire
the tools into the A2 registry with ``scope='exec'``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

from .files import FileAccess, FileAccessConfig, PathDeniedError, get_default_access

logger = logging.getLogger("skcomms.access.exec")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ExecError(Exception):
    """Base class for access-plane exec errors."""


class CommandDeniedError(ExecError):
    """Raised when a command fails the allow/deny policy. The exec security
    boundary speaks through this exception."""


class ExecTimeoutError(ExecError):
    """Raised internally on timeout; surfaced as a result dict, not propagated
    to callers (timeout is an expected, reportable outcome)."""


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Hard timeout default (seconds) — overridable per call, but capped.
DEFAULT_TIMEOUT = 60
#: Ceiling on any per-call timeout, so a caller can't pin a worker forever.
MAX_TIMEOUT = 600
#: Per-stream (stdout / stderr) capture cap, bytes. Output beyond this is
#: dropped and ``truncated`` is set.
DEFAULT_MAX_OUTPUT = 1 * 1024 * 1024  # 1 MiB

#: Argv[0] basenames denied outright (privilege escalation / destructive /
#: persistence). Matched on the *basename* of argv[0] (case-insensitive).
DEFAULT_DENY_BINARIES: tuple[str, ...] = (
    "sudo",
    "su",
    "doas",
    "pkexec",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "init",
    "systemctl",  # service control = persistence/escalation surface
    "mkfs",
    "fdisk",
    "parted",
    "dd",
    "shred",
    "chown",
    "chmod",  # broad perms changes
    "passwd",
    "useradd",
    "userdel",
    "visudo",
    "crontab",  # persistence
    "iptables",
    "nft",
    "tailscale",  # don't let an exec reconfigure the tailnet itself
)

#: Substring patterns (regex, matched against the full reconstructed command
#: string) that are denied even inside an otherwise-allowed binary. Catches
#: ``rm -rf /`` and fork bombs regardless of argv shape.
DEFAULT_DENY_PATTERNS: tuple[str, ...] = (
    r"rm\s+(-[a-zA-Z]*\s+)*(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+/(\s|$)",
    r"rm\s+(-[a-zA-Z]*\s+)*-rf?\s+/\*",
    r":\(\)\s*\{.*\};:",  # classic fork bomb  :(){ :|:& };:
    r">\s*/dev/sd[a-z]",  # writing to a raw disk
    r"mkfs",
    r"/etc/(passwd|shadow|sudoers)",
)

#: Standalone shell-operator tokens. When a command is supplied as a *string*
#: (which a caller might assume is shell-interpreted), shlex-splitting it and
#: finding one of these as its own token means the caller intended shell
#: chaining/redirection — refused on the no-shell path so it can't silently run
#: only the first segment (or, worse, be mishandled). Explicit argv lists are
#: trusted verbatim (no shell ever sees them, so metachars are inert).
SHELL_OPERATOR_TOKENS = frozenset(
    {"|", "||", "&", "&&", ";", ";;", ">", ">>", "<", "<<", "<<<", "`", "$(", "&|"}
)


def _default_audit_log() -> str:
    return str(Path.home() / ".skcapstone" / "skcomms" / "logs" / "access-exec-audit.log")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class ExecAccessConfig:
    """Configuration for :class:`ExecAccess`.

    Attributes:
        file_access: The :class:`FileAccess` whose exposed-root allowlist
            confines ``cwd``. Defaults to the process-wide singleton, so exec
            shares the *exact same* boundary as the file tools.
        default_timeout: Default per-call timeout (seconds).
        max_timeout: Ceiling on any requested timeout.
        max_output: Per-stream output cap (bytes).
        deny_binaries: argv[0] basenames denied outright.
        deny_patterns: Regex patterns denied against the full command string.
        allow_binaries: If non-empty, ONLY these argv[0] basenames are allowed
            (an explicit allowlist; empty = allow anything not denied).
        allow_shell: If False (default), ``shell=True`` calls are refused.
        audit_log: Path to the append-only exec audit log.
        identity: Identity recorded in audit entries (defaults to ``SKAGENT``).
    """

    file_access: Optional[FileAccess] = None
    default_timeout: int = DEFAULT_TIMEOUT
    max_timeout: int = MAX_TIMEOUT
    max_output: int = DEFAULT_MAX_OUTPUT
    deny_binaries: tuple[str, ...] = DEFAULT_DENY_BINARIES
    deny_patterns: tuple[str, ...] = DEFAULT_DENY_PATTERNS
    allow_binaries: tuple[str, ...] = ()
    allow_shell: bool = False
    audit_log: str = field(default_factory=_default_audit_log)
    identity: Optional[str] = None


# ---------------------------------------------------------------------------
# The exec engine
# ---------------------------------------------------------------------------


class ExecAccess:
    """Sandboxed command execution confined to the exposed-root allowlist.

    Every :meth:`run` validates the cwd through the file-access boundary, vets
    the command against the allow/deny policy, runs it without a shell (unless
    explicitly gated), caps output, enforces a timeout, and audit-logs the
    result.
    """

    def __init__(self, config: Optional[ExecAccessConfig] = None):
        self.config = config or ExecAccessConfig()
        self._fa: FileAccess = self.config.file_access or get_default_access()
        self._deny_re = [re.compile(p, re.IGNORECASE) for p in self.config.deny_patterns]
        self._identity = self.config.identity or (
            os.environ.get("SKAGENT")
            or os.environ.get("SKCAPSTONE_AGENT")
            or os.environ.get("SKMEMORY_AGENT")
            or "unknown"
        )

    # -- security boundary --------------------------------------------------

    def _resolve_cwd(self, cwd: Optional[str]) -> Path:
        """Resolve + confine the working directory to the exposed roots.

        ``None`` cwd defaults to the first exposed root. Any explicit cwd is run
        through :meth:`FileAccess._resolve_checked` (the same paranoid resolver
        the file tools use), so ``..`` escapes, absolute out-of-root paths,
        symlinks pointing out, and secrets dirs are all rejected. The resolved
        path must be an existing directory.

        Raises:
            PathDeniedError: If the cwd escapes the allowlist / hits hard-deny.
            ExecError: If there is no exposed root, or the cwd is not a dir.
        """
        roots = self._fa.roots
        if not roots:
            raise ExecError("no exposed roots configured; refusing to exec")
        if cwd is None:
            return roots[0]
        # Reuse the file-tool resolver: this is the single security choke point
        # shared with A4 — cwd cannot escape ~/clawd any more than a file path can.
        resolved = self._fa._resolve_checked(cwd, must_exist=True)
        if not resolved.is_dir():
            raise ExecError(f"cwd is not a directory: {resolved}")
        return resolved

    def _normalize_argv(self, cmd: Union[str, Sequence[str]], shell: bool) -> tuple[list[str], str, bool]:
        """Return ``(argv, display, use_shell)`` for a command.

        For the argv path (default), ``cmd`` may be a list or a string; a string
        is split with :func:`shlex.split` (NOT a shell) and each token is checked
        for shell metacharacters (their presence is an injection signal and is
        refused). For the gated shell path, ``cmd`` is kept as a single string.
        """
        if shell:
            if not self.config.allow_shell:
                raise CommandDeniedError(
                    "shell=True refused: allow_shell is disabled (argv-only by default)"
                )
            if isinstance(cmd, (list, tuple)):
                # A shell call expects one string; join defensively.
                display = " ".join(str(c) for c in cmd)
            else:
                display = str(cmd)
            return [display], display, True

        # argv path — no shell. An explicit list is trusted verbatim (no shell
        # ever interprets it). A string is shlex-split; if that yields a bare
        # shell-operator token the caller meant shell semantics, which the
        # no-shell path must refuse rather than silently mis-run.
        if isinstance(cmd, (list, tuple)):
            argv = [str(c) for c in cmd]
        elif isinstance(cmd, str):
            try:
                argv = shlex.split(cmd)
            except ValueError as exc:
                raise CommandDeniedError(f"cannot parse command: {exc}") from exc
            for tok in argv:
                if tok in SHELL_OPERATOR_TOKENS:
                    raise CommandDeniedError(
                        f"shell operator {tok!r} in a command string; pass a clean "
                        "argv list, or enable shell=True (gated) for shell semantics"
                    )
        else:
            raise CommandDeniedError(f"unsupported command type: {type(cmd).__name__}")

        if not argv:
            raise CommandDeniedError("empty command")
        return argv, " ".join(argv), False

    def _vet_command(self, argv: list[str], display: str) -> None:
        """Apply the allow/deny policy. Raises :class:`CommandDeniedError`.

        Checks (fail closed):
          1. denylist regex patterns against the full command string.
          2. argv[0] basename against the deny-binaries set.
          3. if an allowlist is configured, argv[0] basename must be in it.
        """
        for rx in self._deny_re:
            if rx.search(display):
                raise CommandDeniedError(
                    f"command matches denied pattern {rx.pattern!r}"
                )

        binary = os.path.basename(argv[0]).lower()
        if binary in {b.lower() for b in self.config.deny_binaries}:
            raise CommandDeniedError(f"binary {binary!r} is denylisted")

        if self.config.allow_binaries:
            allowed = {b.lower() for b in self.config.allow_binaries}
            if binary not in allowed:
                raise CommandDeniedError(
                    f"binary {binary!r} not in allowlist {sorted(allowed)}"
                )

    # -- audit --------------------------------------------------------------

    def _audit(self, entry: dict) -> None:
        """Append a JSON line to the exec audit log."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "identity": self._identity,
            **entry,
        }
        try:
            log_path = Path(self.config.audit_log).expanduser()
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:
            # An exec without an audit trail is a security event — shout, but
            # never let logging failure mask the operation's result.
            logger.exception("FAILED to write exec audit entry: %s", record)

    # -- run ----------------------------------------------------------------

    def run(
        self,
        cmd: Union[str, Sequence[str]],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        *,
        shell: bool = False,
        env: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Run a command on this node, confined + vetted + capped + audited.

        Args:
            cmd: An argv list (preferred) or a string. A string on the default
                (no-shell) path is ``shlex.split`` — NOT shell-interpreted.
            cwd: Working directory; confined to the exposed-root allowlist.
                ``None`` -> the first exposed root.
            timeout: Per-call timeout (seconds); clamped to ``max_timeout``.
            shell: Run via a shell. Refused unless ``allow_shell`` is enabled
                in config (dangerous; gated).
            env: Extra environment variables overlaid on the current env.

        Returns:
            ``{exit_code, stdout, stderr, truncated, timed_out, cwd, cmd,
            duration_ms}``. ``exit_code`` is ``-1`` on timeout/spawn failure.

        Raises:
            PathDeniedError: cwd escapes the allowlist.
            CommandDeniedError: command fails the allow/deny policy.
        """
        resolved_cwd = self._resolve_cwd(cwd)
        argv, display, use_shell = self._normalize_argv(cmd, shell)
        self._vet_command(argv, display)

        eff_timeout = self.config.default_timeout if timeout is None else int(timeout)
        eff_timeout = max(1, min(eff_timeout, self.config.max_timeout))

        run_env = dict(os.environ)
        if env:
            run_env.update({str(k): str(v) for k, v in env.items()})

        popen_args: Union[str, list[str]] = display if use_shell else argv

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.Popen(
                popen_args,
                cwd=str(resolved_cwd),
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=run_env,
                # New session/process-group so a timeout kill takes the whole
                # tree (children of the spawned process) with it.
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._audit(
                {
                    "action": "exec",
                    "cmd": display,
                    "cwd": str(resolved_cwd),
                    "exit_code": -1,
                    "error": f"spawn failed: {exc}",
                }
            )
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"failed to start command: {exc}",
                "truncated": False,
                "timed_out": False,
                "cwd": str(resolved_cwd),
                "cmd": display,
                "duration_ms": duration_ms,
            }

        try:
            out_b, err_b = proc.communicate(timeout=eff_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_tree(proc)
            try:
                out_b, err_b = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - very stubborn
                out_b, err_b = b"", b""

        duration_ms = int((time.monotonic() - start) * 1000)
        cap = self.config.max_output
        truncated = len(out_b) > cap or len(err_b) > cap
        stdout = out_b[:cap].decode("utf-8", "replace")
        stderr = err_b[:cap].decode("utf-8", "replace")
        exit_code = -1 if timed_out else (proc.returncode if proc.returncode is not None else -1)

        self._audit(
            {
                "action": "exec",
                "cmd": display,
                "cwd": str(resolved_cwd),
                "exit_code": exit_code,
                "timed_out": timed_out,
                "truncated": truncated,
                "shell": use_shell,
                "duration_ms": duration_ms,
            }
        )

        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
            "timed_out": timed_out,
            "cwd": str(resolved_cwd),
            "cmd": display,
            "duration_ms": duration_ms,
        }

    @staticmethod
    def _kill_tree(proc: "subprocess.Popen") -> None:
        """SIGKILL the process group spawned by ``proc`` (best effort)."""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:  # pragma: no cover
                pass

    # -- status -------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Return node load / uptime / basic health for the exec plane.

        No command is run; this is the lightweight liveness probe.
        """
        info: dict[str, Any] = {
            "node": os.environ.get("SKAGENT") or self._identity,
            "pid": os.getpid(),
            "cpu_count": os.cpu_count(),
            "exposed_roots": [str(r) for r in self._fa.roots],
            "allow_shell": self.config.allow_shell,
            "allow_binaries": list(self.config.allow_binaries),
            "default_timeout": self.config.default_timeout,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        try:
            info["loadavg"] = list(os.getloadavg())
        except (OSError, AttributeError):  # pragma: no cover - platform dependent
            info["loadavg"] = None
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as fh:
                info["uptime_s"] = float(fh.read().split()[0])
        except (OSError, ValueError, IndexError):
            info["uptime_s"] = None
        return info


# ---------------------------------------------------------------------------
# Module-level convenience callables (default singleton)
# ---------------------------------------------------------------------------

_default_exec: Optional[ExecAccess] = None


def get_default_exec() -> ExecAccess:
    """Return (lazily creating) the process-wide default :class:`ExecAccess`."""
    global _default_exec
    if _default_exec is None:
        _default_exec = ExecAccess()
    return _default_exec


def set_default_exec(access: Optional[ExecAccess]) -> None:
    """Override the process-wide default (used by the MCP server / tests)."""
    global _default_exec
    _default_exec = access


def run(
    cmd: Union[str, Sequence[str]],
    cwd: Optional[str] = None,
    timeout: Optional[int] = None,
    *,
    shell: bool = False,
    env: Optional[dict] = None,
) -> dict[str, Any]:
    """Module-level :meth:`ExecAccess.run` against the default exec engine."""
    return get_default_exec().run(cmd, cwd=cwd, timeout=timeout, shell=shell, env=env)


def status() -> dict[str, Any]:
    """Module-level :meth:`ExecAccess.status` against the default exec engine."""
    return get_default_exec().status()


# ---------------------------------------------------------------------------
# MCP registration helper (import-guarded; module works standalone)
# ---------------------------------------------------------------------------

#: Exec tool catalog — ALL scope='exec' (never default-granted). Each entry:
#: ``{name, scope, description, inputSchema}``; ``fn`` is the module-level callable.
TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "run",
        "scope": "exec",
        "description": (
            "Run a command on this node (EXEC scope — never granted by default). "
            "cwd is confined to the exposed-root allowlist; runs without a shell "
            "(argv) by default; denylisted/dangerous commands are refused; output "
            "is size-capped and the process is killed on timeout. Audited."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cmd": {
                    "description": "Command as an argv list (preferred) or a string.",
                    "oneOf": [
                        {"type": "array", "items": {"type": "string"}},
                        {"type": "string"},
                    ],
                },
                "cwd": {
                    "type": "string",
                    "description": "Working dir under an exposed root (default: first root).",
                },
                "timeout": {
                    "type": "integer",
                    "description": f"Seconds before the command is killed (default {DEFAULT_TIMEOUT}, max {MAX_TIMEOUT}).",
                },
                "shell": {
                    "type": "boolean",
                    "description": "Run via a shell (refused unless allow_shell is enabled). Dangerous.",
                    "default": False,
                },
            },
            "required": ["cmd"],
        },
    },
    {
        "name": "exec_status",
        "scope": "exec",
        "description": (
            "Exec-plane node health: load average, uptime, cpu count, exposed "
            "roots, and the exec policy. No command is run."
        ),
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
]


def callable_for(name: str, access: Optional[ExecAccess] = None) -> Callable[..., Any]:
    """Return the bound callable for an exec tool name, against ``access`` (or
    the default singleton)."""
    acc = access or get_default_exec()
    mapping: dict[str, Callable[..., Any]] = {
        "run": acc.run,
        "exec_status": acc.status,
    }
    if name not in mapping:
        raise KeyError(name)
    return mapping[name]


def register(server: Any, access: Optional[ExecAccess] = None) -> list[str]:
    """Attach the exec tools to an MCP ``server`` with ``scope='exec'``.

    Mirrors :func:`skcomms.access.files.register`: tolerant of the host server's
    API (``register_access_tool`` > ``add_tool`` > stash fallback) and never
    imports ``mcp``, so the module stays standalone. Every tool is registered at
    ``scope='exec'`` so it is denied unless the caller is explicitly granted the
    exec scope.

    Returns the list of registered tool names.
    """
    acc = access or get_default_exec()
    registered: list[str] = []

    for spec in TOOL_SPECS:
        name = spec["name"]
        fn = callable_for(name, acc)
        scope = spec["scope"]  # always 'exec'
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
                pass

        bucket = getattr(server, "_access_exec_tools", None)
        if bucket is None:
            bucket = []
            try:
                setattr(server, "_access_exec_tools", bucket)
            except (AttributeError, TypeError):  # pragma: no cover
                logger.warning("register(): cannot attach exec tools to server %r", server)
                break
        bucket.append(
            {"name": name, "fn": fn, "scope": scope, "description": desc, "input_schema": schema}
        )
        registered.append(name)

    logger.info("access.exec.register attached %d tools: %s", len(registered), registered)
    return registered


def register_builtin_exec_tools(registry: Optional[Any] = None) -> list[str]:
    """Register the exec tools into the access :class:`AccessRegistry` (A2).

    Mirrors :func:`skcomms.access.wiring.register_builtin_tools` for the exec
    plane: adapts each module-level callable to an ``(arguments, ctx)`` handler
    and registers it at ``scope='exec'``. Kept separate from the builtin
    (read/write) wiring so exec is opt-in to attach, not just opt-in to grant.

    Returns the list of registered tool names.
    """
    from .registry import register_tool

    def _adapt(fn):
        def handler(arguments: dict, ctx: Any, _fn=fn):
            return _fn(**(arguments or {}))
        return handler

    names: list[str] = []
    for spec in TOOL_SPECS:
        name = spec["name"]
        fn = callable_for(name)
        register_tool(
            name,
            _adapt(fn),
            scope=spec["scope"],  # 'exec'
            description=spec.get("description", ""),
            input_schema=spec.get("inputSchema"),
            replace=True,
            registry=registry,
        )
        names.append(name)
    return names
