"""Tests for the SKFed P7/A7 sandboxed exec tools (aligns skreach F2).

EXEC IS THE DANGEROUS PLANE — these tests are adversarial about the two security
boundaries: **cwd cannot escape the exposed-root allowlist**, and **command
injection / dangerous commands are refused**. We also pin the operational
contract: exit codes, output cap, timeout-kill, audit log, no-shell argv path,
and that the exec tools declare ``scope='exec'`` (so they are never default).
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from skcomms.access.exec import (
    CommandDeniedError,
    ExecAccess,
    ExecAccessConfig,
    TOOL_SPECS,
    register,
    register_builtin_exec_tools,
)
from skcomms.access.files import FileAccess, FileAccessConfig, PathDeniedError
from skcomms.access.registry import AccessRegistry, Scope


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def root(tmp_path):
    d = tmp_path / "root"
    d.mkdir()
    return d


@pytest.fixture
def audit(tmp_path):
    return tmp_path / "exec-audit.log"


@pytest.fixture
def fa(root):
    """A FileAccess whose only exposed root is ``root`` — the exec cwd boundary."""
    return FileAccess(FileAccessConfig(roots=[str(root)], identity="test-agent"))


@pytest.fixture
def ea(fa, audit):
    return ExecAccess(
        ExecAccessConfig(
            file_access=fa,
            audit_log=str(audit),
            identity="test-agent",
            default_timeout=5,
        )
    )


# ---------------------------------------------------------------------------
# Benign command
# ---------------------------------------------------------------------------


def test_echo_returns_exit0_and_stdout(ea):
    res = ea.run(["echo", "hello-skfed"])
    assert res["exit_code"] == 0
    assert "hello-skfed" in res["stdout"]
    assert res["stderr"] == ""
    assert res["timed_out"] is False
    assert res["truncated"] is False


def test_nonzero_exit_code(ea):
    res = ea.run([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert res["exit_code"] == 3


def test_stderr_captured(ea):
    res = ea.run([sys.executable, "-c", "import sys; sys.stderr.write('boom')"])
    assert "boom" in res["stderr"]


# ---------------------------------------------------------------------------
# cwd confinement — the security boundary
# ---------------------------------------------------------------------------


def test_cwd_default_is_first_root(ea, root):
    res = ea.run([sys.executable, "-c", "import os; print(os.getcwd())"])
    assert os.path.realpath(res["stdout"].strip()) == os.path.realpath(str(root))


def test_cwd_inside_root_ok(ea, root):
    sub = root / "sub"
    sub.mkdir()
    res = ea.run(["pwd"], cwd=str(sub))
    assert os.path.realpath(res["stdout"].strip()) == os.path.realpath(str(sub))


def test_cwd_outside_root_rejected(ea, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(PathDeniedError):
        ea.run(["echo", "hi"], cwd=str(outside))


def test_cwd_dotdot_escape_rejected(ea, root):
    # ../../ climbing out of the root must be caught by the resolver.
    with pytest.raises(PathDeniedError):
        ea.run(["echo", "hi"], cwd=str(root / ".." / ".."))


def test_cwd_absolute_etc_rejected(ea):
    with pytest.raises(PathDeniedError):
        ea.run(["ls"], cwd="/etc")


def test_cwd_symlink_escape_rejected(ea, root, tmp_path):
    # A symlink INSIDE the root that points OUTSIDE must not grant escape.
    secret_dir = tmp_path / "secret_outside"
    secret_dir.mkdir()
    link = root / "escape"
    link.symlink_to(secret_dir)
    with pytest.raises(PathDeniedError):
        ea.run(["ls"], cwd=str(link))


# ---------------------------------------------------------------------------
# Timeout kills a long command
# ---------------------------------------------------------------------------


def test_timeout_kills_long_command(ea):
    res = ea.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert res["timed_out"] is True
    assert res["exit_code"] == -1


def test_timeout_kills_child_processes(ea):
    # The spawned python forks a long-sleeping child; the process-group kill
    # must reap the whole tree, so communicate() returns promptly.
    code = (
        "import subprocess, time, sys; "
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "time.sleep(60)"
    )
    res = ea.run([sys.executable, "-c", code], timeout=1)
    assert res["timed_out"] is True


# ---------------------------------------------------------------------------
# Output size cap
# ---------------------------------------------------------------------------


def test_output_cap_truncates(fa, audit):
    ea = ExecAccess(
        ExecAccessConfig(file_access=fa, audit_log=str(audit), max_output=64)
    )
    res = ea.run([sys.executable, "-c", "print('A' * 5000)"])
    assert res["truncated"] is True
    assert len(res["stdout"]) <= 64


# ---------------------------------------------------------------------------
# Denylist / injection refusal
# ---------------------------------------------------------------------------


def test_denylisted_binary_refused(ea):
    with pytest.raises(CommandDeniedError):
        ea.run(["sudo", "ls"])


def test_rm_rf_root_pattern_refused(ea):
    with pytest.raises(CommandDeniedError):
        ea.run(["rm", "-rf", "/"])


def test_fork_bomb_pattern_refused(ea):
    # Even though shell is off, the pattern guard refuses the classic bomb.
    with pytest.raises(CommandDeniedError):
        ea.run(":(){ :|:& };:", shell=False)


def test_metachar_in_argv_list_is_literal_not_shell(ea):
    # An explicit list is trusted verbatim — no shell sees it, so a ';' inside
    # an argument is an inert literal passed to echo (NOT command chaining).
    res = ea.run(["echo", "hi; rm -rf /tmp/x"])
    assert res["exit_code"] == 0
    assert "hi; rm -rf /tmp/x" in res["stdout"]


def test_shell_operator_in_command_string_refused(ea):
    # A STRING that shlex-splits to a bare shell operator means the caller
    # assumed shell semantics; the no-shell path refuses it.
    with pytest.raises(CommandDeniedError):
        ea.run("echo hi | cat")  # '|' lands as its own token


def test_chaining_operator_in_command_string_refused(ea):
    with pytest.raises(CommandDeniedError):
        ea.run("echo hi ; rm -rf /tmp/x")


def test_allowlist_blocks_unlisted_binary(fa, audit):
    ea = ExecAccess(
        ExecAccessConfig(
            file_access=fa,
            audit_log=str(audit),
            allow_binaries=("echo",),
        )
    )
    assert ea.run(["echo", "ok"])["exit_code"] == 0
    with pytest.raises(CommandDeniedError):
        ea.run(["cat", "/etc/hostname"])


# ---------------------------------------------------------------------------
# No-shell (argv) path & gated shell
# ---------------------------------------------------------------------------


def test_argv_no_shell_does_not_expand(ea):
    # Without a shell, '$HOME' is a literal argument, not expanded.
    res = ea.run(["echo", "$HOME"])
    assert res["stdout"].strip() == "$HOME"


def test_shell_refused_by_default(ea):
    with pytest.raises(CommandDeniedError):
        ea.run("echo hi", shell=True)


def test_shell_allowed_when_enabled(fa, audit):
    ea = ExecAccess(
        ExecAccessConfig(file_access=fa, audit_log=str(audit), allow_shell=True)
    )
    res = ea.run("echo shelled", shell=True)
    assert res["exit_code"] == 0
    assert "shelled" in res["stdout"]


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_audit_line_on_exec(ea, audit):
    ea.run(["echo", "audited"])
    assert audit.exists()
    lines = audit.read_text().strip().splitlines()
    assert lines
    entry = json.loads(lines[-1])
    assert entry["action"] == "exec"
    assert entry["identity"] == "test-agent"
    assert "echo audited" in entry["cmd"]
    assert entry["exit_code"] == 0
    assert "ts" in entry
    assert "cwd" in entry


def test_audit_records_denied_spawn(ea, audit):
    # A binary that does not exist -> spawn failure is still audited.
    res = ea.run(["this-binary-does-not-exist-skfed"])
    assert res["exit_code"] == -1
    entry = json.loads(audit.read_text().strip().splitlines()[-1])
    assert entry["exit_code"] == -1


# ---------------------------------------------------------------------------
# status()
# ---------------------------------------------------------------------------


def test_status_reports_health(ea, root):
    st = ea.status()
    assert "loadavg" in st
    assert "uptime_s" in st
    assert st["cpu_count"] == os.cpu_count()
    assert str(root) in st["exposed_roots"]
    assert st["allow_shell"] is False


# ---------------------------------------------------------------------------
# Registration — exec tools declare scope='exec'
# ---------------------------------------------------------------------------


def test_tool_specs_all_exec_scope():
    assert TOOL_SPECS, "expected exec tool specs"
    for spec in TOOL_SPECS:
        assert spec["scope"] == "exec", f"{spec['name']} must be exec-scoped"


def test_register_builtin_exec_tools_into_registry():
    reg = AccessRegistry()
    names = register_builtin_exec_tools(registry=reg)
    assert "run" in names
    assert "exec_status" in names
    for name in names:
        tool = reg.get(name)
        assert tool is not None
        assert tool.scope is Scope.EXEC


def test_exec_scope_not_default_granted():
    # An identity with the default grant (READ) must NOT satisfy an exec tool.
    from skcomms.access.config import AccessConfig

    cfg = AccessConfig()  # scope_grants empty -> default {READ}
    granted = cfg.granted_scopes("some-agent")
    assert granted == {Scope.READ}
    assert Scope.EXEC.satisfied_by(granted) is False


def test_register_via_server_hook_uses_exec_scope():
    captured = []

    class FakeServer:
        def register_access_tool(self, name, fn, *, scope, description, input_schema):
            captured.append((name, scope))

    register(FakeServer(), access=None)
    assert captured
    assert all(scope == "exec" for _, scope in captured)
