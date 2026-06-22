"""Tests for the SKFed P7/A4 sandboxed file tools.

The path-validation tests are the important ones: they verify the security
boundary holds against ``..`` traversal, absolute paths outside the roots,
symlinks pointing out, and secrets hard-deny — all of which must be rejected.
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from skcomms.access.files import (
    AccessError,
    FileAccess,
    FileAccessConfig,
    FileTooLargeError,
    PathDeniedError,
    _apply_unified_diff,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def root(tmp_path):
    """An exposed root directory."""
    d = tmp_path / "root"
    d.mkdir()
    return d


@pytest.fixture
def audit(tmp_path):
    return tmp_path / "audit.log"


@pytest.fixture
def fa(root, audit):
    cfg = FileAccessConfig(
        roots=[str(root)],
        audit_log=str(audit),
        identity="test-agent",
        max_bytes=1024,
    )
    return FileAccess(cfg)


# ---------------------------------------------------------------------------
# Round-trips
# ---------------------------------------------------------------------------


def test_write_read_roundtrip(fa, root):
    p = str(root / "hello.txt")
    res = fa.file_write(p, "hello world\n")
    assert res["written"] is True
    assert res["size"] == len("hello world\n")

    rd = fa.file_read(p)
    assert rd["content"] == "hello world\n"
    assert rd["binary"] is False
    assert rd["encoding"] == "utf-8"
    assert rd["sha"] == res["sha"]


def test_write_creates_nested_dirs(fa, root):
    p = str(root / "a" / "b" / "c.txt")
    fa.file_write(p, "deep")
    assert fa.file_read(p)["content"] == "deep"


def test_list(fa, root):
    fa.file_write(str(root / "a.txt"), "a")
    fa.file_write(str(root / "sub" / "b.txt"), "b")
    listing = fa.file_list(str(root))
    names = {e["name"]: e["type"] for e in listing}
    assert names["a.txt"] == "file"
    assert names["sub"] == "dir"


def test_stat(fa, root):
    p = str(root / "s.txt")
    fa.file_write(p, "xyz")
    st = fa.file_stat(p)
    assert st["type"] == "file"
    assert st["size"] == 3


def test_list_roots(fa, root):
    roots = fa.list_roots()
    assert len(roots) == 1
    assert roots[0] == str(root.resolve())


def test_patch_roundtrip(fa, root):
    p = str(root / "patch.txt")
    fa.file_write(p, "line1\nline2\nline3\n")
    diff = (
        "--- a/patch.txt\n"
        "+++ b/patch.txt\n"
        "@@ -1,3 +1,3 @@\n"
        " line1\n"
        "-line2\n"
        "+LINE-TWO\n"
        " line3\n"
    )
    res = fa.file_patch(p, diff)
    assert res["patched"] is True
    assert fa.file_read(p)["content"] == "line1\nLINE-TWO\nline3\n"


def test_patch_context_mismatch_rejected(fa, root):
    p = str(root / "patch.txt")
    fa.file_write(p, "alpha\nbeta\n")
    bad = (
        "@@ -1,2 +1,2 @@\n"
        " WRONG\n"
        "-beta\n"
        "+gamma\n"
    )
    with pytest.raises(AccessError):
        fa.file_patch(p, bad)


# ---------------------------------------------------------------------------
# Path traversal — the security boundary
# ---------------------------------------------------------------------------


def test_dotdot_escape_rejected(fa, root):
    # ../../etc/passwd style
    with pytest.raises(PathDeniedError):
        fa.file_read(str(root / ".." / ".." / "etc" / "passwd"))


def test_absolute_outside_root_rejected(fa):
    with pytest.raises(PathDeniedError):
        fa.file_read("/etc/passwd")


def test_write_outside_root_rejected(fa, tmp_path):
    outside = str(tmp_path / "not_a_root" / "x.txt")
    with pytest.raises(PathDeniedError):
        fa.file_write(outside, "nope")


def test_symlink_pointing_outside_rejected(fa, root, tmp_path):
    # Create a secret file OUTSIDE the root, then a symlink inside the root
    # that points to it. Reading via the symlink must be denied because the
    # resolved real path escapes the root.
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("TOPSECRET")
    link = root / "innocent.txt"
    link.symlink_to(secret)
    with pytest.raises(PathDeniedError):
        fa.file_read(str(link))


def test_symlinked_dir_escape_rejected(fa, root, tmp_path):
    # A symlinked directory inside the root pointing outside, then a path
    # "through" it. Resolution must follow the symlink and reject.
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "loot.txt").write_text("loot")
    (root / "door").symlink_to(outside_dir)
    with pytest.raises(PathDeniedError):
        fa.file_read(str(root / "door" / "loot.txt"))


def test_null_byte_rejected(fa, root):
    with pytest.raises(PathDeniedError):
        fa.file_read(str(root / "a\x00b"))


def test_list_omits_escaping_symlink(fa, root, tmp_path):
    fa.file_write(str(root / "real.txt"), "ok")
    secret = tmp_path / "secret.txt"
    secret.write_text("s")
    (root / "escape").symlink_to(secret)
    listing = fa.file_list(str(root))
    names = {e["name"] for e in listing}
    assert "real.txt" in names
    assert "escape" not in names  # escaping symlink omitted from listing


# ---------------------------------------------------------------------------
# Secrets hard-deny (under an allowed root)
# ---------------------------------------------------------------------------


def test_pem_under_root_denied(fa, root):
    p = root / "server.pem"
    p.write_text("-----BEGIN PRIVATE KEY-----")
    with pytest.raises(PathDeniedError):
        fa.file_read(str(p))


def test_key_under_root_denied(fa, root):
    p = root / "secret.key"
    p.write_text("k")
    with pytest.raises(PathDeniedError):
        fa.file_read(str(p))


def test_ssh_dir_denied(fa, root):
    d = root / ".ssh"
    d.mkdir()
    p = d / "id_rsa"
    p.write_text("PRIVATE")
    with pytest.raises(PathDeniedError):
        fa.file_read(str(p))


def test_known_hosts_denied(fa, root):
    p = root / "known_hosts"
    p.write_text("github.com ssh-rsa ...")
    with pytest.raises(PathDeniedError):
        fa.file_read(str(p))


def test_env_file_denied(fa, root):
    p = root / ".env"
    p.write_text("API_KEY=sekret")
    with pytest.raises(PathDeniedError):
        fa.file_read(str(p))


def test_capauth_dir_denied(fa, root):
    d = root / "capauth"
    d.mkdir()
    p = d / "identity.json"
    p.write_text("{}")
    with pytest.raises(PathDeniedError):
        fa.file_read(str(p))


def test_cot_pki_denied(fa, root):
    d = root / "cot-pki"
    d.mkdir()
    p = d / "ca.crt"
    p.write_text("x")
    with pytest.raises(PathDeniedError):
        fa.file_read(str(p))


def test_write_to_secret_path_denied(fa, root):
    with pytest.raises(PathDeniedError):
        fa.file_write(str(root / "leak.pem"), "key material")


# ---------------------------------------------------------------------------
# Size cap
# ---------------------------------------------------------------------------


def test_write_size_cap(fa, root):
    big = "x" * 2048  # cap is 1024
    with pytest.raises(FileTooLargeError):
        fa.file_write(str(root / "big.txt"), big)


def test_read_size_cap(fa, root):
    # Write directly (bypass tool) to exceed cap, then read via tool.
    p = root / "big2.txt"
    p.write_text("y" * 2048)
    with pytest.raises(FileTooLargeError):
        fa.file_read(str(p))


# ---------------------------------------------------------------------------
# Binary handling
# ---------------------------------------------------------------------------


def test_binary_read_base64(fa, root):
    p = root / "blob.bin"
    raw = bytes([0, 159, 146, 150, 255, 1, 2, 3])  # invalid utf-8
    p.write_bytes(raw)
    rd = fa.file_read(str(p))
    assert rd["binary"] is True
    assert rd["encoding"] == "base64"
    assert base64.b64decode(rd["content"]) == raw


def test_binary_write_base64(fa, root):
    raw = bytes([0, 1, 2, 250, 251, 252])
    p = str(root / "out.bin")
    fa.file_write(p, base64.b64encode(raw).decode(), encoding="base64")
    rd = fa.file_read(p)
    assert base64.b64decode(rd["content"]) == raw


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_audit_log_on_write(fa, root, audit):
    fa.file_write(str(root / "audited.txt"), "data")
    assert audit.exists()
    lines = audit.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["action"] == "write"
    assert entry["identity"] == "test-agent"
    assert entry["path"].endswith("audited.txt")
    assert "ts" in entry


def test_audit_log_on_patch(fa, root, audit):
    p = str(root / "p.txt")
    fa.file_write(p, "one\ntwo\n")
    diff = "@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n"
    fa.file_patch(p, diff)
    entries = [json.loads(l) for l in audit.read_text().strip().splitlines()]
    actions = [e["action"] for e in entries]
    assert "write" in actions
    assert "patch" in actions


def test_read_not_audited(fa, root, audit):
    p = str(root / "r.txt")
    fa.file_write(p, "x")  # 1 audit line
    fa.file_read(p)
    lines = audit.read_text().strip().splitlines()
    assert len(lines) == 1  # only the write, not the read


# ---------------------------------------------------------------------------
# register() helper
# ---------------------------------------------------------------------------


def test_register_with_custom_hook(fa):
    captured = []

    class FakeServer:
        def register_access_tool(self, name, fn, *, scope, description, input_schema):
            captured.append((name, scope, callable(fn)))

    names = []
    from skcomms.access import files as filesmod

    names = filesmod.register(FakeServer(), access=fa)
    assert set(names) == {
        "file_read",
        "file_write",
        "file_patch",
        "file_list",
        "file_stat",
        "list_roots",
    }
    scopes = {n: s for n, s, _ in captured}
    assert scopes["file_read"] == "read"
    assert scopes["file_list"] == "read"
    assert scopes["file_stat"] == "read"
    assert scopes["list_roots"] == "read"
    assert scopes["file_write"] == "write"
    assert scopes["file_patch"] == "write"
    assert all(is_callable for _, _, is_callable in captured)


def test_register_fallback_bucket(fa):
    class BareServer:
        pass

    from skcomms.access import files as filesmod

    s = BareServer()
    names = filesmod.register(s, access=fa)
    assert len(names) == 6
    bucket = s._access_file_tools
    assert len(bucket) == 6
    assert all(callable(t["fn"]) for t in bucket)


# ---------------------------------------------------------------------------
# diff applier unit
# ---------------------------------------------------------------------------


def test_apply_unified_diff_add_and_remove():
    original = "a\nb\nc\n"
    diff = "@@ -1,3 +1,4 @@\n a\n+inserted\n b\n-c\n+C\n"
    result = _apply_unified_diff(original, diff)
    assert result == "a\ninserted\nb\nC\n"


def test_apply_unified_diff_no_hunk_errors():
    with pytest.raises(AccessError):
        _apply_unified_diff("x\n", "not a diff at all\n")
