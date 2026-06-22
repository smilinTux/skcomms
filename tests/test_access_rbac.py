"""RBAC + per-session identity + audit tests for the sk-access plane (P7 / A6).

Covers:
  * Scope grants: READ identity denied a write tool; granted write allowed;
    wildcard ``"*"`` default grant.
  * The persistent grants store (grants.yml): load, save, grant, revoke,
    merge into AccessConfig.
  * Per-session /sse identity hook: a signed hello is accepted + bound; an
    unsigned/missing hello is rejected when sse_require_auth is ON, and
    falls back to a node-local ctx when OFF.
  * The call-level access audit log: an allow line and a deny line are written
    for both /tool and /sse transports.

capauth keys are generated in-process with pgpy (same pattern as
tests/test_federation.py and tests/test_access_server.py).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from skcomms.envelope import Envelope, SignedEnvelope
from skcomms.signing import EnvelopeSigner
from skcomms.access import (
    AccessConfig,
    AccessRegistry,
    AccessServer,
    AccessAuthError,
    AccessScopeError,
    Scope,
)
from skcomms.access.audit import AccessAuditLog
from skcomms.access import grants as grants_mod


# --- key helpers (same pattern as test_access_server.py) -------------------


def _gen_key(uid: str):
    import pgpy
    from pgpy.constants import (
        CompressionAlgorithm, HashAlgorithm, KeyFlags,
        PubKeyAlgorithm, SymmetricKeyAlgorithm,
    )
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(
        pgpy.PGPUID.new(uid),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return str(key), str(key.pubkey)


@pytest.fixture(scope="module")
def admin_keys():
    return _gen_key("admin <lumina@chef.skworld>")


@pytest.fixture(scope="module")
def reader_keys():
    return _gen_key("reader <guest@chef.skworld>")


# --- server / token factories ----------------------------------------------


def _config(**kw) -> AccessConfig:
    cfg = AccessConfig(
        host="127.0.0.1",
        port=9386,
        scope_grants={
            "lumina@chef.skworld": {Scope.READ, Scope.WRITE, Scope.EXEC},
            "guest@chef.skworld": {Scope.READ},
        },
        node_name="testnode",
        node_fqid="testnode@chef.skworld",
    )
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def _server(audit_path, **kw) -> AccessServer:
    reg = AccessRegistry()
    srv = AccessServer(
        config=_config(**kw),
        registry=reg,
        audit=AccessAuditLog(path=audit_path, node="testnode"),
    )

    async def _writer(args, ctx):
        return {"wrote": args.get("path", "?")}

    srv.registry.register("file_write", _writer, Scope.WRITE, description="fake write")
    return srv


def _signed_token(keys, *, frm="lumina@chef.skworld", tool="health", arguments=None):
    priv, _ = keys
    env = Envelope(
        from_fqid=frm,
        to_fqid="testnode@chef.skworld",
        content_type="application/x-skaccess-call",
        body=json.dumps({"tool": tool, "arguments": arguments or {}}),
    )
    return EnvelopeSigner(priv, "").sign(env)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _audit_lines(audit_path):
    if not audit_path.exists():
        return []
    return [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]


# --- scope grants RBAC ------------------------------------------------------


class TestScopeGrantsRBAC:
    def test_read_identity_denied_write_tool(self, tmp_path, admin_keys, reader_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap)
        srv.trust_key("guest@chef.skworld", reader_keys[1])
        token = _signed_token(reader_keys, frm="guest@chef.skworld", tool="file_write")
        with pytest.raises(AccessScopeError):
            _run(srv.call_tool(token, "file_write", {"path": "/x"}))

    def test_granted_write_allowed(self, tmp_path, admin_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap)
        srv.trust_key("lumina@chef.skworld", admin_keys[1])
        token = _signed_token(admin_keys, frm="lumina@chef.skworld", tool="file_write")
        result = _run(srv.call_tool(token, "file_write", {"path": "/x"}))
        assert result == {"wrote": "/x"}

    def test_wildcard_grant(self, tmp_path, reader_keys):
        # An identity NOT explicitly listed picks up the "*" wildcard grant.
        ap = tmp_path / "audit.log"
        srv = _server(ap, scope_grants={"*": {Scope.READ, Scope.WRITE}})
        srv.trust_key("nobody@chef.skworld", reader_keys[1])
        token = _signed_token(reader_keys, frm="nobody@chef.skworld", tool="file_write")
        result = _run(srv.call_tool(token, "file_write", {"path": "/y"}))
        assert result == {"wrote": "/y"}

    def test_default_fallback_is_read_only(self, tmp_path, reader_keys):
        # No explicit grant, no wildcard -> {READ}; write denied.
        ap = tmp_path / "audit.log"
        srv = _server(ap, scope_grants={})
        srv.trust_key("nobody@chef.skworld", reader_keys[1])
        token = _signed_token(reader_keys, frm="nobody@chef.skworld", tool="file_write")
        with pytest.raises(AccessScopeError):
            _run(srv.call_tool(token, "file_write", {"path": "/z"}))


# --- persistent grants store ------------------------------------------------


class TestGrantsStore:
    def test_grant_then_load(self, tmp_path):
        gp = tmp_path / "grants.yml"
        grants_mod.grant("lumina@chef.skworld", {Scope.WRITE, Scope.READ}, gp)
        loaded = grants_mod.load_grants(gp)
        assert loaded["lumina@chef.skworld"] == {Scope.READ, Scope.WRITE}

    def test_grant_accumulates(self, tmp_path):
        gp = tmp_path / "grants.yml"
        grants_mod.grant("a@chef.skworld", {Scope.READ}, gp)
        grants_mod.grant("a@chef.skworld", {Scope.WRITE}, gp)
        loaded = grants_mod.load_grants(gp)
        assert loaded["a@chef.skworld"] == {Scope.READ, Scope.WRITE}

    def test_revoke(self, tmp_path):
        gp = tmp_path / "grants.yml"
        grants_mod.grant("a@chef.skworld", {Scope.READ, Scope.WRITE, Scope.EXEC}, gp)
        remaining = grants_mod.revoke("a@chef.skworld", {Scope.EXEC}, gp)
        assert remaining == {Scope.READ, Scope.WRITE}
        assert grants_mod.load_grants(gp)["a@chef.skworld"] == {Scope.READ, Scope.WRITE}

    def test_revoke_last_scope_drops_identity(self, tmp_path):
        gp = tmp_path / "grants.yml"
        grants_mod.grant("a@chef.skworld", {Scope.READ}, gp)
        grants_mod.revoke("a@chef.skworld", {Scope.READ}, gp)
        assert "a@chef.skworld" not in grants_mod.load_grants(gp)

    def test_wildcard_identity_persists(self, tmp_path):
        gp = tmp_path / "grants.yml"
        grants_mod.grant("*", {Scope.READ}, gp)
        assert grants_mod.load_grants(gp)["*"] == {Scope.READ}

    def test_load_missing_store_is_empty(self, tmp_path):
        assert grants_mod.load_grants(tmp_path / "nope.yml") == {}

    def test_merge_overlay_wins(self):
        base = {"a": {Scope.READ}, "b": {Scope.READ}}
        overlay = {"a": {Scope.READ, Scope.WRITE}}
        merged = grants_mod.merge_grants(base, overlay)
        assert merged["a"] == {Scope.READ, Scope.WRITE}
        assert merged["b"] == {Scope.READ}

    def test_apply_to_config_merges_store(self, tmp_path):
        gp = tmp_path / "grants.yml"
        grants_mod.grant("guest@chef.skworld", {Scope.WRITE}, gp)
        cfg = AccessConfig(scope_grants={"guest@chef.skworld": {Scope.READ}})
        grants_mod.apply_to_config(cfg, gp)
        # store overlay replaces the static read-only grant.
        assert cfg.granted_scopes("guest@chef.skworld") == {Scope.WRITE}


# --- grants CLI -------------------------------------------------------------


class TestGrantsCLI:
    def test_cli_grant_revoke_list(self, tmp_path, capsys):
        gp = tmp_path / "grants.yml"
        rc = grants_mod.main(["--file", str(gp), "grant", "lumina@chef.skworld", "write"])
        assert rc == 0
        assert grants_mod.load_grants(gp)["lumina@chef.skworld"] == {Scope.READ, Scope.WRITE} or \
            grants_mod.load_grants(gp)["lumina@chef.skworld"] == {Scope.WRITE}

        rc = grants_mod.main(["--file", str(gp), "list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "lumina@chef.skworld" in out

        rc = grants_mod.main(["--file", str(gp), "revoke", "lumina@chef.skworld", "write"])
        assert rc == 0

    def test_cli_bad_scope_errors(self, tmp_path):
        gp = tmp_path / "grants.yml"
        rc = grants_mod.main(["--file", str(gp), "grant", "x@chef.skworld", "bogus"])
        assert rc == 2


# --- per-session /sse identity ---------------------------------------------


class TestSessionAuth:
    def test_signed_hello_accepted_and_bound(self, tmp_path, admin_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap, sse_require_auth=True)
        srv.trust_key("lumina@chef.skworld", admin_keys[1])
        hello = _signed_token(admin_keys, frm="lumina@chef.skworld", tool="hello")
        ctx = srv.authenticate_session(hello)
        assert ctx.identity == "lumina@chef.skworld"
        assert Scope.WRITE in ctx.scopes

    def test_unsigned_hello_rejected_when_required(self, tmp_path):
        ap = tmp_path / "audit.log"
        srv = _server(ap, sse_require_auth=True)
        with pytest.raises(AccessAuthError):
            srv.authenticate_session(None)

    def test_missing_hello_allowed_when_not_required(self, tmp_path):
        ap = tmp_path / "audit.log"
        srv = _server(ap, sse_require_auth=False)
        ctx = srv.authenticate_session(None)
        # node-local fallback ctx with the node's own grants ∪ READ
        assert ctx.identity == "testnode@chef.skworld"
        assert Scope.READ in ctx.scopes

    def test_untrusted_hello_rejected(self, tmp_path, reader_keys, admin_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap, sse_require_auth=True)
        # trust admin's key for the fqid, but reader signs as that fqid
        srv.trust_key("lumina@chef.skworld", admin_keys[1])
        bad = _signed_token(reader_keys, frm="lumina@chef.skworld", tool="hello")
        with pytest.raises(AccessAuthError):
            srv.authenticate_session(bad)

    def test_session_scope_check_uses_session_identity(self, tmp_path, reader_keys):
        # A reader session can't call a write tool even via call_tool_with_ctx.
        ap = tmp_path / "audit.log"
        srv = _server(ap, sse_require_auth=True)
        srv.trust_key("guest@chef.skworld", reader_keys[1])
        hello = _signed_token(reader_keys, frm="guest@chef.skworld", tool="hello")
        ctx = srv.authenticate_session(hello)
        with pytest.raises(AccessScopeError):
            _run(srv.call_tool_with_ctx(ctx, "file_write", {"path": "/x"}, transport="sse"))


# --- audit log --------------------------------------------------------------


class TestAccessAudit:
    def test_allow_line_written(self, tmp_path, admin_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap)
        srv.trust_key("lumina@chef.skworld", admin_keys[1])
        token = _signed_token(admin_keys, frm="lumina@chef.skworld", tool="file_write")
        _run(srv.call_tool(token, "file_write", {"path": "/x"}))
        lines = _audit_lines(ap)
        allow = [l for l in lines if l["decision"] == "allow"]
        assert allow
        assert allow[-1]["tool"] == "file_write"
        assert allow[-1]["identity"] == "lumina@chef.skworld"
        assert allow[-1]["scope"] == "write"
        assert allow[-1]["transport"] == "tool"

    def test_deny_line_written_on_scope(self, tmp_path, reader_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap)
        srv.trust_key("guest@chef.skworld", reader_keys[1])
        token = _signed_token(reader_keys, frm="guest@chef.skworld", tool="file_write")
        with pytest.raises(AccessScopeError):
            _run(srv.call_tool(token, "file_write", {"path": "/x"}))
        lines = _audit_lines(ap)
        deny = [l for l in lines if l["decision"] == "deny"]
        assert deny
        assert deny[-1]["reason"] == "scope"
        assert deny[-1]["identity"] == "guest@chef.skworld"

    def test_deny_line_on_auth_failure(self, tmp_path, admin_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap)
        srv.trust_key("lumina@chef.skworld", admin_keys[1])
        bare = SignedEnvelope(
            envelope=Envelope(
                from_fqid="lumina@chef.skworld",
                to_fqid="testnode@chef.skworld",
                body="{}",
            )
        )
        with pytest.raises(AccessAuthError):
            _run(srv.call_tool(bare, "health"))
        lines = _audit_lines(ap)
        deny = [l for l in lines if l["decision"] == "deny" and l["reason"] == "auth"]
        assert deny

    def test_sse_transport_audited(self, tmp_path, admin_keys):
        ap = tmp_path / "audit.log"
        srv = _server(ap)
        srv.trust_key("lumina@chef.skworld", admin_keys[1])
        hello = _signed_token(admin_keys, frm="lumina@chef.skworld", tool="hello")
        ctx = srv.authenticate_session(hello)
        _run(srv.call_tool_with_ctx(ctx, "file_write", {"path": "/x"}, transport="sse"))
        lines = _audit_lines(ap)
        sse = [l for l in lines if l["transport"] == "sse" and l["decision"] == "allow"]
        assert sse
        assert sse[-1]["node"] == "testnode"
