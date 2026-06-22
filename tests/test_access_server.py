"""Tests for skcomms.access — the sk-access MCP server skeleton (P7 / A2).

Covers the capauth gate (signed pass / unsigned + untrusted reject), scope
enforcement (write tool denied to a read-only identity), the built-in
node_info/health tools, and the tailnet-only bind posture (default host is not
0.0.0.0; a public bind is refused). capauth keys are generated in-process with
pgpy, mirroring tests/test_federation.py.
"""

from __future__ import annotations

import asyncio

import pytest

from skcomms.envelope import Envelope
from skcomms.signing import EnvelopeSigner
from skcomms.access import (
    AccessConfig,
    AccessRegistry,
    AccessServer,
    AccessAuthError,
    AccessScopeError,
    Scope,
)
from skcomms.access.config import is_public_bind, assert_not_public
from skcomms.access.server import ToolNotFoundError, build_app


# --- key helpers (same pattern as test_federation.py) ----------------------


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


@pytest.fixture(scope="module")
def stranger_keys():
    return _gen_key("stranger <evil@attacker.realm>")


# --- server factory --------------------------------------------------------


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


def _server(**kw) -> AccessServer:
    # Isolated registry so the process-wide default isn't polluted between tests.
    reg = AccessRegistry()
    srv = AccessServer(config=_config(**kw), registry=reg)
    return srv


def _signed_token(keys, *, frm="lumina@chef.skworld", tool="health", arguments=None):
    """Build a capauth-signed envelope token authorizing a tool call."""
    priv, _ = keys
    import json as _json

    env = Envelope(
        from_fqid=frm,
        to_fqid="testnode@chef.skworld",
        content_type="application/x-skaccess-call",
        body=_json.dumps({"tool": tool, "arguments": arguments or {}}),
    )
    return EnvelopeSigner(priv, "").sign(env)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# --- bind posture ----------------------------------------------------------


class TestBindPosture:
    def test_default_host_not_public(self):
        # The constructed test config binds loopback (never 0.0.0.0).
        srv = _server()
        assert srv.config.host != "0.0.0.0"
        assert is_public_bind(srv.config.host) is False

    def test_public_bind_flagged(self):
        assert is_public_bind("0.0.0.0") is True
        assert is_public_bind("::") is True
        assert is_public_bind("8.8.8.8") is True

    def test_tailnet_and_loopback_allowed(self):
        assert is_public_bind("127.0.0.1") is False
        assert is_public_bind("100.64.1.2") is False  # CGNAT / tailscale

    def test_validate_refuses_public(self):
        srv = _server(host="0.0.0.0")
        with pytest.raises(ValueError):
            srv.config.validate()

    def test_validate_allows_public_with_override(self):
        srv = _server(host="0.0.0.0", allow_public=True)
        srv.config.validate()  # no raise

    def test_assert_not_public_helper(self):
        with pytest.raises(ValueError):
            assert_not_public("0.0.0.0")
        assert_not_public("127.0.0.1")  # no raise


# --- capauth gate ----------------------------------------------------------


class TestCapauthGate:
    def test_signed_trusted_call_succeeds(self, admin_keys):
        _, pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", pub)
        token = _signed_token(admin_keys, tool="health")
        result = _run(srv.call_tool(token, "health"))
        assert result["status"] == "ok"
        assert result["node"] == "testnode"

    def test_unsigned_rejected(self, admin_keys):
        _, pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", pub)
        from skcomms.envelope import SignedEnvelope

        bare = SignedEnvelope(
            envelope=Envelope(
                from_fqid="lumina@chef.skworld",
                to_fqid="testnode@chef.skworld",
                body="{}",
            )
        )  # no signature
        with pytest.raises(AccessAuthError):
            _run(srv.call_tool(bare, "health"))

    def test_untrusted_signer_rejected(self, stranger_keys, admin_keys):
        # Server only trusts admin's key for that fqid; stranger signs.
        _, admin_pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", admin_pub)
        token = _signed_token(stranger_keys, frm="lumina@chef.skworld", tool="health")
        with pytest.raises(AccessAuthError):
            _run(srv.call_tool(token, "health"))

    def test_replay_rejected(self, admin_keys):
        _, pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", pub)
        token = _signed_token(admin_keys, tool="health")
        _run(srv.call_tool(token, "health"))
        with pytest.raises(AccessAuthError):
            _run(srv.call_tool(token, "health"))  # same nonce → replay

    def test_dev_bypass_allows_unsigned(self):
        srv = _server(dev_bypass=True)
        # Any string token accepted; verification skipped.
        result = _run(srv.call_tool("not-a-real-token", "health"))
        assert result["status"] == "ok"


# --- scope enforcement -----------------------------------------------------


class TestScopeEnforcement:
    def _server_with_write_tool(self, admin_keys, reader_keys):
        srv = _server()
        _, admin_pub = admin_keys
        _, reader_pub = reader_keys
        srv.trust_key("lumina@chef.skworld", admin_pub)
        srv.trust_key("guest@chef.skworld", reader_pub)

        async def _writer(args, ctx):
            return {"wrote": args.get("path", "?")}

        srv.registry.register(
            "file_write", _writer, Scope.WRITE, description="fake write tool"
        )
        return srv

    def test_write_denied_to_reader(self, admin_keys, reader_keys):
        srv = self._server_with_write_tool(admin_keys, reader_keys)
        token = _signed_token(reader_keys, frm="guest@chef.skworld", tool="file_write")
        with pytest.raises(AccessScopeError):
            _run(srv.call_tool(token, "file_write", {"path": "/x"}))

    def test_write_allowed_to_admin(self, admin_keys, reader_keys):
        srv = self._server_with_write_tool(admin_keys, reader_keys)
        token = _signed_token(admin_keys, frm="lumina@chef.skworld", tool="file_write")
        result = _run(srv.call_tool(token, "file_write", {"path": "/x"}))
        assert result == {"wrote": "/x"}

    def test_reader_can_call_read_tool(self, admin_keys, reader_keys):
        srv = self._server_with_write_tool(admin_keys, reader_keys)
        token = _signed_token(reader_keys, frm="guest@chef.skworld", tool="node_info")
        result = _run(srv.call_tool(token, "node_info"))
        assert result["node"] == "testnode"

    def test_scope_grant_hierarchy(self):
        # EXEC grant implicitly satisfies WRITE and READ requirements.
        assert Scope.READ.satisfied_by({Scope.EXEC})
        assert Scope.WRITE.satisfied_by({Scope.EXEC})
        assert not Scope.WRITE.satisfied_by({Scope.READ})


# --- built-in tools --------------------------------------------------------


class TestBuiltins:
    def test_node_info_contents(self, admin_keys):
        _, pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", pub)
        token = _signed_token(admin_keys, tool="node_info")
        info = _run(srv.call_tool(token, "node_info"))
        assert info["node"] == "testnode"
        assert info["fqid"] == "testnode@chef.skworld"
        assert info["public_bind"] is False
        assert info["security"]["tailnet_only"] is True
        assert info["security"]["capauth_gated"] is True
        names = {t["name"] for t in info["tools"]}
        assert {"node_info", "health"} <= names

    def test_health(self, admin_keys):
        _, pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", pub)
        token = _signed_token(admin_keys, tool="health")
        assert _run(srv.call_tool(token, "health"))["status"] == "ok"

    def test_unknown_tool(self, admin_keys):
        _, pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", pub)
        token = _signed_token(admin_keys, tool="nope")
        with pytest.raises(ToolNotFoundError):
            _run(srv.call_tool(token, "nope"))


# --- tool registration API (the A3/A4 seam) --------------------------------


class TestRegistrationSeam:
    def test_register_and_invoke_custom_tool(self, admin_keys):
        _, pub = admin_keys
        srv = _server()
        srv.trust_key("lumina@chef.skworld", pub)

        async def _pg_search(args, ctx):
            return {"q": args["query"], "caller": ctx.identity, "hits": []}

        srv.registry.register(
            "pg_search", _pg_search, "read",
            description="fake knowledge search",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
        )
        token = _signed_token(admin_keys, tool="pg_search", arguments={"query": "bug"})
        result = _run(srv.call_tool(token, "pg_search", {"query": "bug"}))
        assert result["q"] == "bug"
        assert result["caller"] == "lumina@chef.skworld"

    def test_duplicate_registration_rejected(self):
        reg = AccessRegistry()
        reg.register("t", lambda a, c: None, "read")
        with pytest.raises(ValueError):
            reg.register("t", lambda a, c: None, "read")
        reg.register("t", lambda a, c: 1, "read", replace=True)  # ok with replace


# --- app build / posture ---------------------------------------------------


class TestAppBuild:
    def test_build_app_ok_on_loopback(self):
        srv = _server()
        app = build_app(srv)
        assert app is not None
        # /health and /node_info routes are present.
        paths = {getattr(r, "path", None) for r in app.router.routes}
        assert "/health" in paths
        assert "/node_info" in paths
        assert "/tool" in paths

    def test_build_app_refuses_public(self):
        srv = _server(host="0.0.0.0")
        with pytest.raises(ValueError):
            build_app(srv)
