"""sk-access MCP server skeleton (P7 / A2).

The per-node, capauth-gated access server. This module owns:

* the **capauth gate** (:meth:`AccessServer.authenticate`) — reuses
  :func:`skcomms.federation.accept_signed` (signature + freshness + replay) plus
  TOFU key pinning from the :class:`~skcomms.discovery.PeerStore`. Unsigned or
  untrusted callers are rejected.
* the **tool dispatcher** (:meth:`AccessServer.call_tool`) — verifies the caller,
  resolves their granted scopes, enforces the tool's required scope, then invokes
  the registered handler with a :class:`ToolContext`.
* the **built-in tools** ``node_info`` and ``health`` (always present).
* a **FastAPI app** (:func:`build_app`) exposing the MCP SSE transport on the
  **tailnet interface only** (config refuses ``0.0.0.0``/public), plus plain
  ``/node_info`` + ``/health`` GETs for liveness, and a ``/tool`` POST seam.
* **best-effort skos registration** of this node's access endpoint.

A3 (knowledge) and A4 (file) tools attach via :func:`skcomms.access.register_tool`
(default registry) or by handing this server its own :class:`AccessRegistry`.

The capauth token is a :class:`~skcomms.envelope.SignedEnvelope` whose
``body`` carries the tool call (``{"tool": ..., "arguments": ...}``); the
signature proves the caller's identity, freshness+nonce bound replay.
"""

from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass
from typing import Any, Optional

from .. import federation as fed
from ..discovery import PeerStore
from ..envelope import SignedEnvelope
from ..signing import EnvelopeVerifier
from .audit import AccessAuditLog
from .config import AccessConfig
from .registry import AccessRegistry, DEFAULT_REGISTRY, RegisteredTool, Scope

logger = logging.getLogger("skcomms.access.server")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AccessError(Exception):
    """Base class for access-plane rejections."""


class AccessAuthError(AccessError):
    """The caller is unsigned, stale, replayed, or untrusted (HTTP 401)."""


class AccessScopeError(AccessError):
    """The caller's granted scopes do not cover the tool's required scope (403)."""


class ToolNotFoundError(AccessError):
    """No tool with the requested name is registered (404)."""


# ---------------------------------------------------------------------------
# Tool invocation context
# ---------------------------------------------------------------------------


@dataclass
class ToolContext:
    """Passed to every tool handler as the 2nd argument.

    Attributes:
        identity: Verified caller identity (envelope ``from_fqid``).
        fingerprint: Verified signer PGP fingerprint (or ``None`` in dev-bypass).
        scopes: The caller's granted :class:`Scope` set.
        config: The server :class:`AccessConfig` (exposed roots, etc.).
        server: Back-reference to the :class:`AccessServer`.
    """

    identity: Optional[str]
    fingerprint: Optional[str]
    scopes: set[Scope]
    config: AccessConfig
    server: "AccessServer"

    def has_scope(self, scope: Scope) -> bool:
        return scope.satisfied_by(self.scopes)


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------


class AccessServer:
    """sk-access MCP server: capauth gate + scoped tool dispatch.

    Args:
        config: Resolved :class:`AccessConfig` (default: ``AccessConfig.load()``).
        registry: Tool registry (default: the process-wide DEFAULT_REGISTRY).
        verifier: An :class:`~skcomms.signing.EnvelopeVerifier`. If omitted, one
            is created and seeded TOFU-style from the :class:`PeerStore`.
        peer_store: Peer store for TOFU key resolution (default: a fresh one).
    """

    def __init__(
        self,
        config: Optional[AccessConfig] = None,
        registry: Optional[AccessRegistry] = None,
        verifier: Optional[EnvelopeVerifier] = None,
        peer_store: Optional[PeerStore] = None,
        audit: Optional[AccessAuditLog] = None,
    ) -> None:
        self.config = config or AccessConfig.load()
        self.registry = registry or DEFAULT_REGISTRY
        self._peer_store = peer_store if peer_store is not None else PeerStore()
        self.verifier = verifier or self._build_verifier()
        self.nonce_cache = fed.NonceCache()
        self.audit = audit or AccessAuditLog(node=self.config.node_name)
        self._register_builtins()

    # -- key/TOFU setup -----------------------------------------------------

    def _build_verifier(self) -> EnvelopeVerifier:
        """Build a verifier and pin every peer's known public key (TOFU).

        Each :class:`~skcomms.discovery.PeerInfo` that carries a ``pubkey``
        (pinned on first contact) is loaded under both its fqid and name so a
        signed call's ``from_fqid`` resolves to the trusted key.
        """
        v = EnvelopeVerifier()
        try:
            for peer in self._peer_store.list_all():
                if not peer.pubkey:
                    continue
                for ident in filter(None, (peer.fqid, peer.name)):
                    try:
                        v.add_key(ident, peer.pubkey)
                    except Exception as exc:  # pragma: no cover - bad key data
                        logger.debug("skip peer key %s: %s", ident, exc)
        except Exception as exc:  # pragma: no cover - store unavailable
            logger.debug("peer store unavailable for TOFU seed: %s", exc)
        return v

    def trust_key(self, identity: str, public_key_armor: str) -> str:
        """Pin a public key for an identity (TOFU/test helper).

        Returns:
            The key's 40-char fingerprint.
        """
        return self.verifier.add_key(identity, public_key_armor)

    # -- builtin tools ------------------------------------------------------

    def _register_builtins(self) -> None:
        # replace=True so re-instantiating a server in tests is idempotent.
        self.registry.register(
            "node_info",
            self._tool_node_info,
            Scope.READ,
            description=(
                "Describe this access node: name, fqid, bind host/port, "
                "exposed roots, registered tools, and security posture."
            ),
            input_schema={"type": "object", "properties": {}},
            replace=True,
        )
        self.registry.register(
            "health",
            self._tool_health,
            Scope.READ,
            description="Liveness + readiness of this access node.",
            input_schema={"type": "object", "properties": {}},
            replace=True,
        )

    def _tool_node_info(self, _arguments: dict, ctx: ToolContext) -> dict:
        cfg = ctx.config
        return {
            "node": cfg.node_name,
            "fqid": cfg.node_fqid,
            "hostname": socket.gethostname(),
            "bind_host": cfg.host,
            "bind_port": cfg.port,
            "public_bind": False if not cfg.allow_public else True,
            "exposed_roots": [str(p) for p in cfg.exposed_roots],
            "tools": [
                {"name": t.name, "scope": t.scope.value, "description": t.description}
                for t in self.registry.all()
            ],
            "security": {
                "tailnet_only": not cfg.allow_public,
                "capauth_gated": not cfg.dev_bypass,
                "dev_bypass": cfg.dev_bypass,
                "sse_require_auth": cfg.sse_require_auth,
            },
        }

    def _tool_health(self, _arguments: dict, _ctx: ToolContext) -> dict:
        return {
            "status": "ok",
            "node": self.config.node_name,
            "tools": len(self.registry.names()),
            "keys_pinned": self.verifier.key_count,
        }

    # -- capauth gate -------------------------------------------------------

    def authenticate(self, token: Any) -> ToolContext:
        """Verify a capauth token and resolve the caller's scope context.

        The token is a :class:`~skcomms.envelope.SignedEnvelope` (object, dict,
        bytes, or JSON str). It is run through
        :func:`skcomms.federation.accept_signed` (signature + freshness +
        replay) against this server's TOFU-pinned verifier. The verified
        ``from_fqid`` maps to a granted scope set via config.

        In ``dev_bypass`` mode (OFF by default) verification is skipped and a
        local context with the configured wildcard scopes is returned.

        Args:
            token: The capauth-signed envelope (any accepted form).

        Returns:
            A :class:`ToolContext` for the verified caller.

        Raises:
            AccessAuthError: On unsigned / stale / replayed / untrusted token.
        """
        if self.config.dev_bypass:
            logger.warning("sk-access dev_bypass ON — capauth verification skipped")
            ident = self.config.node_fqid or self.config.node_name
            return ToolContext(
                identity=ident,
                fingerprint=None,
                scopes=self.config.granted_scopes(ident) | {Scope.READ, Scope.WRITE, Scope.EXEC},
                config=self.config,
                server=self,
            )

        signed = self._coerce_signed(token)
        try:
            env = fed.accept_signed(
                signed, verifier=self.verifier, nonce_cache=self.nonce_cache
            )
        except fed.FederationError as exc:
            raise AccessAuthError(str(exc)) from exc

        scopes = self.config.granted_scopes(env.from_fqid)
        return ToolContext(
            identity=env.from_fqid,
            fingerprint=signed.signer_fingerprint or None,
            scopes=scopes,
            config=self.config,
            server=self,
        )

    def authenticate_session(self, token: Any) -> ToolContext:
        """Authenticate an MCP **session** (the /sse handshake hook, A6/F1).

        An MCP client opening an /sse session presents a capauth-signed *hello*
        (a :class:`SignedEnvelope`, same form as the per-call token; its body may
        carry ``{"hello": ...}`` — the signature is what matters). This binds the
        whole session to the verified identity, and every tool call on that
        session is then scope-checked against THAT identity — not a blanket
        node-local grant.

        Behaviour is governed by ``config.sse_require_auth``:

        * **ON (prod default):** a missing/unsigned/untrusted hello raises
          :class:`AccessAuthError`. The session is bound to the verified fqid +
          its granted scopes.
        * **OFF (loopback/dev):** if no token is presented, fall back to a
          node-local context (the node's own granted scopes ∪ READ), preserving
          the old "tailnet-trusted" behaviour for local dev. A *presented* token
          is still verified even when auth isn't required.

        Args:
            token: The signed hello envelope, or ``None`` (dev fallback only).

        Returns:
            A :class:`ToolContext` bound to the session identity.

        Raises:
            AccessAuthError: When auth is required and the hello is
                missing/unsigned/untrusted.
        """
        if token is None or token == "":
            if self.config.sse_require_auth and not self.config.dev_bypass:
                raise AccessAuthError(
                    "sse session requires a capauth-signed hello "
                    "(sse_require_auth is ON)"
                )
            # Dev/loopback fallback: node-local trusted session.
            ident = self.config.node_fqid or self.config.node_name
            return ToolContext(
                identity=ident,
                fingerprint=None,
                scopes=self.config.granted_scopes(ident) | {Scope.READ},
                config=self.config,
                server=self,
            )
        # A hello was presented — verify it (even if auth wasn't required).
        return self.authenticate(token)

    @staticmethod
    def _coerce_signed(token: Any) -> SignedEnvelope:
        """Normalize a token into a :class:`SignedEnvelope`."""
        if isinstance(token, SignedEnvelope):
            return token
        if isinstance(token, (bytes, bytearray)):
            return SignedEnvelope.from_bytes(bytes(token))
        if isinstance(token, str):
            return SignedEnvelope.from_bytes(token.encode("utf-8"))
        if isinstance(token, dict):
            return SignedEnvelope.model_validate(token)
        raise AccessAuthError(f"unrecognized capauth token type: {type(token).__name__}")

    # -- dispatch -----------------------------------------------------------

    async def call_tool(
        self, token: Any, name: str, arguments: Optional[dict] = None,
        *, transport: str = "tool",
    ) -> Any:
        """Authenticate, enforce scope, then invoke a registered tool.

        Args:
            token: The capauth-signed token (envelope) authorizing the call.
            name: Registered tool name.
            arguments: Tool arguments.
            transport: Audit label for the calling path (``"tool"`` | ``"sse"``).

        Returns:
            The tool's JSON-serialisable result.

        Raises:
            AccessAuthError: Caller not verified/trusted.
            AccessScopeError: Caller lacks the tool's required scope.
            ToolNotFoundError: No such tool.
        """
        try:
            ctx = self.authenticate(token)
        except AccessAuthError:
            self.audit.record(
                transport=transport, identity=None, tool=name, scope=None,
                decision="deny", reason="auth",
            )
            raise
        return await self.call_tool_with_ctx(ctx, name, arguments, transport=transport)

    async def call_tool_with_ctx(
        self, ctx: ToolContext, name: str, arguments: Optional[dict] = None,
        *, transport: str = "tool",
    ) -> Any:
        """Dispatch when the caller is already authenticated.

        Used by the MCP/SSE transport which authenticates once per session.
        Every decision (allow / scope-deny / not-found) is audit-logged.
        """
        tool: Optional[RegisteredTool] = self.registry.get(name)
        if tool is None:
            self.audit.record(
                transport=transport, identity=ctx.identity, fingerprint=ctx.fingerprint,
                tool=name, scope=None, decision="deny", reason="not_found",
            )
            raise ToolNotFoundError(f"unknown tool: {name}")
        if not ctx.has_scope(tool.scope):
            self.audit.record(
                transport=transport, identity=ctx.identity, fingerprint=ctx.fingerprint,
                tool=name, scope=tool.scope.value, decision="deny", reason="scope",
            )
            raise AccessScopeError(
                f"identity {ctx.identity!r} lacks scope {tool.scope.value!r} "
                f"for tool {name!r} (granted: {sorted(s.value for s in ctx.scopes)})"
            )
        logger.info(
            "access tool=%s scope=%s caller=%s", name, tool.scope.value, ctx.identity
        )
        self.audit.record(
            transport=transport, identity=ctx.identity, fingerprint=ctx.fingerprint,
            tool=name, scope=tool.scope.value, decision="allow",
        )
        return await tool.invoke(arguments or {}, ctx)

    # -- skos registration (best-effort) ------------------------------------

    def register_with_skos(self) -> bool:
        """Advertise this node's access MCP endpoint to skos (best-effort).

        Tries the skos service registry if importable; otherwise drops a
        local advertisement YAML under the skcomms home so peers/skos can
        discover the endpoint. Never raises — registration is non-critical.

        Returns:
            True if some advertisement succeeded.
        """
        endpoint = f"http://{self.config.host}:{self.config.port}/sse"
        advert = {
            "service": "sk-access",
            "node": self.config.node_name,
            "fqid": self.config.node_fqid,
            "endpoint": endpoint,
            "transport": "mcp-sse",
            "scopes": ["read", "write", "exec"],
            "tools": self.registry.names(),
        }
        try:  # skos service registry, if present
            import skos  # type: ignore

            register = getattr(skos, "register_service", None)
            if callable(register):
                register(advert)
                logger.info("registered sk-access with skos: %s", endpoint)
                return True
        except Exception as exc:
            logger.debug("skos service registry unavailable: %s", exc)

        # Fallback: write a local advert file for discovery.
        try:
            from pathlib import Path

            import yaml

            from ..config import SKCOMMS_HOME

            advert_dir = Path(SKCOMMS_HOME).expanduser() / "access"
            advert_dir.mkdir(parents=True, exist_ok=True)
            (advert_dir / "advert.yml").write_text(yaml.safe_dump(advert, sort_keys=False))
            logger.info("wrote local sk-access advert: %s", advert_dir / "advert.yml")
            return True
        except Exception as exc:  # pragma: no cover - fs failure
            logger.debug("local advert write failed: %s", exc)
            return False


# ---------------------------------------------------------------------------
# FastAPI app (MCP over SSE on the tailnet)
# ---------------------------------------------------------------------------


def build_app(server: Optional[AccessServer] = None):
    """Build the FastAPI app wrapping the access server.

    Exposes:
        * ``GET  /health``     — unauthenticated liveness (no tool dispatch).
        * ``GET  /node_info``  — unauthenticated node descriptor (no secrets).
        * ``POST /tool``       — capauth-gated tool call seam (token in body or
          ``Authorization: Bearer <signed-envelope-json>``). A3/A4 tools are
          reachable here once registered.
        * ``GET  /sse`` + ``POST /messages`` — the MCP SSE transport mount,
          where MCP clients (Claude Code, Lumina) speak the protocol.

    The app does NOT itself choose a bind address — the caller passes
    ``server.config.host`` to uvicorn. :meth:`AccessConfig.validate` is invoked
    here so importing/serving with a public bind fails fast.

    Args:
        server: An :class:`AccessServer` (default: a freshly loaded one).

    Returns:
        A configured ``fastapi.FastAPI`` instance.
    """
    from fastapi import Body, FastAPI, Header, HTTPException, Request  # noqa: F401

    srv = server or AccessServer()
    srv.config.validate()  # refuse public binds at app-build time

    app = FastAPI(title="sk-access", version="0.1.0")
    app.state.access_server = srv

    @app.get("/health", tags=["health"])
    async def _health():
        return srv._tool_health({}, None)  # type: ignore[arg-type]

    @app.get("/node_info", tags=["node"])
    async def _node_info():
        # Unauthenticated descriptor: uses a read-only synthetic ctx.
        ctx = ToolContext(
            identity=None,
            fingerprint=None,
            scopes={Scope.READ},
            config=srv.config,
            server=srv,
        )
        return srv._tool_node_info({}, ctx)

    @app.post("/tool", tags=["access"])
    async def _tool(body: dict = Body(...), authorization: Optional[str] = Header(default=None)):
        # body via Body(...) not Request: under `from __future__ import annotations`
        # FastAPI can't resolve the local-only `Request` annotation (it lives in the
        # module namespace), which mis-binds it as a query param (422). `dict` resolves.
        token = body.get("token")
        if token is None and authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:]
        if token is None:
            raise HTTPException(status_code=401, detail="missing capauth token")
        name = body.get("tool") or body.get("name")
        if not name:
            raise HTTPException(status_code=400, detail="missing tool name")
        arguments = body.get("arguments") or {}
        try:
            result = await srv.call_tool(token, name, arguments)
        except AccessAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except AccessScopeError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ToolNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"ok": True, "result": result}

    _mount_mcp_sse(app, srv)
    return app


def _extract_sse_hello(request) -> Any:
    """Pull a capauth-signed hello token off an /sse connect request.

    Looked for, in order:
      1. ``Authorization: Bearer <signed-envelope-json>`` header,
      2. ``X-Capauth-Hello`` header,
      3. ``?hello=<...>`` query parameter (for clients that can't set headers).

    Returns the raw token string, or ``None`` if none present.
    """
    try:
        headers = request.headers
        auth = headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:]
        hello = headers.get("x-capauth-hello")
        if hello:
            return hello
        q = request.query_params.get("hello")
        if q:
            return q
    except Exception as exc:  # pragma: no cover - exotic request object
        logger.debug("sse hello extraction failed: %s", exc)
    return None


def _mount_mcp_sse(app, srv: AccessServer) -> None:
    """Mount the MCP SSE transport, exposing registered tools to MCP clients.

    Per-session identity (A6/F1): an /sse session is authenticated **once at
    connect time** via :meth:`AccessServer.authenticate_session`, which requires
    a capauth-signed hello when ``config.sse_require_auth`` is ON (prod default)
    and falls back to a node-local context only for loopback/dev when it is OFF.
    Every tool call on the session is then scope-checked against THAT verified
    identity (not a blanket node-local grant) and audit-logged with
    ``transport="sse"``.

    The hello rides the connect request (``Authorization: Bearer``,
    ``X-Capauth-Hello`` header, or ``?hello=`` query param — see
    :func:`_extract_sse_hello`). If auth is required and absent/invalid, the
    connection is refused 401 before the MCP protocol starts.
    """
    try:
        from mcp.server import Server as MCPServer
        from mcp.server.sse import SseServerTransport
        from mcp.types import TextContent, Tool
        from starlette.responses import JSONResponse
        from starlette.routing import Mount, Route
    except Exception as exc:  # pragma: no cover - mcp missing
        logger.warning("MCP SSE deps unavailable, /sse not mounted: %s", exc)
        return

    mcp = MCPServer("sk-access")

    # The session ctx is resolved per-connection in _handle_sse and stashed
    # here so the (process-global) MCP call handler can read it. MCP runs one
    # session per connection within this coroutine, so a contextvar keeps
    # concurrent sessions isolated.
    import contextvars

    _session_ctx: "contextvars.ContextVar[Optional[ToolContext]]" = contextvars.ContextVar(
        "sk_access_session_ctx", default=None
    )

    @mcp.list_tools()
    async def _list_tools() -> list:
        return [
            Tool(
                name=t.name,
                description=f"[{t.scope.value}] {t.description}",
                inputSchema=t.input_schema,
            )
            for t in srv.registry.all()
        ]

    @mcp.call_tool()
    async def _call(name: str, arguments: dict) -> list:
        ctx = _session_ctx.get()
        if ctx is None:  # pragma: no cover - connect always sets it
            return [TextContent(type="text", text=json.dumps({"error": "no session identity"}))]
        try:
            result = await srv.call_tool_with_ctx(ctx, name, arguments, transport="sse")
        except AccessError as exc:
            return [TextContent(type="text", text=json.dumps({"error": str(exc)}))]
        return [TextContent(type="text", text=json.dumps(result, default=str))]

    transport = SseServerTransport("/messages/")

    async def _handle_sse(request):
        # Authenticate the SESSION before the MCP protocol starts.
        token = _extract_sse_hello(request)
        try:
            ctx = srv.authenticate_session(token)
        except AccessAuthError as exc:
            srv.audit.record(
                transport="sse", identity=None, tool="<session>", scope=None,
                decision="deny", reason="auth",
            )
            return JSONResponse({"error": str(exc)}, status_code=401)
        _session_ctx.set(ctx)
        logger.info("sse session bound to identity=%s", ctx.identity)
        async with transport.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await mcp.run(read_stream, write_stream, mcp.create_initialization_options())

    app.router.routes.append(Route("/sse", endpoint=_handle_sse))
    app.router.routes.append(Mount("/messages/", app=transport.handle_post_message))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the sk-access server on the tailnet interface.

    Refuses a public bind unless ``allow_public`` / ``SK_ACCESS_ALLOW_PUBLIC``
    is set. Best-effort skos registration runs after the app is built.
    """
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    import uvicorn

    srv = AccessServer()
    from .exec import register_builtin_exec_tools
    from .wiring import register_builtin_tools
    tools = register_builtin_tools(registry=srv.registry)
    # exec tools register too, but are exec-scope (denied unless explicitly granted).
    tools += register_builtin_exec_tools(registry=srv.registry)
    logger.info("sk-access registered %d tools: %s", len(tools), ", ".join(tools))
    app = build_app(srv)
    srv.register_with_skos()
    logger.info(
        "sk-access serving on %s:%d (tailnet-only=%s, capauth=%s)",
        srv.config.host,
        srv.config.port,
        not srv.config.allow_public,
        not srv.config.dev_bypass,
    )
    uvicorn.run(app, host=srv.config.host, port=srv.config.port, log_level="info")


if __name__ == "__main__":
    main()
