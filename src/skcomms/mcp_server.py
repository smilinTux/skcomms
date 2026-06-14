"""
SKComms MCP Server — expose messaging tools to AI agents via Model Context Protocol.

Tool-agnostic: works with Cursor, Claude Code CLI, Claude Desktop,
Windsurf, Aider, Cline, or any MCP client that speaks stdio.

Tools:
    send_message      — Send a P2P message via SKComms
    receive_messages  — Check inbox for new messages
    get_peers         — List known peers and their online status
    get_status        — Get SKComms daemon health
    update_presence   — Set this node's presence state

Invocation (all equivalent):
    python -m skcomms.mcp_server          # direct module
    bash skcomms/scripts/mcp-serve.sh     # portable launcher

Client configuration — use the launcher script for all clients:

    Cursor (.cursor/mcp.json):
        {"mcpServers": {"skcomms": {
            "command": "bash", "args": ["skcomms/scripts/mcp-serve.sh"]}}}

    Claude Code CLI (.mcp.json at repo root, or `claude mcp add`):
        {"mcpServers": {"skcomms": {
            "command": "bash", "args": ["skcomms/scripts/mcp-serve.sh"]}}}

    Claude Desktop:
        {"mcpServers": {"skcomms": {
            "command": "bash",
            "args": ["/absolute/path/to/skcomms/scripts/mcp-serve.sh"]}}}
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logger = logging.getLogger("skcomms.mcp")

server = Server("skcomms")

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

_DEFAULT_PORT = 9384
_CONFIG_PATH = Path("~/.skcomms/config.yaml")
_CONFIG_PATH_ALT = Path("~/.skcomms/config.yml")


def _load_api_port() -> int:
    """Discover the SKComms API port from config or return the default.

    Checks ~/.skcomms/config.yaml (and .yml) for an ``api.port`` key.
    Falls back to 9384 if the config is absent or the key is missing.

    Returns:
        int: The configured or default API port.
    """
    for candidate in (_CONFIG_PATH, _CONFIG_PATH_ALT):
        path = candidate.expanduser()
        if path.exists():
            try:
                raw = yaml.safe_load(path.read_text()) or {}
                skcomms = raw.get("skcomms", raw)
                return int(skcomms.get("api", {}).get("port", _DEFAULT_PORT))
            except Exception as e:
                logger.warning("mcp_server.py: %s", e)
                pass
    return _DEFAULT_PORT


def _api_base() -> str:
    """Return the base URL for the local SKComms daemon REST API.

    Returns:
        str: Base URL, e.g. ``http://127.0.0.1:9384``.
    """
    return f"http://127.0.0.1:{_load_api_port()}"


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _json_response(data: Any) -> list[TextContent]:
    """Wrap data as a JSON TextContent response.

    Args:
        data (Any): Serialisable data to return.

    Returns:
        list[TextContent]: Single-element list with JSON text.
    """
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def _error_response(message: str) -> list[TextContent]:
    """Return an error message as a JSON TextContent response.

    Args:
        message (str): Human-readable error description.

    Returns:
        list[TextContent]: Single-element list with ``{"error": ...}`` JSON.
    """
    return [TextContent(type="text", text=json.dumps({"error": message}))]


# ---------------------------------------------------------------------------
# HTTP client helper
# ---------------------------------------------------------------------------


async def _get(path: str, params: Optional[dict] = None) -> dict | list:
    """Perform a GET request against the local SKComms daemon.

    Args:
        path (str): URL path, e.g. ``/api/v1/status``.
        params (dict | None): Optional query parameters.

    Returns:
        dict | list: Parsed JSON response body.

    Raises:
        httpx.HTTPError: On network or HTTP error.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{_api_base()}{path}", params=params)
        resp.raise_for_status()
        return resp.json()


async def _post(path: str, body: dict) -> dict | list:
    """Perform a POST request against the local SKComms daemon.

    Args:
        path (str): URL path, e.g. ``/api/v1/send``.
        body (dict): JSON-serialisable request body.

    Returns:
        dict | list: Parsed JSON response body.

    Raises:
        httpx.HTTPError: On network or HTTP error.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{_api_base()}{path}", json=body)
        resp.raise_for_status()
        return resp.json()


# ═══════════════════════════════════════════════════════════
# Tool Definitions
# ═══════════════════════════════════════════════════════════


@server.list_tools()
async def list_tools() -> list[Tool]:
    """Register all SKComms tools with the MCP server."""
    return [
        Tool(
            name="send_message",
            description=(
                "Send a P2P message to another agent via SKComms. "
                "Routes through available transports (Syncthing, file, Nostr). "
                "Returns delivery status and the assigned envelope ID."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "to": {
                        "type": "string",
                        "description": "Peer ID, agent name, or PGP fingerprint of the recipient",
                    },
                    "content": {
                        "type": "string",
                        "description": "Message text to send",
                    },
                    "urgency": {
                        "type": "string",
                        "enum": ["low", "normal", "high"],
                        "description": "Message urgency level (default: normal)",
                    },
                },
                "required": ["to", "content"],
            },
        ),
        Tool(
            name="receive_messages",
            description=(
                "Check inbox for new incoming messages across all SKComms transports. "
                "Optionally filter by sender peer ID and cap the result count."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "from_peer": {
                        "type": "string",
                        "description": "Optional: return only messages from this peer ID",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of messages to return (default: 10)",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="get_peers",
            description=(
                "List all known peers and their last-seen time. "
                "Returns peer IDs with transport addresses and discovery metadata."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="get_status",
            description=(
                "Get the health of the local SKComms daemon: identity, "
                "transport statuses, encryption state, and message counts."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="update_presence",
            description=(
                "Set this node's presence state so peers can see availability. "
                "Broadcasts the update across connected transports."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["online", "away", "busy", "dnd"],
                        "description": "Presence status to broadcast",
                    },
                },
                "required": ["status"],
            },
        ),
    ]


# ═══════════════════════════════════════════════════════════
# Tool Dispatch
# ═══════════════════════════════════════════════════════════


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Dispatch tool calls to the appropriate handler.

    Args:
        name (str): Tool name as registered in list_tools.
        arguments (dict): Tool input arguments from the MCP client.

    Returns:
        list[TextContent]: JSON or error response.
    """
    handlers = {
        "send_message": _handle_send_message,
        "receive_messages": _handle_receive_messages,
        "get_peers": _handle_get_peers,
        "get_status": _handle_get_status,
        "update_presence": _handle_update_presence,
    }
    handler = handlers.get(name)
    if handler is None:
        return _error_response(f"Unknown tool: {name}")
    try:
        return await handler(arguments)
    except Exception as exc:
        logger.exception("Tool '%s' failed", name)
        return _error_response(f"{name} failed: {exc}")


# ═══════════════════════════════════════════════════════════
# Tool Handlers
# ═══════════════════════════════════════════════════════════


async def _handle_send_message(args: dict) -> list[TextContent]:
    """Send a P2P message via the SKComms daemon REST API.

    Args:
        args (dict): Must contain ``to`` and ``content``; optionally ``urgency``.

    Returns:
        list[TextContent]: Delivery status with envelope ID and transport used.
    """
    to = args.get("to", "").strip()
    content = args.get("content", "").strip()
    urgency = args.get("urgency", "normal")

    if not to:
        return _error_response("'to' (recipient peer ID) is required")
    if not content:
        return _error_response("'content' (message text) is required")

    valid_urgencies = {"low", "normal", "high"}
    if urgency not in valid_urgencies:
        urgency = "normal"

    try:
        result = await _post(
            "/api/v1/send",
            {"recipient": to, "message": content, "urgency": urgency},
        )
        return _json_response(
            {
                "delivered": result.get("delivered", False),
                "envelope_id": result.get("envelope_id", ""),
                "transport_used": result.get("transport_used"),
                "attempts": result.get("attempts", []),
            }
        )
    except httpx.ConnectError:
        return _error_response(
            f"Cannot reach SKComms daemon at {_api_base()}. Is it running? Start with: skcomms serve"
        )
    except httpx.HTTPStatusError as exc:
        return _error_response(f"SKComms API error {exc.response.status_code}: {exc.response.text}")


async def _handle_receive_messages(args: dict) -> list[TextContent]:
    """Check inbox for new messages via the SKComms daemon REST API.

    Args:
        args (dict): Optionally contains ``from_peer`` (str) and ``limit`` (int).

    Returns:
        list[TextContent]: List of message objects with sender, content, timestamp.
    """
    from_peer: Optional[str] = args.get("from_peer")
    limit: int = int(args.get("limit", 10))

    try:
        envelopes: list = await _get("/api/v1/inbox")
    except httpx.ConnectError:
        return _error_response(
            f"Cannot reach SKComms daemon at {_api_base()}. Is it running? Start with: skcomms serve"
        )
    except httpx.HTTPStatusError as exc:
        return _error_response(f"SKComms API error {exc.response.status_code}: {exc.response.text}")

    messages = []
    for env in envelopes:
        sender = env.get("sender", "")
        # Skip ACK envelopes — they are delivery receipts, not real messages
        if env.get("is_ack"):
            continue
        if from_peer and sender != from_peer:
            continue
        messages.append(
            {
                "envelope_id": env.get("envelope_id", "")[:12],
                "sender": sender,
                "content": env.get("content", ""),
                "urgency": env.get("urgency", "normal"),
                "thread_id": env.get("thread_id"),
                "created_at": env.get("created_at", ""),
            }
        )
        if len(messages) >= limit:
            break

    return _json_response({"count": len(messages), "messages": messages})


async def _handle_get_peers(_args: dict) -> list[TextContent]:
    """List known peers from the SKComms peer directory.

    Args:
        _args (dict): Unused; no parameters required.

    Returns:
        list[TextContent]: List of peer objects with ID and last-seen time.
    """
    try:
        peers: list = await _get("/api/v1/peers")
    except httpx.ConnectError:
        return _error_response(
            f"Cannot reach SKComms daemon at {_api_base()}. Is it running? Start with: skcomms serve"
        )
    except httpx.HTTPStatusError as exc:
        return _error_response(f"SKComms API error {exc.response.status_code}: {exc.response.text}")

    peer_list = [
        {
            "peer_id": p.get("name", ""),
            "fingerprint": p.get("fingerprint"),
            "nostr_pubkey": p.get("nostr_pubkey"),
            "transports": [t.get("transport") for t in p.get("transports", [])],
            "discovered_via": p.get("discovered_via", ""),
            "last_seen": p.get("last_seen"),
        }
        for p in peers
    ]
    return _json_response({"count": len(peer_list), "peers": peer_list})


async def _handle_get_status(_args: dict) -> list[TextContent]:
    """Get the SKComms daemon health status.

    Args:
        _args (dict): Unused; no parameters required.

    Returns:
        list[TextContent]: Daemon status dict with identity, transports, crypto.
    """
    try:
        status = await _get("/api/v1/status")
    except httpx.ConnectError:
        return _json_response(
            {
                "daemon": "offline",
                "error": (
                    f"Cannot reach SKComms daemon at {_api_base()}. Start with: skcomms serve"
                ),
            }
        )
    except httpx.HTTPStatusError as exc:
        return _error_response(f"SKComms API error {exc.response.status_code}: {exc.response.text}")

    return _json_response(status)


async def _handle_update_presence(args: dict) -> list[TextContent]:
    """Set this node's presence state via the SKComms daemon REST API.

    Args:
        args (dict): Must contain ``status`` — one of online/away/busy/dnd.

    Returns:
        list[TextContent]: Confirmation with updated status and identity.
    """
    presence_status = args.get("status", "").strip()
    valid_statuses = {"online", "away", "busy", "dnd"}

    if not presence_status:
        return _error_response("'status' is required")
    if presence_status not in valid_statuses:
        return _error_response(
            f"Invalid status '{presence_status}'. Must be one of: "
            + ", ".join(sorted(valid_statuses))
        )

    try:
        result = await _post("/api/v1/presence", {"status": presence_status})
        return _json_response(
            {
                "updated": True,
                "status": result.get("status", presence_status),
                "identity": result.get("identity"),
                "updated_at": result.get("updated_at"),
            }
        )
    except httpx.ConnectError:
        return _error_response(
            f"Cannot reach SKComms daemon at {_api_base()}. Is it running? Start with: skcomms serve"
        )
    except httpx.HTTPStatusError as exc:
        return _error_response(f"SKComms API error {exc.response.status_code}: {exc.response.text}")


# ═══════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════


def main() -> None:
    """Run the SKComms MCP server on stdio transport."""
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    asyncio.run(_run_server())


async def _run_server() -> None:
    """Async entry point for the stdio MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    main()
