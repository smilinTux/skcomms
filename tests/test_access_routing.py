"""Tests for skcomms.access.routing — SKFed P7 / A5 federation routing.

Covers:
  * node -> base-URL resolution (peer-store access/tailscale transports, aliases,
    raw host/url passthrough, dotted-node-id, and unknown-node error);
  * ``is_local`` / ``local_node`` (None/self stays local);
  * a LOCAL routing wrapper call hits the in-process A4 file tool with NO network;
  * a REMOTE call capauth-signs an envelope and POSTs it to the right peer URL
    (HTTP + signer mocked) — and the peer's own AccessServer gate accepts the
    signed token (real signature round-trip via the TOFU verifier);
  * ``fetch_located`` routes by ``hit["node"]`` (local hit local, remote hit routed);
  * a remote HTTP error surfaces as RemoteAccessError.

capauth keys are generated in-process with pgpy (same pattern as
tests/test_access_server.py / tests/test_federation.py).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from skcomms.access import routing
from skcomms.access.config import AccessConfig
from skcomms.access.routing import (
    NodeNotFoundError,
    NodeResolver,
    RemoteAccessError,
    call_remote,
    fetch_located,
    routed_file_read,
)
from skcomms.discovery import PeerInfo, PeerStore, PeerTransport
from skcomms.signing import EnvelopeSigner


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
def caller_keys():
    return _gen_key("caller <lumina@chef.skworld>")


# --- a peer store backed by a tmp dir --------------------------------------


@pytest.fixture
def peer_store(tmp_path):
    store = PeerStore(peers_dir=tmp_path / "peers")
    # node .41 reachable via an explicit `access` transport (port-aware).
    store.add(
        PeerInfo(
            name="jarvis",
            fqid="jarvis@chef.skworld",
            transports=[
                PeerTransport(
                    transport="access",
                    settings={"node": ".41", "host": "100.64.0.41", "port": 9386},
                ),
            ],
        )
    )
    # node .100 reachable only via a tailscale transport (default access port).
    store.add(
        PeerInfo(
            name="comfy",
            fqid="comfy@chef.skworld",
            transports=[
                PeerTransport(transport="tailscale", settings={"tailscale_ip": "100.64.0.100"}),
            ],
        )
    )
    return store


@pytest.fixture
def resolver(peer_store):
    cfg = AccessConfig(node_name=".158", node_fqid="lumina@chef.skworld", port=9386)
    return NodeResolver(config=cfg, peer_store=peer_store)


# --- node resolution -------------------------------------------------------


def test_resolve_access_transport(resolver):
    assert resolver.resolve(".41") == "http://100.64.0.41:9386"
    assert resolver.resolve("jarvis@chef.skworld") == "http://100.64.0.41:9386"
    assert resolver.resolve("jarvis") == "http://100.64.0.41:9386"


def test_resolve_tailscale_fallback(resolver):
    # No `access` transport -> falls back to tailscale_ip on the default port.
    assert resolver.resolve("comfy") == "http://100.64.0.100:9386"
    assert resolver.resolve("comfy@chef.skworld") == "http://100.64.0.100:9386"


def test_resolve_raw_host_and_url(resolver):
    assert resolver.resolve("100.64.0.7") == "http://100.64.0.7:9386"
    assert resolver.resolve("100.64.0.7:1234") == "http://100.64.0.7:1234"
    assert resolver.resolve("http://node.ts.net:9000") == "http://node.ts.net:9000"


def test_resolve_alias_wins(peer_store):
    cfg = AccessConfig(node_name=".158", port=9386)
    res = NodeResolver(config=cfg, peer_store=peer_store, node_aliases={".41": "10.9.9.9:7"})
    assert res.resolve(".41") == "http://10.9.9.9:7"


def test_resolve_unknown_node_errors(resolver):
    with pytest.raises(NodeNotFoundError):
        resolver.resolve(".999")
    with pytest.raises(NodeNotFoundError):
        resolver.resolve("nope@chef.skworld")


# --- local / self ----------------------------------------------------------


def test_is_local(resolver):
    assert resolver.is_local(None) is True
    assert resolver.is_local("") is True
    assert resolver.is_local(".158") is True
    assert resolver.is_local("lumina@chef.skworld") is True
    assert resolver.is_local(".41") is False


# --- local call stays local (no network) -----------------------------------


def test_routed_read_local_no_network(resolver, monkeypatch, tmp_path):
    # The local file tool is exercised directly; call_remote MUST NOT fire.
    f = tmp_path / "hi.txt"
    f.write_text("local-bytes")

    called = {"local": 0, "remote": 0}

    def _local_read(path):
        called["local"] += 1
        return {"path": path, "content": "local-bytes"}

    monkeypatch.setattr(routing.files_mod, "file_read", _local_read)
    monkeypatch.setattr(
        routing, "call_remote",
        lambda *a, **k: called.__setitem__("remote", called["remote"] + 1),
    )

    out = routed_file_read(str(f), None, resolver=resolver)
    assert out["content"] == "local-bytes"
    assert called == {"local": 1, "remote": 0}

    # node == self id also stays local
    routed_file_read(str(f), ".158", resolver=resolver)
    assert called["remote"] == 0


# --- remote call signs + posts to the right URL ----------------------------


def test_remote_call_signs_and_posts(resolver, caller_keys, monkeypatch):
    priv, _pub = caller_keys
    posted = {}

    # Inject our in-process signing key.
    monkeypatch.setattr(routing, "_load_signer", lambda agent: EnvelopeSigner(priv))
    # Make self-identity deterministic (no capauth install needed).
    monkeypatch.setattr(
        routing, "resolve_self_identity",
        lambda agent=None: {"agent": "lumina", "fqid": "lumina@chef.skworld"},
    )

    def _fake_post(base_url, signed_bytes, *, timeout):
        posted["url"] = base_url
        posted["signed"] = json.loads(signed_bytes.decode("utf-8"))
        return {"ok": True, "remote": True}

    monkeypatch.setattr(routing, "_post_tool", _fake_post)

    out = call_remote(".41", "file_read", {"path": "/home/x/y.py"}, resolver=resolver)

    assert posted["url"] == "http://100.64.0.41:9386"
    env = posted["signed"]["envelope"]
    assert env["from_fqid"] == "lumina@chef.skworld"
    assert posted["signed"]["signature"]  # actually signed
    body = json.loads(env["body"])
    assert body == {"tool": "file_read", "arguments": {"path": "/home/x/y.py"}}
    assert out == {"ok": True, "remote": True}


def test_remote_call_accepted_by_peer_gate(resolver, caller_keys, monkeypatch):
    """End-to-end: the signed envelope this side produces is accepted by a real
    AccessServer's capauth gate (TOFU pin of the caller's pubkey)."""
    from skcomms.access.registry import AccessRegistry, Scope
    from skcomms.access.server import AccessServer

    priv, pub = caller_keys
    monkeypatch.setattr(routing, "_load_signer", lambda agent: EnvelopeSigner(priv))
    monkeypatch.setattr(
        routing, "resolve_self_identity",
        lambda agent=None: {"agent": "lumina", "fqid": "lumina@chef.skworld"},
    )

    # A peer-side server that grants the caller read scope + a dummy file_read.
    peer_cfg = AccessConfig(
        node_name=".41", port=9386,
        scope_grants={"lumina@chef.skworld": {Scope.READ}},
    )
    peer_reg = AccessRegistry()
    srv = AccessServer(config=peer_cfg, registry=peer_reg, peer_store=PeerStore(peers_dir=resolver.peer_store.peers_dir))
    srv.trust_key("lumina@chef.skworld", pub)
    srv.registry.register(
        "file_read", lambda args, ctx: {"path": args["path"], "served_by": ".41"},
        Scope.READ, replace=True,
    )

    captured = {}

    def _capture_post(base_url, signed_bytes, *, timeout):
        captured["bytes"] = signed_bytes
        signed_obj = json.loads(signed_bytes.decode("utf-8"))
        inner = json.loads(signed_obj["envelope"]["body"])
        # Run it through the REAL server gate, just like the /tool endpoint.
        result = asyncio.run(
            srv.call_tool(signed_obj, inner["tool"], inner.get("arguments", {}))
        )
        # Mirror _post_tool's unwrap of the {"ok","result"} HTTP envelope.
        return result

    monkeypatch.setattr(routing, "_post_tool", _capture_post)

    out = call_remote(".41", "file_read", {"path": "/home/x/y.py"}, resolver=resolver)
    assert out == {"path": "/home/x/y.py", "served_by": ".41"}


# --- fetch_located routes by hit.node --------------------------------------


def test_fetch_located_routes_by_node(resolver, monkeypatch):
    routed = {}

    def _fake_remote(node, tool, arguments, **kw):
        routed["node"] = node
        routed["tool"] = tool
        routed["args"] = arguments
        return {"path": arguments["path"], "served_by": node}

    monkeypatch.setattr(routing, "call_remote", _fake_remote)

    # remote hit -> routes to that node
    hit = {"node": ".41", "path": "/home/x/enroll.py", "score": 0.9}
    out = fetch_located(hit, resolver=resolver)
    assert routed == {"node": ".41", "tool": "file_read", "args": {"path": "/home/x/enroll.py"}}
    assert out["served_by"] == ".41"


def test_fetch_located_local_hit_no_network(resolver, monkeypatch):
    calls = {"local": 0, "remote": 0}
    monkeypatch.setattr(
        routing.files_mod, "file_read",
        lambda path: calls.__setitem__("local", calls["local"] + 1) or {"path": path},
    )
    monkeypatch.setattr(
        routing, "call_remote",
        lambda *a, **k: calls.__setitem__("remote", calls["remote"] + 1),
    )
    # local node id -> stays local
    fetch_located({"node": ".158", "path": "/home/clawd/a.md"}, resolver=resolver)
    # no node -> local
    fetch_located({"path": "/home/clawd/b.md"}, resolver=resolver)
    assert calls == {"local": 2, "remote": 0}


def test_fetch_located_requires_path(resolver):
    with pytest.raises(routing.RoutingError):
        fetch_located({"node": ".41"}, resolver=resolver)


# --- remote HTTP error surfaces as RemoteAccessError -----------------------


def test_remote_http_error(resolver, caller_keys, monkeypatch):
    import urllib.error

    priv, _pub = caller_keys
    monkeypatch.setattr(routing, "_load_signer", lambda agent: EnvelopeSigner(priv))
    monkeypatch.setattr(
        routing, "resolve_self_identity",
        lambda agent=None: {"agent": "lumina", "fqid": "lumina@chef.skworld"},
    )

    class _Err(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("http://x/tool", 403, "Forbidden", {}, None)

        def read(self):
            return json.dumps({"detail": "scope denied"}).encode()

    def _boom(url, data=None, timeout=None):
        raise _Err()

    monkeypatch.setattr(routing, "_post_tool", routing._post_tool)  # use real
    monkeypatch.setattr("urllib.request.urlopen", _boom)

    with pytest.raises(RemoteAccessError) as ei:
        call_remote(".41", "file_write", {"path": "/x", "content": "z"}, resolver=resolver)
    assert ei.value.status == 403
    assert "scope denied" in (ei.value.detail or "")
