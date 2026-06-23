"""Capability / service-discovery document for an skcomms node.

A node advertises *which* transports and services it actually has **in this
deployment**.  Availability varies by config and access, so the document is
honest: status is derived from the loaded config + the live transport registry,
with a small set of cheap TCP probes for co-resident services (Nostr relay,
LiveKit SFU, sk-access plane, CoT/TAK service).

Status vocabulary
-----------------
``up``
    Configured/registered **and** confirmed reachable right now — either the
    transport's own ``health_check`` reports ``available`` (mapped to ``up``),
    or a cheap probe succeeded.
``configured``
    Present in this node's config / registry but liveness can't be cheaply or
    reliably determined.  We do **not** claim ``up`` we can't prove.
``degraded``
    Registered but its health check reports ``degraded``.
``down``
    Configured/registered but confirmed unreachable (health ``unavailable`` or
    a probe failed).
``unconfigured``
    Not part of this node's configuration at all.

Services (text, voice, video, file-transfer, data-streaming, federation,
access-plane, geo-cot) are **derived** from the status of the transports /
co-resident services they ride on — never asserted independently.

Public API:
    build_capabilities(skcomms=None, *, probe=True) -> dict
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

from .cluster import get_operator, get_realm

logger = logging.getLogger("skcomms.capabilities")

# Status constants — keep in sync with the app's status-dot mapping.
UP = "up"
CONFIGURED = "configured"
DEGRADED = "degraded"
DOWN = "down"
UNCONFIGURED = "unconfigured"

# Transport HealthStatus.status -> capability status.
_HEALTH_TO_STATUS = {
    "available": UP,
    "degraded": DEGRADED,
    "unavailable": DOWN,
}

# The full catalog of transports skcomms knows how to speak, with their honest
# wire protocol + supported roles. ``probe`` (host, port) is filled in for
# transports whose liveness can be cheaply checked at the TCP layer; ``None``
# means we fall back to registry/health-only derivation.
#
# Order here is the display order in the app.
_TRANSPORT_CATALOG: list[dict] = [
    {"id": "file", "protocol": "filesystem", "roles": ["send", "recv"]},
    {"id": "syncthing", "protocol": "syncthing", "roles": ["send", "recv"]},
    {
        "id": "https-s2s",
        "protocol": "https",
        "roles": ["send", "recv"],
        "aliases": ["http-s2s"],
    },
    {"id": "websocket", "protocol": "ws", "roles": ["send", "recv"]},
    {"id": "tailscale", "protocol": "wireguard", "roles": ["send", "recv"]},
    {
        "id": "webrtc",
        "protocol": "webrtc",
        "roles": ["send", "recv"],
        "media": ["audio", "video"],
    },
    {"id": "p2p", "protocol": "webrtc-datachannel", "roles": ["send", "recv"]},
    {"id": "ble-mesh", "protocol": "bluetooth-le", "roles": ["send", "recv"]},
    {"id": "lora", "protocol": "lora", "roles": ["send", "recv"]},
    {"id": "nostr", "protocol": "nostr", "roles": ["send", "recv"]},
]

# Co-resident SK services that back higher-level capabilities. These are NOT
# skcomms transports — they are sibling daemons we can cheaply probe so the
# node can honestly advertise voice/video/access-plane/geo availability.
# Only the PORT matters: many of these bind the node's tailnet IP (not
# loopback), so we probe loopback AND the detected tailnet IP (see
# _probe_hosts) and report up if EITHER accepts.
_SERVICE_PROBES: dict[str, int] = {
    "livekit": 7880,  # SFU — backs voice/video
    "nostr-relay": 7447,  # discovery relay — backs federation
    "sk-access": 9386,  # access plane
    "cot": 8087,  # CoT/TAK service — backs geo
}

# Transports whose rail is "up" when their broker/server infrastructure is
# reachable (like services): webrtc + websocket need the signaling broker to
# establish connections. If the broker is live, the rail is available even
# though this API process isn't holding an active peer connection.
_TRANSPORT_PROBES: dict[str, int] = {
    "webrtc": 9390,  # WebRTC signaling broker (skcomms-signaling-broker)
    "websocket": 9390,  # same broker also serves the ws rail
}


def _tailnet_ip() -> str | None:
    """Best-effort: this node's tailscale (100.64.0.0/10) IPv4, or None.

    Uses a connect-less UDP socket toward the tailscale MagicDNS address so the
    kernel picks the source IP it would use to reach the tailnet — no packets
    sent, no subprocess. Tailnet services bind this, not loopback.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("100.100.100.100", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip if ip.startswith("100.") else None
    except OSError:
        return None


def _probe_hosts() -> list[str]:
    """Candidate hosts for a service probe: loopback + the tailnet IP."""
    hosts = ["127.0.0.1"]
    tip = _tailnet_ip()
    if tip and tip not in hosts:
        hosts.append(tip)
    return hosts


def _tcp_probe(port: int, hosts: list[str] | None = None, timeout: float = 0.35) -> bool:
    """Return True iff a TCP connect to (host, port) succeeds on ANY candidate
    host (loopback or the tailnet IP — services may bind either).

    A cheap liveness signal — does not speak any protocol, just confirms a
    listener is accepting connections. Kept short so the endpoint stays snappy.
    """
    for host in (hosts or _probe_hosts()):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _registry_status(transport) -> str:
    """Map a registered transport's live health to a capability status."""
    try:
        health = transport.health_check()
        raw = getattr(health, "status", None)
        raw = getattr(raw, "value", raw)  # Enum -> str
        return _HEALTH_TO_STATUS.get(str(raw), CONFIGURED)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("health_check failed for %s: %s", getattr(transport, "name", "?"), exc)
        # Registered but we can't confirm liveness — report configured, not up.
        return CONFIGURED


def _rank(status: str) -> int:
    """Order statuses worst→best for service derivation (max = best)."""
    return {UNCONFIGURED: 0, DOWN: 1, CONFIGURED: 2, DEGRADED: 3, UP: 4}.get(status, 0)


def _best(*statuses: str) -> str:
    """Best (most-available) status among the inputs — for OR'd transports.

    A service that can ride any of several transports is as available as its
    best-available rail.
    """
    if not statuses:
        return UNCONFIGURED
    return max(statuses, key=_rank)


def build_capabilities(skcomms=None, *, probe: bool = True) -> dict:
    """Build the honest capability document for this node.

    Args:
        skcomms: An :class:`skcomms.core.SKComms` instance. When ``None`` one is
            constructed via ``SKComms.from_config()`` (best-effort; on failure a
            transport-less document is still returned).
        probe: When True, run cheap TCP probes for co-resident services
            (LiveKit/Nostr/sk-access/CoT) to upgrade ``configured`` → ``up`` /
            confirm ``down``. When False, no network/socket calls are made
            (registry/health only) — used by tests for determinism.

    Returns:
        A JSON-serialisable dict with ``node``, ``transports`` and ``services``.
    """
    comm = skcomms
    if comm is None:
        try:
            from .core import SKComms

            comm = SKComms.from_config()
        except Exception as exc:
            logger.debug("build_capabilities: SKComms.from_config failed: %s", exc)
            comm = None

    # ── node identity ──────────────────────────────────────────────────────
    fqid = None
    label = None
    try:
        from .identity import resolve_self_identity

        ident = resolve_self_identity()
        fqid = ident.get("fqid")
        label = ident.get("agent")
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("identity resolve failed: %s", exc)

    if comm is not None:
        label = label or comm.identity
        if not fqid:
            fqid = f"{comm.identity}@{get_operator()}.{get_realm()}"

    node = {
        "id": fqid or (f"{label}@{get_operator()}.{get_realm()}" if label else None),
        "label": label or "unknown",
        "host": socket.gethostname(),
    }

    # ── which transports are configured / registered ───────────────────────
    # config.transports: declared in this node's config.yml (may be disabled).
    configured_names: dict[str, bool] = {}
    if comm is not None:
        try:
            for name, tconf in comm._config.transports.items():
                configured_names[name] = bool(getattr(tconf, "enabled", True))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("reading configured transports failed: %s", exc)

    # registered transports: actually loaded into the router (live objects).
    registered: dict[str, object] = {}
    if comm is not None:
        try:
            for t in comm.router.transports:
                registered[t.name] = t
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("reading registered transports failed: %s", exc)

    def _name_variants(entry: dict) -> list[str]:
        return [entry["id"], *entry.get("aliases", [])]

    # ── transport statuses ─────────────────────────────────────────────────
    transports: list[dict] = []
    status_by_id: dict[str, str] = {}
    for entry in _TRANSPORT_CATALOG:
        variants = _name_variants(entry)

        # Is it registered (loaded into the router)? -> live health.
        reg_obj = next((registered[v] for v in variants if v in registered), None)
        is_configured = any(configured_names.get(v) for v in variants)
        is_declared = any(v in configured_names for v in variants)

        if reg_obj is not None:
            status = _registry_status(reg_obj)
        elif is_configured:
            # Declared + enabled in config but not loaded (e.g. failed import /
            # optional dep missing) — present but not live.
            status = DOWN
        elif is_declared:
            # Declared but disabled in this deployment.
            status = UNCONFIGURED
        else:
            status = UNCONFIGURED

        # Rail-infrastructure probe: webrtc/websocket are "up" when their
        # signaling broker is live + reachable (the rail can establish
        # connections), even if this process holds no active peer right now.
        if probe and entry["id"] in _TRANSPORT_PROBES and status != UP:
            if _tcp_probe(_TRANSPORT_PROBES[entry["id"]]):
                status = UP

        rec = {
            "id": entry["id"],
            "protocol": entry["protocol"],
            "status": status,
            "roles": entry["roles"],
        }
        if "media" in entry:
            rec["media"] = entry["media"]
        transports.append(rec)
        status_by_id[entry["id"]] = status

    # ── co-resident service probes (optional, cheap) ───────────────────────
    # These upgrade derived service availability beyond pure transport status.
    probe_status: dict[str, str] = {}
    if probe:
        hosts = _probe_hosts()  # loopback + tailnet IP, computed once
        for svc, port in _SERVICE_PROBES.items():
            probe_status[svc] = UP if _tcp_probe(port, hosts) else DOWN
    else:
        probe_status = {svc: CONFIGURED for svc in _SERVICE_PROBES}

    t = status_by_id  # shorthand

    # ── services derived from transports + probes ──────────────────────────
    # Each service is as available as the best rail it can ride. Where a
    # co-resident daemon is the real backend (voice/video/access/geo) we fold
    # its probe in too.
    voice_via = ["webrtc", "websocket"]
    video_via = ["webrtc"]
    fed_via = ["https-s2s", "nostr"]
    stream_via = ["websocket", "p2p"]

    voice_status = _best(t["webrtc"], t["websocket"], probe_status.get("livekit", DOWN))
    video_status = _best(t["webrtc"], probe_status.get("livekit", DOWN))
    fed_status = _best(t["https-s2s"], t["nostr"], probe_status.get("nostr-relay", DOWN))

    services: list[dict] = [
        {
            "id": "text",
            "status": _best(
                t["file"], t["syncthing"], t["https-s2s"], t["websocket"], t["nostr"]
            ),
            "via": ["file", "syncthing", "https-s2s", "websocket", "nostr"],
        },
        {"id": "voice", "status": voice_status, "via": voice_via},
        {"id": "video", "status": video_status, "via": video_via},
        {
            "id": "file-transfer",
            "status": _best(t["file"], t["syncthing"], t["webrtc"], t["p2p"]),
            "via": ["file", "syncthing", "webrtc", "p2p"],
        },
        {
            "id": "data-streaming",
            "status": _best(t["websocket"], t["p2p"]),
            "via": stream_via,
        },
        {"id": "federation", "status": fed_status, "via": fed_via},
        {
            "id": "access-plane",
            "status": probe_status.get("sk-access", CONFIGURED if not probe else DOWN),
            "via": ["sk-access"],
        },
        {
            "id": "geo-cot",
            "status": probe_status.get("cot", CONFIGURED if not probe else DOWN),
            "via": ["cot"],
        },
    ]

    return {"node": node, "transports": transports, "services": services}
