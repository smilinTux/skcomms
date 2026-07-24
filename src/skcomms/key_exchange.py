"""Key exchange for SKComms peer onboarding.

Two modes:
    Public  — Fetch a peer's identity from their published DID on skworld.io
    Private — Export/import JSON peer bundles directly (file, USB, Signal, etc.)

Usage:
    # Public: fetch peer from DID registry
    peer = fetch_peer_from_did("lumina")
    peer = fetch_peer_from_did("https://ws.weblink.skworld.io/agents/lumina/.well-known/did.json")

    # Private: export own identity as bundle
    bundle = export_peer_bundle()

    # Private: import a peer bundle
    peer = import_peer_bundle(bundle)
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .discovery import PeerInfo, PeerStore, PeerTransport

logger = logging.getLogger("skcomms.key_exchange")

BUNDLE_VERSION = "1.0"
SKWORLD_DID_BASE = "https://ws.weblink.skworld.io/agents"


# ---------------------------------------------------------------------------
# Public key exchange — DID-based
# ---------------------------------------------------------------------------


def fetch_peer_from_did(
    name_or_url: str,
    *,
    peers_dir: Optional[Path] = None,
    save: bool = True,
) -> PeerInfo:
    """Fetch a peer's identity from their published DID document.

    Args:
        name_or_url: Agent slug (e.g. "lumina") or full DID document URL.
        peers_dir: Directory to save peer files (default ~/.skcapstone/skcomms/peers).
        save: Whether to persist the peer to disk.

    Returns:
        PeerInfo populated from the DID document.

    Raises:
        KeyExchangeError: If fetch or parsing fails, or the URL is blocked by
            the SSRF guard (non-http(s) scheme or a private/internal host).
    """
    import urllib.error

    from .ssrf import guarded_urlopen

    if name_or_url.startswith("http://") or name_or_url.startswith("https://"):
        url = name_or_url
        # Extract slug from URL for naming
        slug = _slug_from_url(url)
    elif name_or_url.startswith("file://"):
        # Local file for testing
        file_path = name_or_url[7:]
        try:
            did_doc = json.loads(Path(file_path).read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("key_exchange.py: %s", exc)
            raise KeyExchangeError(f"Failed to read local DID file: {exc}") from exc
        return _did_doc_to_peer(did_doc, peers_dir=peers_dir, save=save)
    else:
        slug = re.sub(r"[^a-z0-9-]", "-", name_or_url.lower()).strip("-")
        url = f"{SKWORLD_DID_BASE}/{slug}/.well-known/did.json"

    logger.info("Fetching DID from %s", url)

    try:
        # SSRF-guarded, rebind-safe fetch: the URL can be caller-supplied, so
        # it is vetted and the connection is pinned (see skcomms.ssrf).
        with guarded_urlopen(
            url,
            headers={"Accept": "application/did+json, application/json"},
            timeout=15,
        ) as resp:
            did_doc = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise KeyExchangeError(
                f"Peer '{name_or_url}' not found at {url}. "
                "They may not have published their DID yet."
            ) from exc
        raise KeyExchangeError(f"HTTP {exc.code} fetching DID: {exc.reason}") from exc
    except Exception as exc:
        logger.warning("key_exchange.py: %s", exc)
        raise KeyExchangeError(f"Failed to fetch DID from {url}: {exc}") from exc

    # Also try to fetch PGP public key if available alongside the DID
    public_key_armor = None
    asc_url = url.rsplit("/did.json", 1)[0] + "/public.asc"
    try:
        with guarded_urlopen(asc_url, timeout=10) as resp2:
            candidate = resp2.read().decode("utf-8")
            if "BEGIN PGP PUBLIC KEY BLOCK" in candidate:
                public_key_armor = candidate
                logger.info("Fetched PGP public key from %s", asc_url)
    except Exception:
        logger.debug("No public.asc at %s (optional)", asc_url)

    return _did_doc_to_peer(
        did_doc,
        peers_dir=peers_dir,
        save=save,
        public_key_armor=public_key_armor,
    )


def _slug_from_url(url: str) -> str:
    """Extract agent slug from a DID document URL."""
    # URL like .../agents/lumina/.well-known/did.json
    parts = url.rstrip("/").split("/")
    for i, part in enumerate(parts):
        if part == "agents" and i + 1 < len(parts):
            return parts[i + 1]
    # Fallback: use the hostname
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.hostname or "unknown"


def _did_doc_to_peer(
    did_doc: dict,
    *,
    peers_dir: Optional[Path] = None,
    save: bool = True,
    public_key_armor: Optional[str] = None,
) -> PeerInfo:
    """Convert a W3C DID document to a PeerInfo."""
    did_id = did_doc.get("id", "")

    # Extract name from alsoKnownAs or DID id
    name = _extract_name_from_did(did_doc)
    if not name:
        name = did_id.split(":")[-1] if did_id else "unknown"

    # Extract fingerprint from alsoKnownAs URIs
    fingerprint = _extract_fingerprint_from_did(did_doc)

    # Extract JWK public key from verificationMethod
    jwk = None
    vm_list = did_doc.get("verificationMethod", [])
    for vm in vm_list:
        if vm.get("publicKeyJwk"):
            jwk = vm["publicKeyJwk"]
            break

    peer = PeerInfo(
        name=name,
        fingerprint=fingerprint,
        discovered_via="did",
        last_seen=datetime.now(timezone.utc),
        transports=[],
    )

    if save:
        store = PeerStore(peers_dir or _default_peers_dir())
        store.add(peer)

        # Save public key if we have it
        if public_key_armor:
            key_path = (peers_dir or _default_peers_dir()) / f"{_safe_filename(name)}.pub.asc"
            key_path.write_text(public_key_armor, encoding="utf-8")
            logger.info("Saved public key to %s", key_path)

        # Save DID metadata alongside peer YAML
        meta_path = (peers_dir or _default_peers_dir()) / f"{_safe_filename(name)}.did.json"
        meta = {
            "did": did_id,
            "did_key": did_doc.get("id") if did_id.startswith("did:key:") else None,
            "jwk": jwk,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return peer


def _extract_name_from_did(did_doc: dict) -> Optional[str]:
    """Extract a human-readable name from a DID document."""
    # Check alsoKnownAs for capauth: URIs
    for aka in did_doc.get("alsoKnownAs", []):
        if isinstance(aka, str):
            # capauth:opus@skworld.io → Opus
            if aka.startswith("capauth:"):
                local = aka.split(":")[1].split("@")[0]
                return local.title()
            # capauth:name:Queen Lumina
            if "name:" in aka:
                return aka.split("name:")[-1]

    # Check service endpoints for agent name
    for svc in did_doc.get("service", []):
        meta = svc.get("serviceEndpoint", {})
        if isinstance(meta, dict) and meta.get("name"):
            return meta["name"]

    # Check skworld:agentCard
    agent_card = did_doc.get("skworld:agentCard", {})
    if agent_card.get("name"):
        return agent_card["name"]

    return None


def _extract_fingerprint_from_did(did_doc: dict) -> Optional[str]:
    """Extract a PGP fingerprint from alsoKnownAs URIs."""
    for aka in did_doc.get("alsoKnownAs", []):
        if isinstance(aka, str) and aka.startswith("capauth:fingerprint:"):
            return aka.split("capauth:fingerprint:")[-1]
        # Also check for raw 40-char hex fingerprint
        if isinstance(aka, str) and re.match(r"^[A-Fa-f0-9]{40}$", aka):
            return aka.upper()
    return None


# ---------------------------------------------------------------------------
# Private key exchange — peer bundles
# ---------------------------------------------------------------------------


def export_peer_bundle(
    capauth_dir: Optional[Path] = None,
    include_transports: bool = True,
) -> dict:
    """Export own identity as a peer bundle for direct exchange.

    Reads from the local CapAuth profile and skcomms config.

    Returns:
        dict with bundle format suitable for JSON serialization.

    Raises:
        KeyExchangeError: If identity cannot be loaded.
    """
    ca_dir = capauth_dir or Path.home() / ".capauth" / "identity"

    # Read public key
    pub_path = ca_dir / "public.asc"
    if not pub_path.exists():
        raise KeyExchangeError(f"Public key not found: {pub_path}")
    public_key = pub_path.read_text(encoding="utf-8").strip()

    # Read profile
    profile_path = ca_dir / "profile.json"
    profile: dict = {}
    if profile_path.exists():
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("key_exchange.py: %s", e)
            pass

    # Get fingerprint from GPG
    fingerprint = _get_fingerprint_from_key(public_key)
    if not fingerprint:
        # Try profile
        fingerprint = profile.get("fingerprint", "")

    # Get name from key UID or profile
    name = _get_name_from_key(public_key)
    if not name:
        entity = profile.get("entity", {})
        name = entity.get("name", os.environ.get("USER", "agent"))

    # Get email from key UID
    email = _get_email_from_key(public_key)

    # Read did:key if available
    did_key = ""
    did_key_path = Path.home() / ".skcapstone" / "did" / "did_key.txt"
    if did_key_path.exists():
        did_key = did_key_path.read_text(encoding="utf-8").strip()

    bundle: dict[str, Any] = {
        "skcomms_peer_bundle": BUNDLE_VERSION,
        "name": name,
        "fingerprint": fingerprint,
        "email": email or "",
        "public_key": public_key,
        "did_key": did_key,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    if include_transports:
        bundle["transports"] = _get_local_transports()

    return bundle


def import_peer_bundle(
    bundle: dict,
    *,
    peers_dir: Optional[Path] = None,
    gpg_import: bool = True,
) -> PeerInfo:
    """Import a peer bundle and create PeerInfo + save public key.

    Args:
        bundle: Parsed peer bundle dict.
        peers_dir: Directory for peer files (default ~/.skcapstone/skcomms/peers).
        gpg_import: Whether to import the public key to GPG keyring.

    Returns:
        Created PeerInfo.

    Raises:
        KeyExchangeError: If bundle is invalid.
    """
    version = bundle.get("skcomms_peer_bundle")
    if not version:
        raise KeyExchangeError("Invalid bundle: missing 'skcomms_peer_bundle' version field")

    name = bundle.get("name", "").strip()
    if not name:
        raise KeyExchangeError("Invalid bundle: missing 'name'")

    fingerprint = bundle.get("fingerprint", "").strip() or None
    public_key = bundle.get("public_key", "").strip()

    if not public_key or "BEGIN PGP PUBLIC KEY BLOCK" not in public_key:
        raise KeyExchangeError("Invalid bundle: missing or malformed 'public_key'")

    # Build transports from bundle
    transports: list[PeerTransport] = []
    for t in bundle.get("transports", []):
        if isinstance(t, dict) and t.get("transport"):
            transports.append(
                PeerTransport(
                    transport=t["transport"],
                    settings=t.get("settings", {}),
                )
            )

    if not transports:
        # Default transports (coord 48289e82): a bundle that advertises no
        # transports falls back to this node's local file/syncthing routes.
        # Derive them through skcomms.paths, the SAME resolver config.load_config
        # and the S2S inbox writer use, instead of hardcoding node-shared
        # ~/.skcapstone paths. When an agent is scoped (SKAGENT / SKCAPSTONE_AGENT)
        # the routes point at that agent's OWN agents/<agent>/comms tree, so its
        # daemon polls exactly where envelopes land rather than a node-shared
        # inbox it never reads (the reader/writer divergence the FOLLOW-UP note
        # here used to describe). Agentless callers keep the legacy node-shared
        # locations.
        from . import paths as _paths

        agent = _paths.resolve_agent()
        comms_root = str(_paths.agent_comms_dir(agent)) if agent else "~/.skcapstone/comms"
        transports = [
            PeerTransport(transport="syncthing", settings={"comms_root": comms_root}),
            PeerTransport(
                transport="file",
                settings={"inbox_path": str(_paths.file_transport_inbox(agent))},
            ),
        ]

    peer = PeerInfo(
        name=name,
        fingerprint=fingerprint,
        discovered_via="bundle",
        last_seen=datetime.now(timezone.utc),
        transports=transports,
    )

    pdir = peers_dir or _default_peers_dir()
    pdir.mkdir(parents=True, exist_ok=True)

    # Save peer YAML
    store = PeerStore(pdir)
    store.add(peer)

    # Save public key file
    safe_name = _safe_filename(name)
    key_path = pdir / f"{safe_name}.pub.asc"
    key_path.write_text(public_key, encoding="utf-8")
    logger.info("Saved public key to %s", key_path)

    # Save DID metadata if present
    did_key = bundle.get("did_key", "")
    if did_key:
        meta_path = pdir / f"{safe_name}.did.json"
        meta = {
            "did_key": did_key,
            "email": bundle.get("email", ""),
            "imported_at": datetime.now(timezone.utc).isoformat(),
        }
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Import to GPG keyring
    if gpg_import:
        _gpg_import_key(public_key, name)

    return peer


# ---------------------------------------------------------------------------
# GPG helpers
# ---------------------------------------------------------------------------


def _gpg_import_key(armor: str, name: str) -> bool:
    """Import an ASCII-armored public key into the local GPG keyring."""
    try:
        result = subprocess.run(
            ["gpg", "--batch", "--import"],
            input=armor.encode("utf-8"),
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            logger.info("Imported %s's public key to GPG keyring", name)
            return True
        stderr = result.stderr.decode("utf-8", errors="replace")
        if "already in secret keyring" in stderr or "not changed" in stderr:
            logger.debug("Key for %s already in keyring", name)
            return True
        logger.warning("GPG import for %s failed: %s", name, stderr.strip())
        return False
    except FileNotFoundError:
        logger.debug("gpg not found — skipping keyring import")
        return False
    except Exception as exc:
        logger.warning("GPG import error: %s", exc)
        return False


def _get_fingerprint_from_key(armor: str) -> Optional[str]:
    """Extract fingerprint from a PGP public key via gpg."""
    try:
        result = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--import-options", "show-only", "--import"],
            input=armor.encode("utf-8"),
            capture_output=True,
            timeout=10,
        )
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]
    except Exception as e:
        logger.warning("key_exchange.py: %s", e)
        pass
    return None


def _get_name_from_key(armor: str) -> Optional[str]:
    """Extract the UID name from a PGP public key."""
    try:
        result = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--import-options", "show-only", "--import"],
            input=armor.encode("utf-8"),
            capture_output=True,
            timeout=10,
        )
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("uid:"):
                uid_field = line.split(":")[9]
                # "Queen Lumina (Sovereign AI) <email>" → "Queen Lumina"
                name = uid_field.split("(")[0].split("<")[0].strip()
                if name:
                    return name
    except Exception as e:
        logger.warning("key_exchange.py: %s", e)
        pass
    return None


def _get_email_from_key(armor: str) -> Optional[str]:
    """Extract email from a PGP public key UID."""
    try:
        result = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--import-options", "show-only", "--import"],
            input=armor.encode("utf-8"),
            capture_output=True,
            timeout=10,
        )
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("uid:"):
                uid_field = line.split(":")[9]
                match = re.search(r"<([^>]+)>", uid_field)
                if match:
                    return match.group(1)
    except Exception as e:
        logger.warning("key_exchange.py: %s", e)
        pass
    return None


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------


def _get_local_transports() -> list[dict]:
    """Read local skcomms config and return transport info suitable for bundle."""
    config_path = Path.home() / ".skcapstone" / "skcomms" / "config.yml"
    if not config_path.exists():
        return []

    try:
        import yaml

        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        skcomms = config.get("skcomms", config)
        transports_cfg = skcomms.get("transports", {})
        result = []
        for name, tcfg in transports_cfg.items():
            if isinstance(tcfg, dict) and tcfg.get("enabled", True):
                result.append(
                    {
                        "transport": name,
                        "settings": tcfg.get("settings", {}),
                    }
                )
        return result
    except Exception as e:
        logger.warning("key_exchange.py: %s", e)
        return []


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _default_peers_dir() -> Path:
    return Path(os.environ.get("SKCOMMS_HOME", str(Path.home() / ".skcapstone" / "skcomms"))) / "peers"


def _safe_filename(name: str) -> str:
    """Sanitize a name for use as a filename."""
    safe = re.sub(r"[^\w\s-]", "", name).strip()
    safe = re.sub(r"[\s]+", "_", safe)
    return safe.lower() or "peer"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class KeyExchangeError(Exception):
    """Raised when key exchange operations fail."""
