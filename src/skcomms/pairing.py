"""QR device-pairing — encode an agent's pairing bundle to a skp:// URI/QR and
accept a scanned one (verify fingerprint via TOFU, add the peer)."""
from __future__ import annotations

import base64
import logging
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)
SKP_SCHEME = "skp"

# graceful imports — keep the module importable even if deps shift
try:
    from .identity import resolve_self_identity
except Exception:  # noqa: BLE001
    def resolve_self_identity(agent=None):
        return {}


class PairingBundle(BaseModel):
    fqid: str
    fingerprint: str                       # 40-hex (or test value); canonical id
    syncthing_device_id: Optional[str] = None
    tailscale: Optional[str] = None
    https: Optional[str] = None
    pubkey: Optional[str] = None           # armored, only when --embed-key

    @field_validator("fqid", "fingerprint")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("fqid and fingerprint are required")
        return v


def to_skp_uri(b: PairingBundle) -> str:
    params = {"v": "1", "fqid": b.fqid, "fp": b.fingerprint}
    if b.syncthing_device_id:
        params["sy"] = b.syncthing_device_id
    if b.tailscale:
        params["ts"] = b.tailscale
    if b.https:
        params["https"] = b.https
    if b.pubkey:
        params["pk"] = base64.urlsafe_b64encode(b.pubkey.encode()).decode()
    return f"{SKP_SCHEME}://pair?" + urlencode(params)


def parse_skp_uri(uri: str) -> PairingBundle:
    u = urlparse(uri)
    if u.scheme != SKP_SCHEME or u.netloc != "pair":
        raise ValueError(f"not an skp pairing URI: {uri!r}")
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    pk = q.get("pk")
    pubkey = base64.urlsafe_b64decode(pk.encode()).decode() if pk else None
    return PairingBundle(fqid=q.get("fqid", ""), fingerprint=q.get("fp", ""),
                         syncthing_device_id=q.get("sy"), tailscale=q.get("ts"),
                         https=q.get("https"), pubkey=pubkey)


def _self_hints(fqid: str) -> dict:
    """Connectivity hints for *fqid* from the peer registry (best-effort)."""
    try:
        from .registry import PeerRegistry
        rec = PeerRegistry.from_config().resolve(fqid)
        if rec is None:
            return {}
        return {k: v for k, v in {
            "syncthing_device_id": rec.syncthing_device_id,
            "tailscale": (rec.tailscale or {}).get("magicdns") if isinstance(rec.tailscale, dict) else rec.tailscale,
            "https": rec.https,
        }.items() if v}
    except Exception as exc:  # noqa: BLE001
        logger.debug("self hints unavailable: %s", exc)
        return {}


def _self_pubkey_armor(expected_fingerprint: Optional[str] = None,
                       agent: Optional[str] = None) -> Optional[str]:
    """The active AGENT's own armored public key (for --embed-key).

    Returns the agent's CapAuth public key — **never the operator key**.
    ``export_peer_bundle()`` / ``~/.capauth`` hold the *operator's* key
    (e.g. chef), which is the wrong key for an agent's pairing QR; only the
    per-agent ``capauth/identity/public.asc`` matches the agent's identity
    fingerprint. When *expected_fingerprint* is given, a candidate is returned
    only if its fingerprint matches — so an embedded key is always the right
    one (or None, falling back to a compact, fetch-on-accept QR).
    """
    import os
    from pathlib import Path

    name = agent or os.environ.get("SKAGENT") or os.environ.get("SKCAPSTONE_AGENT")
    candidates = []
    if name:
        candidates.append(
            Path.home() / ".skcapstone" / "agents" / name / "capauth" / "identity" / "public.asc"
        )
    for p in candidates:
        try:
            if not p.exists():
                continue
            armor = p.read_text(encoding="utf-8")
            if "PGP PUBLIC KEY" not in armor:
                continue
            if expected_fingerprint:
                from .peers import fingerprint_from_pubkey
                if fingerprint_from_pubkey(armor).upper() != expected_fingerprint.upper():
                    logger.debug("agent key at %s does not match identity fingerprint", p)
                    continue
            return armor
        except Exception as exc:  # noqa: BLE001
            logger.debug("agent pubkey read failed at %s: %s", p, exc)
    return None


def bundle_from_self(agent: Optional[str] = None, *, embed_key: bool = False) -> PairingBundle:
    ident = resolve_self_identity(agent) or {}
    fqid = ident.get("fqid") or ""
    fp = ident.get("fingerprint") or ""
    hints = _self_hints(fqid)
    pubkey = _self_pubkey_armor(fp, agent) if embed_key else None
    return PairingBundle(fqid=fqid, fingerprint=fp, pubkey=pubkey, **hints)


def make_pairing_qr(bundle: PairingBundle):
    """Return (skp_uri, segno.QRCode). Caller can .save(path) or .terminal()."""
    import segno
    uri = to_skp_uri(bundle)
    return uri, segno.make(uri, error="m")


def _local_agent_pubkey(fqid: str) -> Optional[str]:
    """The armored pubkey for *fqid* if that agent lives on THIS box.

    Covers same-box/self pairing (the agent's CapAuth key is on disk) and any
    locally-provisioned agent — no network needed.
    """
    try:
        from pathlib import Path
        agent = fqid.split("@", 1)[0]
        if not agent:
            return None
        p = Path.home() / ".skcapstone" / "agents" / agent / "capauth" / "identity" / "public.asc"
        if p.exists():
            armor = p.read_text(encoding="utf-8")
            if "PGP PUBLIC KEY" in armor:
                return armor
    except Exception as exc:  # noqa: BLE001
        logger.debug("local agent pubkey lookup failed: %s", exc)
    return None


def _known_peer_pubkey(fqid: str) -> Optional[str]:
    """A previously-stored armored pubkey for *fqid* from the TOFU store."""
    try:
        from .tofu import _load_store  # type: ignore
        rec = (_load_store() or {}).get(fqid) or {}
        armor = rec.get("pubkey")
        if armor and "PGP PUBLIC KEY" in armor:
            return armor
    except Exception as exc:  # noqa: BLE001
        logger.debug("tofu pubkey lookup failed: %s", exc)
    return None


def _default_fetcher(bundle: "PairingBundle") -> Optional[str]:
    """Resolve the peer's armored pubkey for a COMPACT QR (no network in tests).

    Order: a locally-provisioned agent's CapAuth key (covers same-box/self
    pairing), then a previously-stored TOFU key, then a DID/HTTPS fetch via the
    bundle's hint. ``accept_pairing`` always re-verifies the result against the
    bundle's fingerprint, so a wrong key is still rejected.
    """
    local = _local_agent_pubkey(bundle.fqid) or _known_peer_pubkey(bundle.fqid)
    if local:
        return local
    try:
        from .key_exchange import fetch_peer_from_did
        target = bundle.https or bundle.fqid.split("@")[0]
        peer = fetch_peer_from_did(target)
        if isinstance(peer, dict):
            return peer.get("public_key") or peer.get("pubkey")
    except Exception as exc:  # noqa: BLE001
        logger.debug("pubkey fetch failed: %s", exc)
    return None


def accept_pairing(uri_or_path: str, *, fetcher=None) -> dict:
    """Accept a scanned skp:// URI (or a file containing one): verify the peer's
    key fingerprint against the bundle, then TOFU-add the peer. Returns a summary
    dict. Raises ValueError on a fingerprint mismatch or unresolvable key."""
    import os
    import tempfile
    from pathlib import Path
    from .peers import add_peer, fingerprint_from_pubkey
    text = uri_or_path
    p = Path(uri_or_path)
    if not uri_or_path.startswith(f"{SKP_SCHEME}://") and p.exists():
        text = p.read_text(encoding="utf-8").strip()
    bundle = parse_skp_uri(text)
    pubkey = bundle.pubkey or (fetcher or _default_fetcher)(bundle)
    if not pubkey:
        raise ValueError(f"could not resolve a public key for {bundle.fqid}")
    actual_fp = fingerprint_from_pubkey(pubkey)
    if actual_fp.upper() != bundle.fingerprint.upper():
        raise ValueError(
            f"fingerprint mismatch for {bundle.fqid}: QR claims {bundle.fingerprint}, "
            f"key is {actual_fp} — refusing to pair")
    # write the pubkey to a temp file for peers.add_peer (which reads a path)
    fd, tmp = tempfile.mkstemp(suffix=".asc")
    os.close(fd)
    try:
        Path(tmp).write_text(pubkey, encoding="utf-8")
        add_peer(bundle.fqid, bundle.syncthing_device_id or "", tmp)
    finally:
        os.unlink(tmp)
    return {"fqid": bundle.fqid, "fingerprint": actual_fp,
            "syncthing_device_id": bundle.syncthing_device_id,
            "transport_hints": {k: getattr(bundle, k) for k in ("tailscale", "https") if getattr(bundle, k)}}
