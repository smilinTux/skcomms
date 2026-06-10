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


def _self_pubkey_armor() -> Optional[str]:
    """This agent's armored public key (for --embed-key), best-effort."""
    try:
        from .key_exchange import export_peer_bundle
        bundle = export_peer_bundle()
        return bundle.get("pubkey") if isinstance(bundle, dict) else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("self pubkey unavailable: %s", exc)
        return None


def bundle_from_self(agent: Optional[str] = None, *, embed_key: bool = False) -> PairingBundle:
    ident = resolve_self_identity(agent) or {}
    fqid = ident.get("fqid") or ""
    fp = ident.get("fingerprint") or ""
    hints = _self_hints(fqid)
    pubkey = _self_pubkey_armor() if embed_key else None
    return PairingBundle(fqid=fqid, fingerprint=fp, pubkey=pubkey, **hints)


def make_pairing_qr(bundle: PairingBundle):
    """Return (skp_uri, segno.QRCode). Caller can .save(path) or .terminal()."""
    import segno
    uri = to_skp_uri(bundle)
    return uri, segno.make(uri, error="m")


def _default_fetcher(bundle: "PairingBundle") -> Optional[str]:
    """Fetch the peer's armored pubkey via its hints (best-effort, no network in tests)."""
    try:
        from .key_exchange import fetch_peer_from_did
        target = bundle.https or bundle.fqid.split("@")[0]
        peer = fetch_peer_from_did(target)
        return peer.get("pubkey") if isinstance(peer, dict) else None
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
