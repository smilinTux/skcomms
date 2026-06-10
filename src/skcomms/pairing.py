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
