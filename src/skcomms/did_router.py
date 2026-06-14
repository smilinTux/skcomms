"""
DID (Decentralized Identity) API router for SKComms.

Exposes W3C DID documents at three tiers and provides peer DID resolution,
challenge-response verification, and on-disk publishing.

Routes (no auth required):
    GET  /.well-known/did.json     → Tier 2 (mesh) document; Tier 1 fallback
    GET  /api/v1/did/key           → {"did_key": "did:key:z...", "fingerprint": "..."}
    POST /api/v1/did/verify        → challenge-response structural verification

Routes (CapAuth bearer token required):
    GET  /api/v1/did/document      → all tiers {"key":{...}, "mesh":{...}, "public":{...}}
    GET  /api/v1/did/peers/{name}  → peer DID from ~/.skcapstone/peers/{name}.json
    POST /api/v1/did/publish       → write DID files to disk

All DID document responses use Content-Type: application/did+json.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("skcomms.did")

# Single router with no prefix — routes carry their full paths.
did_router = APIRouter(tags=["did"])

_DID_CONTENT_TYPE = "application/did+json"

# ---------------------------------------------------------------------------
# Auth dependency (mirrors profile_router.py)
# ---------------------------------------------------------------------------

try:
    from .capauth_validator import CapAuthValidator as _CapAuthValidator

    _validator: Any = _CapAuthValidator()
except Exception as e:
    logger.warning("CapAuth validator unavailable — authenticated DID endpoints will be disabled: %s", e)
    _validator = None


def _require_capauth(authorization: Optional[str] = Header(None)) -> str:
    """Validate CapAuth bearer token and return the authenticated fingerprint."""
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization scheme (expected Bearer)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if _validator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CapAuth validator unavailable",
        )
    fingerprint = _validator.validate(token)
    if fingerprint is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired CapAuth token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return fingerprint


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _skcapstone_home() -> Path:
    return Path(os.environ.get("SKCAPSTONE_HOME", str(Path.home() / ".skcapstone")))


def _skcomms_home() -> Path:
    return Path(os.environ.get("SKCOMMS_HOME", str(Path.home() / ".skcomms")))


def _tailnet_params() -> tuple[str, str]:
    """Read Tailscale hostname and tailnet from environment, falling back to hostname."""
    hostname = os.environ.get("SKWORLD_HOSTNAME", "")
    tailnet = os.environ.get("SKWORLD_TAILNET", "")
    if not hostname:
        try:
            hostname = socket.gethostname()
        except Exception as e:
            logger.warning("did_router.py: %s", e)
            pass
    return hostname, tailnet


def _did_json(doc: dict) -> JSONResponse:
    """Wrap a DID document in a JSONResponse with the correct Content-Type."""
    return JSONResponse(content=doc, media_type=_DID_CONTENT_TYPE)


def _load_generator() -> Any:
    """Load a DIDDocumentGenerator from the local CapAuth profile."""
    from capauth.did import DIDDocumentGenerator  # type: ignore[import]

    return DIDDocumentGenerator.from_profile()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@did_router.get("/.well-known/did.json", include_in_schema=True)
async def well_known_did() -> JSONResponse:
    """Tier 2 (mesh) DID document; falls back to Tier 1 (did:key) if Tailscale absent.

    No authentication required. Served to Tailscale peers via ``tailscale serve``.
    """
    try:
        from capauth.did import DIDTier  # type: ignore[import]

        gen = _load_generator()
        hostname, tailnet = _tailnet_params()
        doc = gen.generate(DIDTier.WEB_MESH, tailnet_hostname=hostname, tailnet_name=tailnet)
        return _did_json(doc)
    except Exception as exc:
        logger.warning("/.well-known/did.json error: %s", exc)
        raise HTTPException(status_code=503, detail=f"DID unavailable: {exc}")


@did_router.get("/api/v1/did/key")
async def did_key_endpoint() -> JSONResponse:
    """Return the did:key identifier and PGP fingerprint.

    No authentication required.
    """
    try:
        gen = _load_generator()
        ctx = gen._ctx
        return JSONResponse(
            {
                "did_key": ctx.did_key_id,
                "fingerprint": ctx.fingerprint,
                "name": ctx.name,
            }
        )
    except Exception as exc:
        logger.warning("/api/v1/did/key error: %s", exc)
        raise HTTPException(status_code=503, detail=f"DID key unavailable: {exc}")


@did_router.get("/api/v1/did/document")
async def did_document_all(fingerprint: str = Depends(_require_capauth)) -> JSONResponse:
    """Return all three DID tiers.

    Requires CapAuth bearer token.
    """
    try:
        from capauth.did import DIDTier  # type: ignore[import]

        gen = _load_generator()
        hostname, tailnet = _tailnet_params()
        docs = gen.generate_all(tailnet_hostname=hostname, tailnet_name=tailnet)
        return JSONResponse(
            {
                "key": docs[DIDTier.KEY],
                "mesh": docs[DIDTier.WEB_MESH],
                "public": docs[DIDTier.WEB_PUBLIC],
                "did_key": gen._ctx.did_key_id,
                "fingerprint": gen._ctx.fingerprint,
            }
        )
    except Exception as exc:
        logger.warning("/api/v1/did/document error: %s", exc)
        raise HTTPException(status_code=503, detail=f"DID document unavailable: {exc}")


@did_router.get("/api/v1/did/peers/{name}")
async def did_peer(name: str, fingerprint: str = Depends(_require_capauth)) -> JSONResponse:
    """Return peer DID from ``~/.skcapstone/peers/{name}.json``.

    Computes ``did:key`` from the peer's public key on first call and caches it back.
    Requires CapAuth bearer token.
    """
    peers_dir = _skcapstone_home() / "peers"
    peer_file = peers_dir / f"{name}.json"

    if not peer_file.exists():
        raise HTTPException(status_code=404, detail=f"Peer '{name}' not found")

    try:
        peer_data = json.loads(peer_file.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("did_router.py: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to read peer file: {exc}")

    did_key = peer_data.get("did_key")
    if not did_key:
        pub_armor = peer_data.get("public_key") or peer_data.get("public_key_armor")
        if pub_armor:
            try:
                from capauth.did import (  # type: ignore[import]
                    _compute_did_key,
                    _pgp_armor_to_rsa_numbers,
                    _rsa_numbers_to_der,
                )

                n, e = _pgp_armor_to_rsa_numbers(pub_armor)
                did_key = _compute_did_key(_rsa_numbers_to_der(n, e))
                # Cache to disk
                peer_data["did_key"] = did_key
                peer_file.write_text(json.dumps(peer_data, indent=2), encoding="utf-8")
            except Exception as exc:
                logger.debug("Could not compute did:key for peer %s: %s", name, exc)

    return JSONResponse(
        {
            "name": name,
            "did_key": did_key,
            "did_web": peer_data.get("did_web"),
            "fingerprint": peer_data.get("fingerprint"),
            "peer_file": str(peer_file),
        }
    )


class _VerifyRequest(BaseModel):
    """Request body for DID challenge-response verification."""

    did: str
    challenge: str  # hex-encoded random bytes


@did_router.post("/api/v1/did/verify")
async def did_verify(req: _VerifyRequest) -> JSONResponse:
    """Structural DID validation (challenge-response skeleton).

    No authentication required. Full cryptographic challenge-response
    verification (peer signs and returns) is a future extension.
    """
    verified = False
    detail = "Challenge-response signing not yet implemented"

    if req.did.startswith("did:key:z"):
        verified = True
        detail = "did:key structural validation passed"
    elif req.did.startswith("did:web:"):
        verified = True
        detail = "did:web structural validation passed"

    return JSONResponse(
        {
            "did": req.did,
            "challenge": req.challenge,
            "verified": verified,
            "detail": detail,
        }
    )


@did_router.post("/api/v1/did/publish")
async def did_publish(fingerprint: str = Depends(_require_capauth)) -> JSONResponse:
    """Generate all DID tiers and write files to disk.

    Writes:
      ``~/.skcomms/well-known/did.json``   → Tier 2 (mesh)
      ``~/.skcapstone/did/key.json``       → Tier 1 (did:key)
      ``~/.skcapstone/did/public.json``    → Tier 3 (public)
      ``~/.skcapstone/did/did_key.txt``    → plain did:key string

    Requires CapAuth bearer token.
    """
    try:
        from capauth.did import DIDTier  # type: ignore[import]

        gen = _load_generator()
        hostname, tailnet = _tailnet_params()
        docs = gen.generate_all(tailnet_hostname=hostname, tailnet_name=tailnet)

        written: list[str] = []
        errors: list[str] = []

        def _write(path: Path, content: str) -> None:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                written.append(str(path))
            except Exception as exc:
                logger.warning("did_router.py: %s", exc)
                errors.append(f"{path}: {exc}")

        _write(
            _skcomms_home() / "well-known" / "did.json",
            json.dumps(docs[DIDTier.WEB_MESH], indent=2),
        )
        did_dir = _skcapstone_home() / "did"
        _write(did_dir / "key.json", json.dumps(docs[DIDTier.KEY], indent=2))
        _write(did_dir / "public.json", json.dumps(docs[DIDTier.WEB_PUBLIC], indent=2))
        _write(did_dir / "did_key.txt", gen._ctx.did_key_id)

        return JSONResponse(
            {
                "published": not errors,
                "did_key": gen._ctx.did_key_id,
                "fingerprint": gen._ctx.fingerprint,
                "written": written,
                "errors": errors,
            }
        )
    except Exception as exc:
        logger.error("DID publish failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"DID publish failed: {exc}")
