"""Public P2P pairing over a Tailscale **Funnel** URL (card 2ab5aa6c).

Two peers who are NOT on the same tailnet cannot reach each other over the
tailnet-only :mod:`skcomms.transports.tailscale` mesh, nor scan each other's
``skp://`` QR in person. Tailscale **Funnel** exposes a local service to the
PUBLIC internet (distinct from tailnet-only ``serve``), so a node can offer a
public pairing endpoint that an off-tailnet peer POSTs their peer bundle to.

This module is the skcomms **side** of that integration only:

    * resolve the node's configured Funnel base URL (config / env / a read-only
      ``tailscale funnel status`` probe). Never provisions Funnel itself;
    * mint the public pairing URL (and an optional bearer token) a peer uses;
    * accept an inbound public pairing request and route it straight into the
      EXISTING key exchange (:func:`skcomms.key_exchange.import_peer_bundle`),
      which does all the crypto (armor validation + fingerprint derivation).

The public Funnel is only the *bootstrap channel*: the CapAuth key-exchange and
its verification are unchanged, so the crypto still protects the pairing even
though the transport is public.

**Disabled by default.** With no Funnel URL configured (``SKCOMMS_FUNNEL_URL``
unset and no live funnel), :func:`funnel_enabled` is ``False``,
:func:`mint_pairing_url` returns ``None``, and the API route 404s. Nothing binds
a public port or opens a live Funnel here (that is an operator/deploy concern).

Fail-closed: a request with no bundle, a malformed bundle, or (when a token is
configured) a missing/mismatched token is rejected. A wrong key can never pair
because ``import_peer_bundle`` re-derives the fingerprint from the armored key.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
from typing import Any, Callable, Optional
from urllib.parse import urlencode

from pydantic import BaseModel, Field

logger = logging.getLogger("skcomms.public_pairing")

#: Env: the node's public Tailscale Funnel base URL (e.g.
#: ``https://node.tailnet.ts.net``). Unset -> public pairing is OFF.
FUNNEL_URL_ENV = "SKCOMMS_FUNNEL_URL"

#: Env: optional shared bearer token an inbound public pairing request must
#: present. When set, a missing/mismatched token is rejected fail-closed. When
#: unset the endpoint accepts any well-formed bundle (crypto still verifies it).
FUNNEL_TOKEN_ENV = "SKCOMMS_FUNNEL_PAIR_TOKEN"

#: The public pairing route (mounted on the same Funnel-exposed FastAPI app).
PUBLIC_PAIR_PATH = "/api/v1/pair/public"

#: Query-string key carrying the pairing token in a minted URL.
TOKEN_PARAM = "t"

#: Injected base resolver: ``() -> base url | None``.
BaseResolver = Callable[[], Optional[str]]


class PublicPairingError(Exception):
    """Raised when an inbound public pairing request is rejected (fail-closed)."""


def _tailscale_funnel_base() -> Optional[str]:
    """Best-effort, **read-only** probe of this node's live Funnel base URL.

    Reads ``tailscale funnel status --json`` and returns
    ``https://<node>.<tailnet>.ts.net`` only when a funnel is actually being
    served (i.e. the operator has already exposed something). This never mutates
    Funnel state and returns ``None`` on any failure (tailscale absent, no
    funnel configured, parse error), so public pairing stays OFF unless it is
    genuinely exposed.
    """
    import json
    import subprocess

    try:
        out = subprocess.run(
            ["tailscale", "funnel", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:  # tailscale missing / timeout -> not exposed
        logger.debug("tailscale funnel probe failed: %s", exc)
        return None
    if out.returncode != 0 or not (out.stdout or "").strip():
        return None
    try:
        data = json.loads(out.stdout or "{}")
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("tailscale funnel status parse error: %s", exc)
        return None
    # Only treat the node as funnel-exposed when at least one AllowFunnel entry
    # is truthy. The keys are ``<host>:<port>`` -> bool.
    allow = data.get("AllowFunnel") or {}
    if not any(bool(v) for v in allow.values()):
        return None
    host = None
    for hp in allow:
        if allow.get(hp):
            host = str(hp).split(":", 1)[0].rstrip(".")
            break
    return f"https://{host}" if host else None


def resolve_funnel_base(
    base: Optional[str] = None, *, resolver: Optional[BaseResolver] = None
) -> Optional[str]:
    """Resolve this node's public Funnel base URL (no trailing slash), or ``None``.

    Order (first hit wins): explicit ``base`` -> ``SKCOMMS_FUNNEL_URL`` env ->
    ``resolver()`` (default :func:`_tailscale_funnel_base`). Returns ``None``
    when nothing is configured, which is what keeps public pairing disabled by
    default.
    """
    if base:
        return base.rstrip("/")
    env = os.environ.get(FUNNEL_URL_ENV)
    if env:
        return env.rstrip("/")
    fn = resolver if resolver is not None else _tailscale_funnel_base
    try:
        resolved = fn()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("funnel base resolver raised: %s", exc)
        return None
    return resolved.rstrip("/") if resolved else None


def funnel_enabled(base: Optional[str] = None, *, resolver: Optional[BaseResolver] = None) -> bool:
    """True iff a public Funnel base URL is configured (feature is ON)."""
    return resolve_funnel_base(base, resolver=resolver) is not None


def configured_token() -> Optional[str]:
    """The configured inbound pairing token (``SKCOMMS_FUNNEL_PAIR_TOKEN``), or None."""
    tok = os.environ.get(FUNNEL_TOKEN_ENV)
    return tok or None


def mint_pairing_token(nbytes: int = 32) -> str:
    """Mint a fresh URL-safe pairing token a peer must present (opt-in)."""
    return secrets.token_urlsafe(nbytes)


def mint_pairing_url(
    base: Optional[str] = None,
    *,
    token: Optional[str] = None,
    resolver: Optional[BaseResolver] = None,
) -> Optional[str]:
    """Mint the public pairing URL a peer POSTs their bundle to.

    Returns ``<funnel-base>/api/v1/pair/public`` (with ``?t=<token>`` when a
    token is supplied), or ``None`` when no Funnel base is configured (feature
    off). Does not hardcode any hostname; the base always comes from
    :func:`resolve_funnel_base`.
    """
    fbase = resolve_funnel_base(base, resolver=resolver)
    if not fbase:
        return None
    url = fbase + PUBLIC_PAIR_PATH
    if token:
        url = f"{url}?{urlencode({TOKEN_PARAM: token})}"
    return url


class PublicPairingRequest(BaseModel):
    """An inbound public pairing request received over the Funnel channel.

    ``bundle`` is the peer's ``skcomms_peer_bundle`` (the same shape
    :func:`skcomms.key_exchange.export_peer_bundle` produces). ``token`` carries
    the optional bearer token when the node requires one.
    """

    bundle: dict[str, Any] = Field(default_factory=dict)
    token: Optional[str] = None


def _check_token(expected: Optional[str], provided: Optional[str]) -> None:
    """Fail-closed token check (constant-time). No-op when no token is required."""
    if not expected:
        return
    if not provided or not hmac.compare_digest(str(expected), str(provided)):
        raise PublicPairingError("invalid or missing pairing token")


def handle_public_pairing_request(
    payload: "PublicPairingRequest | dict",
    *,
    expected_token: Optional[str] = None,
    peers_dir=None,
    gpg_import: bool = False,
    importer: Optional[Callable] = None,
    self_bundle_provider: Optional[Callable[[], dict]] = None,
) -> dict:
    """Accept an inbound public pairing request and route it into key exchange.

    Steps (all fail-closed):
        1. Token gate: when *expected_token* is set, ``payload.token`` must
           match (constant-time), else :class:`PublicPairingError`.
        2. Import the peer's bundle via the EXISTING key exchange
           (:func:`skcomms.key_exchange.import_peer_bundle`), which validates
           the armored key and derives the fingerprint. A missing/malformed
           bundle raises (``KeyExchangeError``). The crypto is unchanged.
        3. Best-effort attach THIS node's own bundle so the peer can import us
           back (mutual bootstrap). A failure to build the self bundle does not
           fail the inbound pairing.

    Args:
        payload: A :class:`PublicPairingRequest` or an equivalent dict.
        expected_token: Required token (defaults to ``configured_token()`` when
            ``None`` is passed *and* one is configured; pass ``""`` to force no
            token). See below.
        peers_dir: Override the peer store dir (tests).
        gpg_import: Forwarded to ``import_peer_bundle`` (default False: the
            public bootstrap does not touch the gpg keyring).
        importer: Override the import callable (tests). Signature
            ``(bundle, *, peers_dir, gpg_import) -> PeerInfo``.
        self_bundle_provider: Override the self-bundle builder (tests). Default
            :func:`skcomms.key_exchange.export_peer_bundle`.

    Returns:
        ``{"paired": {"name", "fqid", "fingerprint"}, "self_bundle": {...} | None}``.

    Raises:
        PublicPairingError: token gate rejected.
        KeyExchangeError: bundle missing/malformed (fail-closed on bad input).
    """
    from .key_exchange import KeyExchangeError, export_peer_bundle, import_peer_bundle

    if isinstance(payload, PublicPairingRequest):
        req = payload
    elif isinstance(payload, dict):
        req = PublicPairingRequest(**payload)
    else:  # pragma: no cover - defensive
        raise PublicPairingError("unrecognised pairing payload")

    # 1. Token gate (fail-closed).
    if expected_token is None:
        expected_token = configured_token()
    _check_token(expected_token, req.token)

    # 2. Fail-closed on an empty/missing bundle before touching key exchange.
    if not req.bundle:
        raise KeyExchangeError("public pairing request carried no peer bundle")

    _import = importer or import_peer_bundle
    peer = _import(req.bundle, peers_dir=peers_dir, gpg_import=gpg_import)

    fqid = req.bundle.get("fqid") or None

    # M2 pairing fold: best-effort dual-write into capauth.pairing. Public
    # pairing is also a TOFU add (import_peer_bundle just persisted the peer +
    # its armored key locally), so the SAME mirror as pairing.accept_pairing is
    # correct: subject = the peer's fqid, carrying its real armored public key.
    # mirror_pairing is gated on the kernel flag, no-ops on a missing fqid/key,
    # and swallows every capauth error, so it can NEVER change this accept path's
    # return value or raise (see pairing_mirror).
    from .pairing_mirror import mirror_pairing

    mirror_pairing(fqid, req.bundle.get("public_key") or "")

    # 3. Best-effort mutual bundle so the peer can import us back.
    self_bundle: Optional[dict] = None
    try:
        provider = self_bundle_provider or export_peer_bundle
        self_bundle = provider()
    except Exception as exc:  # noqa: BLE001 - self bundle is optional
        logger.debug("public pairing: self bundle unavailable: %s", exc)

    return {
        "paired": {
            "name": getattr(peer, "name", None),
            "fqid": fqid,
            "fingerprint": getattr(peer, "fingerprint", None),
        },
        "self_bundle": self_bundle,
    }
