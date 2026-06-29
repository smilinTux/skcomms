"""SKFed self-announce — refresh THIS node's live endpoints in the realm directory.

A federation daemon's endpoints (its S2S inbox + hybrid-prekey URL) are *live*:
they depend on the node's current funnel/serve exposure, which can change across
restarts (a new tailnet node, a re-issued funnel host, a port change). This module
is the thin glue an agent daemon calls **on startup** so the on-disk
:class:`~skcomms.skfed_directory.SignedDirectory` always reflects the node's
current reachable endpoints:

    on daemon start ->  announce_self(agent)
                        ├─ resolve the node's live base URL (passed / env / tailscale)
                        ├─ derive inbox_url + prekey_url
                        └─ publish_self_to_realm_directory(...)  # upsert + re-sign

Base-URL resolution order (first hit wins):

    1. an explicit ``base=`` argument
    2. ``SKFED_BASE_URL`` env
    3. an injected ``base_resolver`` (default: read-only ``tailscale status``
       MagicDNS probe -> ``https://<node>.<tailnet>.ts.net``)

``inbox_url`` / ``prekey_url`` may also be given directly (or via
``SKFED_INBOX_URL`` / ``SKFED_PREKEY_URL``), overriding the derived values.

Everything that touches I/O — the publisher, the signer, the base resolver — is
injectable, so this whole path is unit-testable offline against a tmp
``SKCOMMS_HOME``. The default publisher is the proven
:func:`skcomms.skfed_directory.publish_self_to_realm_directory` (upsert + re-sign
+ atomic persist), and the default signer is the node's on-disk CapAuth key.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Iterable, Optional, Union

from . import skfed_directory
from .identity import resolve_self_identity

logger = logging.getLogger("skcomms.skfed_announce")

#: S2S federation inbox path (matches skcomms.api + mode-b-setup.sh).
INBOX_PATH = "/api/v1/inbox"
#: Hybrid-prekey bundle path (matches skcomms.api + node_registry).
PREKEY_PATH = "/api/v1/prekey"

#: Injected base resolver: ``() -> base url | None``.
BaseResolver = Callable[[], Optional[str]]


def _join(base: str, path: str) -> str:
    """Join a base URL and an absolute path with exactly one slash."""
    return base.rstrip("/") + path


def _default_base_resolver() -> Optional[str]:
    """Best-effort, **read-only** probe of this node's live funnel/serve base URL.

    Asks ``tailscale status --json`` for the node's MagicDNS name and returns
    ``https://<node>.<tailnet>.ts.net``. This is a pure read (no ``serve`` /
    ``funnel`` mutation). Returns ``None`` on any failure (tailscale absent, not
    up, parse error) so callers fall back to an explicit ``base`` / env.
    """
    import json
    import subprocess

    try:
        out = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:  # tailscale missing / timeout -> no base
        logger.debug("tailscale base probe failed: %s", exc)
        return None
    if out.returncode != 0:
        return None
    try:
        data = json.loads(out.stdout or "{}")
        dns = str((data.get("Self") or {}).get("DNSName", "")).rstrip(".")
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("tailscale status parse error: %s", exc)
        return None
    return f"https://{dns}" if dns else None


def resolve_base(base: Optional[str] = None, *, resolver: Optional[BaseResolver] = None) -> Optional[str]:
    """Resolve this node's directory/endpoint base URL (no trailing slash).

    Order: explicit ``base`` -> ``SKFED_BASE_URL`` env -> ``resolver()``
    (default :func:`_default_base_resolver`). Returns ``None`` if nothing
    resolves.
    """
    if base:
        return base.rstrip("/")
    env = os.environ.get("SKFED_BASE_URL")
    if env:
        return env.rstrip("/")
    fn = resolver if resolver is not None else _default_base_resolver
    try:
        resolved = fn()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("base resolver raised: %s", exc)
        return None
    return resolved.rstrip("/") if resolved else None


def announce_self(
    agent: Optional[str] = None,
    *,
    inbox_url: Optional[str] = None,
    prekey_url: Optional[str] = None,
    base: Optional[str] = None,
    did: Optional[str] = None,
    caps: Optional[list[str]] = None,
    fqid: Optional[str] = None,
    signer=None,
    publisher: Optional[Callable] = None,
    base_resolver: Optional[BaseResolver] = None,
    realm: Optional[str] = None,
    operator: Optional[str] = None,
) -> "skfed_directory.SignedDirectory":
    """Refresh THIS agent's entry in the local realm directory (call on startup).

    Resolves the node's live endpoints and upserts + re-signs the directory via
    *publisher* (default :func:`skfed_directory.publish_self_to_realm_directory`).

    Args:
        agent: Short agent name (for fqid + node-key resolution). ``None`` -> the
            resolved self identity.
        inbox_url: Explicit S2S inbox URL. Falls back to ``SKFED_INBOX_URL`` env,
            then ``<base>/api/v1/inbox``.
        prekey_url: Explicit hybrid-prekey URL. Falls back to ``SKFED_PREKEY_URL``
            env, then ``<base>/api/v1/prekey``.
        base: Explicit base URL for the node's endpoints (overrides resolution).
        did: Optional DID to advertise.
        caps: Optional capability tags (e.g. ``["dm", "files"]``).
        fqid: Override the announced fqid (defaults to the resolved identity's).
        signer: Override the node signer (forwarded to the publisher; ``None``
            lets the publisher load the on-disk node key).
        publisher: Override the publish callable (for tests). Must accept
            ``(fqid, inbox_url, prekey_url=..., *, did, caps, agent, signer,
            realm, operator)``.
        base_resolver: Override the live-base resolver (for tests / non-tailscale).
        realm / operator: Overrides for a brand-new directory.

    Returns:
        The freshly signed, persisted :class:`~skcomms.skfed_directory.SignedDirectory`.

    Raises:
        ValueError: if no fqid can be resolved (nothing to announce), or no
            inbox URL can be resolved (pass ``inbox_url=`` / ``base=`` or set the
            ``SKFED_*`` env).
    """
    fqid = fqid or resolve_self_identity(agent).get("fqid")
    if not fqid:
        raise ValueError(
            "announce_self: no fqid resolved (cluster.json / identity missing) — "
            "nothing to announce. Pass fqid= or configure ~/.skcapstone/cluster.json."
        )

    resolved_base = resolve_base(base, resolver=base_resolver)

    if inbox_url is None:
        inbox_url = os.environ.get("SKFED_INBOX_URL")
    if inbox_url is None and resolved_base:
        inbox_url = _join(resolved_base, INBOX_PATH)
    if inbox_url is None:
        raise ValueError(
            "announce_self: could not resolve an inbox URL — pass inbox_url= / "
            "base=, or set SKFED_BASE_URL / SKFED_INBOX_URL."
        )

    if prekey_url is None:
        prekey_url = os.environ.get("SKFED_PREKEY_URL")
    if prekey_url is None and resolved_base:
        prekey_url = _join(resolved_base, PREKEY_PATH)

    publish = publisher or skfed_directory.publish_self_to_realm_directory
    logger.info("skfed announce_self: %s -> inbox=%s prekey=%s", fqid, inbox_url, prekey_url)
    return publish(
        fqid,
        inbox_url,
        prekey_url,
        did=did,
        caps=caps,
        agent=agent,
        signer=signer,
        realm=realm,
        operator=operator,
    )


def refresh_all(
    agents: Iterable[Union[str, dict]],
    *,
    base: Optional[str] = None,
    base_resolver: Optional[BaseResolver] = None,
    publisher: Optional[Callable] = None,
    signer=None,
    realm: Optional[str] = None,
    operator: Optional[str] = None,
) -> list:
    """Re-announce every agent this node co-hosts (multi-agent node startup helper).

    Each item is either a short agent name (fqid resolved from identity) or a
    dict of :func:`announce_self` kwargs (e.g.
    ``{"agent": "jarvis", "fqid": ..., "base": ...}``) for per-agent overrides.
    Shared ``base`` / ``base_resolver`` / ``signer`` / ``realm`` / ``operator``
    apply unless an item overrides them.

    Returns:
        The list of resulting :class:`~skcomms.skfed_directory.SignedDirectory`
        objects (one per agent, in order).
    """
    results = []
    for item in agents:
        common = dict(
            base=base,
            base_resolver=base_resolver,
            publisher=publisher,
            signer=signer,
            realm=realm,
            operator=operator,
        )
        if isinstance(item, dict):
            kwargs = {**common, **item}
            agent_name = kwargs.pop("agent", None)
            results.append(announce_self(agent_name, **kwargs))
        else:
            results.append(announce_self(item, **common))
    return results
