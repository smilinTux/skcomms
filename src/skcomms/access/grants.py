"""Persistent scope-grants store + CLI for the sk-access plane (P7 / A6).

RBAC for the access plane is **per-identity scope grants**: an identity (an fqid
like ``lumina@chef.skworld``, or the ``"*"`` wildcard) is granted a set of
:class:`~skcomms.access.registry.Scope` (``read`` | ``write`` | ``exec``). The
access server's :meth:`AccessConfig.granted_scopes` consults the merged grants;
a verified identity with no grant falls back to ``"*"`` then to ``{READ}``.

This module owns the **persistent** half of that picture, kept separate from the
``access.yml`` server config so grants can be edited live (by the operator or a
``grant``/``revoke`` CLI) without touching the rest of the config:

    ~/.skcapstone/skcomms/access/grants.yml

Layout::

    grants:
      "lumina@chef.skworld": [read, write, exec]
      "guest@chef.skworld":  [read]
      "*":                   [read]

:func:`load_grants` reads it; :func:`merge_grants` folds it into an
:class:`AccessConfig` (the grants.yml entries take precedence over / union with
whatever the server config already carried). The CLI (``python -m
skcomms.access.grants``) does ``grant`` / ``revoke`` / ``list`` and writes back.

Note on grant semantics: a grant set is stored verbatim (``{read}`` ≠
``{write}``). Scope *hierarchy* (an EXEC grant implicitly satisfies a WRITE
requirement) is applied at *check* time by :meth:`Scope.satisfied_by`, not by
expanding the stored set — so revoking ``exec`` from ``{read, write, exec}``
correctly leaves ``{read, write}``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Iterable, Optional

import yaml

from .registry import Scope

logger = logging.getLogger("skcomms.access.grants")

_GRANTS_PATH = Path("~/.skcapstone/skcomms/access/grants.yml")

WILDCARD = "*"


def grants_path(path: Optional[Path] = None) -> Path:
    """Resolve the grants.yml path (override-able for tests)."""
    return (path or _GRANTS_PATH).expanduser()


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def _parse_scopes(raw) -> set[Scope]:
    if isinstance(raw, str):
        raw = [raw]
    return {Scope(str(s).strip().lower()) for s in (raw or []) if str(s).strip()}


def load_grants(path: Optional[Path] = None) -> dict[str, set[Scope]]:
    """Load the persistent grants store.

    Args:
        path: Alternate grants.yml path (testing).

    Returns:
        Map of identity -> granted :class:`Scope` set. ``{}`` if the file is
        absent or unparseable (a missing/broken store must never *grant* — it
        falls through to the server's defaults).
    """
    p = grants_path(path)
    if not p.exists():
        return {}
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # pragma: no cover - corrupt file
        logger.warning("grants.yml parse failed (%s) — ignoring store", exc)
        return {}
    raw = doc.get("grants", doc) if isinstance(doc, dict) else {}
    out: dict[str, set[Scope]] = {}
    for ident, scopes in (raw or {}).items():
        try:
            out[str(ident)] = _parse_scopes(scopes)
        except ValueError as exc:
            logger.warning("grants.yml: bad scope for %s (%s) — skipped", ident, exc)
    return out


def save_grants(grants: dict[str, set[Scope]], path: Optional[Path] = None) -> Path:
    """Persist the grants store atomically.

    Identities granting an empty set are dropped (revoking the last scope
    removes the identity entirely). Scopes are written in stable rank order.

    Returns:
        The path written.
    """
    p = grants_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {
        ident: [s.value for s in sorted(scopes, key=lambda x: x.rank)]
        for ident, scopes in sorted(grants.items())
        if scopes
    }
    tmp = p.with_suffix(".yml.tmp")
    tmp.write_text(yaml.safe_dump({"grants": body}, sort_keys=False), encoding="utf-8")
    tmp.replace(p)
    return p


# ---------------------------------------------------------------------------
# Merge into config
# ---------------------------------------------------------------------------


def merge_grants(
    base: dict[str, set[Scope]],
    overlay: dict[str, set[Scope]],
) -> dict[str, set[Scope]]:
    """Return ``base`` folded with ``overlay`` (overlay wins per-identity).

    For an identity present in both, the **overlay's** set replaces the base's
    (the persistent store is authoritative for identities it names — that's how
    a ``revoke`` actually removes a scope the static config granted). Identities
    only in ``base`` are kept as-is.
    """
    merged: dict[str, set[Scope]] = {k: set(v) for k, v in base.items()}
    for ident, scopes in overlay.items():
        merged[ident] = set(scopes)
    return merged


def apply_to_config(config, path: Optional[Path] = None) -> "object":
    """Load grants.yml and merge it into ``config.scope_grants`` in place.

    Args:
        config: An :class:`~skcomms.access.config.AccessConfig`.
        path: Alternate grants.yml path (testing).

    Returns:
        The same ``config`` (for chaining), with ``scope_grants`` merged.
    """
    persisted = load_grants(path)
    config.scope_grants = merge_grants(config.scope_grants, persisted)
    return config


# ---------------------------------------------------------------------------
# Mutators (used by the CLI)
# ---------------------------------------------------------------------------


def grant(identity: str, scopes: Iterable[Scope], path: Optional[Path] = None) -> set[Scope]:
    """Add ``scopes`` to ``identity`` in the persistent store and save.

    Returns the identity's resulting scope set.
    """
    store = load_grants(path)
    cur = store.get(identity, set())
    cur = cur | set(scopes)
    store[identity] = cur
    save_grants(store, path)
    return cur


def revoke(identity: str, scopes: Iterable[Scope], path: Optional[Path] = None) -> set[Scope]:
    """Remove ``scopes`` from ``identity`` in the persistent store and save.

    If the identity's set becomes empty it is dropped from the store entirely.
    Returns the identity's resulting scope set (possibly empty).
    """
    store = load_grants(path)
    cur = store.get(identity, set())
    cur = cur - set(scopes)
    if cur:
        store[identity] = cur
    else:
        store.pop(identity, None)
    save_grants(store, path)
    return cur


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _fmt(scopes: set[Scope]) -> str:
    return ",".join(s.value for s in sorted(scopes, key=lambda x: x.rank)) or "(none)"


def _cmd_list(args) -> int:
    store = load_grants(args.file)
    if not store:
        print("(no grants stored)")
        print(f"store: {grants_path(args.file)}")
        return 0
    for ident in sorted(store):
        print(f"{ident}\t{_fmt(store[ident])}")
    print(f"\nstore: {grants_path(args.file)}")
    return 0


def _parse_scope_args(raw: list[str]) -> set[Scope]:
    out: set[Scope] = set()
    for token in raw:
        for piece in token.replace(",", " ").split():
            out.add(Scope(piece.strip().lower()))
    return out


def _cmd_grant(args) -> int:
    try:
        scopes = _parse_scope_args(args.scopes)
    except ValueError as exc:
        print(f"error: bad scope ({exc}); valid: read, write, exec", file=sys.stderr)
        return 2
    if not scopes:
        print("error: no scopes given", file=sys.stderr)
        return 2
    result = grant(args.identity, scopes, args.file)
    print(f"granted {_fmt(scopes)} -> {args.identity}; now: {_fmt(result)}")
    print("note: reload or restart sk-access to apply (grants merge at server start).")
    return 0


def _cmd_revoke(args) -> int:
    try:
        scopes = _parse_scope_args(args.scopes)
    except ValueError as exc:
        print(f"error: bad scope ({exc}); valid: read, write, exec", file=sys.stderr)
        return 2
    if not scopes:
        print("error: no scopes given", file=sys.stderr)
        return 2
    result = revoke(args.identity, scopes, args.file)
    print(f"revoked {_fmt(scopes)} from {args.identity}; now: {_fmt(result)}")
    print("note: reload or restart sk-access to apply.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m skcomms.access.grants",
        description="Manage sk-access RBAC scope grants (grants.yml).",
    )
    p.add_argument(
        "--file", type=Path, default=None,
        help=f"grants.yml path (default: {_GRANTS_PATH})",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="list all grants")
    pl.set_defaults(func=_cmd_list)

    pg = sub.add_parser("grant", help="grant scope(s) to an identity (fqid or '*')")
    pg.add_argument("identity", help="fqid, e.g. lumina@chef.skworld, or '*'")
    pg.add_argument("scopes", nargs="+", help="one or more of: read write exec")
    pg.set_defaults(func=_cmd_grant)

    pr = sub.add_parser("revoke", help="revoke scope(s) from an identity")
    pr.add_argument("identity", help="fqid, e.g. lumina@chef.skworld, or '*'")
    pr.add_argument("scopes", nargs="+", help="one or more of: read write exec")
    pr.set_defaults(func=_cmd_revoke)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
