"""SKFed directory re-address: swap leaky funnel FQDNs for a NEUTRAL domain.

The live realm directory (:mod:`skcomms.skfed_directory`) advertises each agent's
``inbox_url`` / ``prekey_url``. When those are served off a raw Tailscale **funnel**
host, the URL is the node's tailnet name — e.g.
``https://cbrd21-laptop12thgenintelcore.tail204f0c.ts.net/api/v1/inbox`` — which
**leaks the operator's machine hostname** to every sender that fetches the
directory (coord ``d9cc87ad``).

This module is the fix: load the signed directory, rewrite every leaky
``*.ts.net`` endpoint to a **neutral custom domain** (``fed-<agent>.skworld.io``
by default), **re-sign** with the node key (:func:`skfed_directory.load_node_signer`),
and persist. It is:

* **idempotent** — an entry already on the neutral domain is left untouched, so
  re-running converges and reports zero changes;
* **dry-run-first** — :func:`reseed_neutral_addresses` with ``dry_run=True``
  (the default) computes + returns the before/after changes and writes **nothing**;
* **scoped** — only ``*.ts.net`` (leaky) hosts are rewritten unless
  ``only_leaky=False``; an optional ``fqids`` filter narrows it further.

The neutral domain only *helps privacy* once it actually fronts the funnel — see
``docs/funnel-privacy.md`` for the Cloudflare CNAME / origin-rule / CF-Tunnel
cutover (referencing ``UNIFIED_INGRESS_STANDARD``). This module rewrites the
**advertised** address; the operator runs that cutover so the neutral name
resolves to the same backend.

CLI::

    python -m skcomms.skfed_readdr            # dry-run: print before/after
    python -m skcomms.skfed_readdr --apply    # rewrite + re-sign + persist
    python -m skcomms.skfed_readdr --base-domain skworld.io --prefix fed- --apply
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from .signing import EnvelopeSigner
from .skfed_directory import (
    DirectoryEntry,
    SignedDirectory,
    load_directory,
    load_node_signer,
    save_directory,
)

DEFAULT_BASE_DOMAIN = "skworld.io"
DEFAULT_PREFIX = "fed-"
#: Hosts ending with this suffix are treated as leaky funnel/tailnet names.
DEFAULT_LEAKY_SUFFIX = ".ts.net"

#: The directory's URL fields this module rewrites.
_URL_FIELDS = ("inbox_url", "prekey_url")


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def agent_label(fqid: str) -> str:
    """Return the short agent label from a ``<agent>@<operator>.<realm>`` FQID.

    Lower-cased so it forms a valid DNS label (``Jarvis@..`` -> ``jarvis``).
    """
    return fqid.split("@", 1)[0].strip().lower()


def neutral_host_for(
    fqid: str,
    *,
    base_domain: str = DEFAULT_BASE_DOMAIN,
    prefix: str = DEFAULT_PREFIX,
) -> str:
    """Return the neutral host for an agent, e.g. ``fed-lumina.skworld.io``.

    Args:
        fqid: The agent FQID whose label seeds the subdomain.
        base_domain: The custom domain that fronts the funnel.
        prefix: Subdomain prefix (default ``fed-``).
    """
    return f"{prefix}{agent_label(fqid)}.{base_domain}"


def url_host(url: str) -> str:
    """Return the hostname of *url* (no port), or ``""`` if unparseable."""
    return (urlsplit(url).hostname or "").lower()


def is_leaky_host(host: str, *, leaky_suffix: str = DEFAULT_LEAKY_SUFFIX) -> bool:
    """Whether *host* is a leaky funnel/tailnet name (``*.ts.net`` by default)."""
    return host.lower().endswith(leaky_suffix)


def rewrite_url(url: str, new_host: str) -> str:
    """Return *url* with its host replaced by *new_host*.

    Scheme, path, query and fragment are preserved; any explicit port on the old
    (leaky) host is dropped — the neutral domain fronts the funnel on :443.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, new_host, parts.path, parts.query, parts.fragment))


# ---------------------------------------------------------------------------
# Change model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReseedChange:
    """One ``before -> after`` URL rewrite for a single directory entry field."""

    fqid: str
    field: str  # "inbox_url" | "prekey_url"
    before: str
    after: str


@dataclass
class ReseedResult:
    """Outcome of a (dry-run or applied) re-seed.

    Attributes:
        changes: The before/after rewrites that were (or would be) applied.
        entries_after: The full entry list after rewriting (pre-sign).
        signed: The freshly signed+persisted directory (``None`` on dry-run or
            when there was nothing to change).
        dry_run: Whether this was a dry-run (no write).
    """

    changes: list[ReseedChange] = field(default_factory=list)
    entries_after: list[DirectoryEntry] = field(default_factory=list)
    signed: Optional[SignedDirectory] = None
    dry_run: bool = True


# ---------------------------------------------------------------------------
# Core: compute rewrites + re-seed
# ---------------------------------------------------------------------------


def compute_rewrites(
    sd: SignedDirectory,
    *,
    base_domain: str = DEFAULT_BASE_DOMAIN,
    prefix: str = DEFAULT_PREFIX,
    leaky_suffix: str = DEFAULT_LEAKY_SUFFIX,
    only_leaky: bool = True,
    fqids: Optional[list[str]] = None,
) -> tuple[list[DirectoryEntry], list[ReseedChange]]:
    """Compute neutral-address rewrites for *sd* (no signing, no I/O).

    Returns the full rewritten entry list plus the list of changes. Entries
    already on the neutral domain (or non-leaky when ``only_leaky``) are left
    untouched, making this idempotent.
    """
    fqid_set = set(fqids) if fqids else None
    new_entries: list[DirectoryEntry] = []
    changes: list[ReseedChange] = []

    for entry in sd.entries:
        if fqid_set is not None and entry.fqid not in fqid_set:
            new_entries.append(entry)
            continue

        new_host = neutral_host_for(entry.fqid, base_domain=base_domain, prefix=prefix)
        updates: dict[str, str] = {}
        for fld in _URL_FIELDS:
            url = getattr(entry, fld)
            if not url:
                continue
            host = url_host(url)
            if only_leaky and not is_leaky_host(host, leaky_suffix=leaky_suffix):
                continue
            if host == new_host:
                continue  # already neutral -> idempotent no-op
            new_url = rewrite_url(url, new_host)
            updates[fld] = new_url
            changes.append(
                ReseedChange(fqid=entry.fqid, field=fld, before=url, after=new_url)
            )

        new_entries.append(entry.model_copy(update=updates) if updates else entry)

    return new_entries, changes


def reseed_neutral_addresses(
    *,
    base_domain: str = DEFAULT_BASE_DOMAIN,
    prefix: str = DEFAULT_PREFIX,
    leaky_suffix: str = DEFAULT_LEAKY_SUFFIX,
    only_leaky: bool = True,
    fqids: Optional[list[str]] = None,
    agent: Optional[str] = None,
    signer: Optional[EnvelopeSigner] = None,
    dry_run: bool = True,
    directory: Optional[SignedDirectory] = None,
) -> ReseedResult:
    """Re-seed the realm directory's leaky endpoints with neutral addresses.

    Loads the persisted directory, rewrites leaky ``*.ts.net`` ``inbox_url`` /
    ``prekey_url`` to ``<prefix><agent>.<base_domain>``, and (unless
    ``dry_run``) re-signs with the node key and persists.

    Args:
        base_domain: Neutral custom domain fronting the funnel (``skworld.io``).
        prefix: Subdomain prefix (``fed-``).
        leaky_suffix: Host suffix considered leaky (``.ts.net``).
        only_leaky: Rewrite only leaky hosts (default). ``False`` rewrites all.
        fqids: Optional subset of FQIDs to rewrite.
        agent: Agent name for :func:`load_node_signer` (defaults to self).
        signer: Override the re-signing key (defaults to the node signer).
        dry_run: When ``True`` (default), compute + return changes, write NOTHING.
        directory: Inject a directory instead of loading from disk (tests).

    Returns:
        ReseedResult: the changes, the post-rewrite entries, and (when applied)
        the freshly signed + persisted directory.
    """
    sd = directory if directory is not None else load_directory()
    if sd is None:
        return ReseedResult(changes=[], entries_after=[], signed=None, dry_run=dry_run)

    new_entries, changes = compute_rewrites(
        sd,
        base_domain=base_domain,
        prefix=prefix,
        leaky_suffix=leaky_suffix,
        only_leaky=only_leaky,
        fqids=fqids,
    )

    if dry_run or not changes:
        return ReseedResult(
            changes=changes, entries_after=new_entries, signed=None, dry_run=dry_run
        )

    signer = signer or load_node_signer(agent)
    signed = SignedDirectory.build(
        realm=sd.realm, operator=sd.operator, entries=new_entries, signer=signer
    )
    save_directory(signed)
    return ReseedResult(
        changes=changes, entries_after=new_entries, signed=signed, dry_run=False
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _format_changes(result: ReseedResult) -> str:
    if not result.changes:
        return "  (no leaky endpoints — directory already neutral / nothing to do)"
    lines = []
    for c in result.changes:
        lines.append(f"  {c.fqid}  [{c.field}]")
        lines.append(f"    - {c.before}")
        lines.append(f"    + {c.after}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint: dry-run by default, ``--apply`` to rewrite + re-sign."""
    ap = argparse.ArgumentParser(
        prog="skcomms.skfed_readdr",
        description="Re-seed the SKFed directory with neutral fed-<agent>.<domain> addresses.",
    )
    ap.add_argument("--base-domain", default=DEFAULT_BASE_DOMAIN)
    ap.add_argument("--prefix", default=DEFAULT_PREFIX)
    ap.add_argument("--leaky-suffix", default=DEFAULT_LEAKY_SUFFIX)
    ap.add_argument("--all", action="store_true", help="rewrite ALL hosts, not just leaky *.ts.net")
    ap.add_argument("--fqid", action="append", default=None, help="limit to these FQID(s); repeatable")
    ap.add_argument("--agent", default=None, help="agent name for the node signer")
    ap.add_argument("--apply", action="store_true", help="APPLY the rewrite (default is dry-run)")
    args = ap.parse_args(argv)

    dry_run = not args.apply
    result = reseed_neutral_addresses(
        base_domain=args.base_domain,
        prefix=args.prefix,
        leaky_suffix=args.leaky_suffix,
        only_leaky=not args.all,
        fqids=args.fqid,
        agent=args.agent,
        dry_run=dry_run,
    )

    banner = "DRY-RUN (no changes written)" if dry_run else "APPLIED (re-signed + persisted)"
    print(f"=== skfed neutral re-address — {banner} ===")
    print(_format_changes(result))
    if dry_run and result.changes:
        print("\nRe-run with --apply to rewrite + re-sign + persist.")
    if (not dry_run) and result.signed is not None:
        print(f"\nre-signed by fingerprint: {result.signed.signer_fingerprint}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
