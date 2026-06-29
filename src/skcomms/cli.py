"""
SKComms CLI — sovereign agent messaging from the command line.

Send, receive, and manage messages across all transports
from any terminal. Works standalone or alongside the daemon.

Usage:
    skcomms send lumina "Hello from the terminal"
    skcomms receive
    skcomms status
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Optional

import click

import logging
logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
except ImportError:
    console = None  # type: ignore[assignment]

from . import __version__
from .config import SKCOMMS_HOME

_HOME = SKCOMMS_HOME


def _print(msg: str) -> None:
    """Print using rich if available, else plain click.echo."""
    if console:
        console.print(msg)
    else:
        click.echo(msg)


@click.group()
@click.version_option(version=__version__, prog_name="skcomms")
def main():
    """SKComms — Sovereign Agent Communication.

    Transport-agnostic encrypted messaging.
    One message. Many paths. Always delivered.
    """


@main.command("send-transport")
@click.argument("recipient")
@click.argument("message")
@click.option("--config", "-c", default=None, help="Config file path.")
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["failover", "broadcast", "stealth", "speed"]),
    default=None,
    help="Override routing mode.",
)
@click.option("--thread", "-t", default=None, help="Thread ID for conversation grouping.")
@click.option("--reply-to", default=None, help="Envelope ID this replies to.")
@click.option(
    "--urgency",
    "-u",
    type=click.Choice(["low", "normal", "high", "critical"]),
    default="normal",
)
def send(
    recipient: str,
    message: str,
    config: Optional[str],
    mode: Optional[str],
    thread: Optional[str],
    reply_to: Optional[str],
    urgency: str,
):
    """Send a message to another agent.

    Messages are routed through all configured transports
    based on the routing mode (default: failover).

    Examples:

        skcomms send lumina "Sync complete on desktop"

        skcomms send opus "Need review" --urgency high
    """
    from .core import SKComms
    from .models import RoutingMode, Urgency

    comm = SKComms.from_config(config)
    mode_enum = RoutingMode(mode) if mode else None
    urgency_enum = Urgency(urgency)

    report = comm.send(
        recipient=recipient,
        message=message,
        mode=mode_enum,
        thread_id=thread,
        in_reply_to=reply_to,
        urgency=urgency_enum,
    )

    if report.delivered:
        via = report.successful_transport or "unknown"
        _print(f"\n  [green]Sent[/] to [bold]{recipient}[/] via {via}")
        for a in report.attempts:
            if a.success:
                _print(f"    [dim]{a.transport_name}: {a.latency_ms:.1f}ms[/]")
    else:
        _print(f"\n  [red]Failed[/] to send to [bold]{recipient}[/]")
        for a in report.attempts:
            _print(f"    [red]{a.transport_name}: {a.error}[/]")
        sys.exit(1)
    _print("")


@main.command()
@click.option("--config", "-c", default=None, help="Config file path.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def receive(config: Optional[str], json_out: bool):
    """Check all transports for incoming messages.

    Polls every configured transport, deduplicates, and
    displays received messages.
    """
    from .core import SKComms

    comm = SKComms.from_config(config)
    envelopes = comm.receive()

    if not envelopes:
        _print("\n  [dim]No new messages.[/]\n")
        return

    if json_out:
        for env in envelopes:
            click.echo(env.model_dump_json(indent=2))
        return

    _print(f"\n  [bold]{len(envelopes)}[/] message(s) received:\n")

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("From", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Content", max_width=60)
        table.add_column("Thread", style="dim", max_width=12)
        table.add_column("Urgency")

        urgency_colors = {
            "low": "dim",
            "normal": "white",
            "high": "yellow",
            "critical": "bold red",
        }

        for env in envelopes:
            preview = env.payload.content[:80] + ("..." if len(env.payload.content) > 80 else "")
            urg = env.metadata.urgency.value
            urg_color = urgency_colors.get(urg, "white")
            tid = env.metadata.thread_id[:12] if env.metadata.thread_id else ""
            table.add_row(
                env.sender,
                env.payload.content_type.value,
                preview,
                tid,
                f"[{urg_color}]{urg.upper()}[/]",
            )

        console.print(table)
    else:
        for env in envelopes:
            click.echo(
                f"  {env.sender} [{env.payload.content_type.value}]: {env.payload.content[:80]}"
            )

    _print("")


@main.command()
@click.option("--config", "-c", default=None, help="Config file path.")
@click.option("--interval", "-i", default=5, type=int, help="Poll interval in seconds.")
@click.option("--all-agents", is_flag=True, help="Receive for all local agents (auto-discover).")
def daemon(config: Optional[str], interval: int, all_agents: bool):
    """Run a background receive daemon that polls for messages.

    Continuously polls all configured transports at the given interval.
    With --all-agents, discovers all agents in ~/.skcapstone/agents/
    and receives for all of them with a single daemon.

    \b
    Examples:
        skcomms daemon                    # Poll every 5s for current agent
        skcomms daemon --all-agents       # Poll for all agents
        skcomms daemon -i 10 --all-agents # Poll every 10s for all agents
    """
    import signal
    import time

    from .config import load_config
    from .core import SKComms

    cfg = load_config(config)

    # If --all-agents, inject agents: auto into syncthing transport settings
    if all_agents:
        for tname, tconf in cfg.transports.items():
            if tname == "syncthing":
                tconf.settings["agents"] = "auto"

    comm = SKComms.from_config(config)

    # Re-configure syncthing transport if --all-agents was used
    if all_agents:
        for transport in comm.router.transports:
            if hasattr(transport, "_agents_mode") and transport._agents_mode != "auto":
                transport._agents_mode = "auto"
                transport._discover_agents()

    agent_name = comm.identity
    agents_info = ""
    for transport in comm.router.transports:
        if hasattr(transport, "_local_names"):
            agents_info = f" (scanning for: {', '.join(transport._local_names)})"
            break

    _print("\n  [bold]SKComms daemon started[/]")
    _print(f"  Identity: [cyan]{agent_name}[/]{agents_info}")
    _print(f"  Poll interval: {interval}s")
    _print("  Press Ctrl+C to stop.\n")

    running = True

    def _shutdown(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    total_received = 0
    while running:
        try:
            envelopes = comm.receive()
            if envelopes:
                total_received += len(envelopes)
                for env in envelopes:
                    preview = env.payload.content[:60]
                    urg = env.metadata.urgency.value.upper()
                    _print(f"  [green]>[/] [{urg}] {env.sender} → {env.recipient}: {preview}")
        except Exception as exc:
            logger.warning("cli.py: %s", exc)
            _print(f"  [red]Error during receive: {exc}[/]")

        time.sleep(interval)

    _print(f"\n  Daemon stopped. {total_received} message(s) received total.\n")


@main.command()
@click.option("--config", "-c", default=None, help="Config file path.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def status(config: Optional[str], json_out: bool):
    """Show SKComms status and transport health."""
    from .core import SKComms

    comm = SKComms.from_config(config)
    st = comm.status()

    if json_out:
        click.echo(json.dumps(st, indent=2, default=str))
        return

    ident = st["identity"]
    _print("")
    if console:
        console.print(
            Panel(
                f"Identity: [bold cyan]{ident.get('name', 'unknown')}[/]\n"
                f"Fingerprint: {ident.get('fingerprint') or '[dim]none[/]'}\n"
                f"Mode: [bold]{st['default_mode']}[/]\n"
                f"Encrypt: {'[green]yes[/]' if st['encrypt'] else '[red]no[/]'}\n"
                f"Sign: {'[green]yes[/]' if st['sign'] else '[red]no[/]'}\n"
                f"Transports: [bold]{st['transport_count']}[/]",
                title="SKComms",
                border_style="bright_blue",
            )
        )

    transports = st.get("transports", {})
    if transports and console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Transport", style="bold")
        table.add_column("Status")
        table.add_column("Latency", justify="right")
        table.add_column("Details", style="dim")

        status_colors = {
            "available": "green",
            "degraded": "yellow",
            "unavailable": "red",
        }

        for name, health in transports.items():
            if isinstance(health, dict):
                s = health.get("status", "unknown")
                color = status_colors.get(s, "dim")
                lat = f"{health.get('latency_ms', 0):.1f}ms" if health.get("latency_ms") else ""
                err = health.get("error", "")
                table.add_row(name, f"[{color}]{s.upper()}[/]", lat, err)

                if s == "degraded" and health.get("details", {}).get("disk_warning"):
                    _print(f"\n  [bold yellow]⚠ {health['details']['disk_warning']}[/]")

        console.print(table)

    _print("")


def _detect_syncthing() -> Optional[str]:
    """Auto-detect the Syncthing comms root directory.

    Checks common locations: ~/.skcapstone/comms, ~/Sync/comms,
    and queries the Syncthing API if available.

    Returns:
        str: Path to comms_root if found, else None.
    """
    # Reason: prefer the Syncthing-shared path over the local-only default
    candidates = [
        Path("~/.skcapstone/sync/comms").expanduser(),
        Path("~/.skcapstone/comms").expanduser(),
        Path("~/Sync/skcomms").expanduser(),
        Path("~/Sync/comms").expanduser(),
        Path("~/.local/share/syncthing/skcomms").expanduser(),
    ]
    for path in candidates:
        if path.exists():
            return str(path)

    try:
        import subprocess

        result = subprocess.run(
            ["syncthing", "--version"],
            capture_output=True,
            timeout=3,
            check=False,
        )
        if result.returncode == 0:
            return str(Path("~/.skcapstone/comms").expanduser())
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass

    return None


def _check_disk_space_warning(comms_path: Path) -> None:
    """Warn if disk space is low enough to trigger Syncthing's minDiskFree.

    Syncthing defaults to 1% free — on a 2TB drive that's ~20GB. If
    you're near capacity, Syncthing silently refuses to sync new files.
    This has caused hours of debugging in production.

    Args:
        comms_path: Path to the comms root directory.
    """
    import shutil as _shutil

    try:
        target = Path(comms_path).expanduser()
        target.mkdir(parents=True, exist_ok=True)
        usage = _shutil.disk_usage(target)
        free_pct = (usage.free / usage.total) * 100
        free_gb = usage.free / (1024**3)
        total_gb = usage.total / (1024**3)
        threshold_gb = total_gb * 0.01

        if free_pct < 1.5:
            _print(f"  [bold red]⚠ LOW DISK SPACE[/]: {free_gb:.1f}GB free ({free_pct:.1f}%)")
            _print(
                f"    Syncthing default minDiskFree = 1% = [bold]{threshold_gb:.0f}GB[/] on this {total_gb:.0f}GB volume"
            )
            _print(
                "    Sync will be [bold red]BLOCKED[/] until you free space or lower the threshold."
            )
            _print("    Fix: set minDiskFree to 100MB in Syncthing folder settings.")
        elif free_pct < 5:
            _print(
                f"  [yellow]![/] Disk space: {free_gb:.1f}GB free ({free_pct:.1f}%) — watch for Syncthing minDiskFree threshold"
            )
        else:
            _print(f"  [green]✓[/] Disk space: {free_gb:.1f}GB free ({free_pct:.1f}%)")
    except OSError:
        pass


def _test_file_transport_ping(drop_root: Path) -> bool:
    """Test the file transport by writing and removing a probe file.

    Args:
        drop_root: The filedrop root directory.

    Returns:
        bool: True if the write/read/remove succeeded.
    """
    import time

    probe = drop_root / "inbox" / f".skcomms_probe_{int(time.time())}.tmp"
    try:
        probe.write_text("ping")
        result = probe.exists() and probe.read_text() == "ping"
        probe.unlink(missing_ok=True)
        return result
    except OSError:
        return False


@main.command("init")
@click.option("--agent", "-a", default=None, help="Agent name (defaults to resolved identity).")
def init(agent: Optional[str]):
    """Initialize the ~/.skcapstone/skcomms/ realm message tree.

    Creates ``~/.skcapstone/skcomms/<realm>/<operator>/<agent>/{outbox,inbox}`` derived
    from cluster.json + the resolved agent identity, plus a top-level
    ``.stignore`` so Syncthing ignores volatile/local files. Idempotent.

    Honors the ``SKCOMMS_HOME`` env override (default ``~/.skcapstone/skcomms``).

    Examples:

        skcomms init

        skcomms init --agent lumina
    """
    from .home import scaffold

    info = scaffold(agent=agent)
    _print(f"\n  [bold green]skcomms initialized[/] for [cyan]{info['agent']}[/]\n")
    _print(f"  Home:     [dim]{info['home']}[/]")
    _print(f"  FQID dir: [dim]{info['agent_dir']}[/]")
    _print(f"  Outbox:   [dim]{info['outbox']}[/]")
    _print(f"  Inbox:    [dim]{info['inbox']}[/]")
    _print(f"  Ignore:   [dim]{info['stignore']}[/]")
    _print("")


@main.command("send")
@click.argument("to_fqid")
@click.argument("message")
@click.option("--agent", "-a", default=None, help="Sending agent (defaults to identity).")
@click.option("--subject", "-s", default=None, help="Optional subject.")
@click.option("--thread", "-t", default=None, help="Thread id for conversation grouping.")
@click.option("--reply-to", default=None, help="Envelope id this replies to.")
def send(
    to_fqid: str,
    message: str,
    agent: Optional[str],
    subject: Optional[str],
    thread: Optional[str],
    reply_to: Optional[str],
):
    """Send a signed Envelope v1 to a peer FQID.

    Builds an Envelope v1 from the resolved identity, signs it, and drops
    it in the sender's outbox + the peer's inbox under ~/.skcapstone/skcomms.

    Examples:

        skcomms send opus@chef.skworld "sync complete"

        skcomms send jarvis@chef.skworld "review please" --subject PR
    """
    from .mailbox import send_message

    try:
        result = send_message(
            to_fqid,
            message,
            agent=agent,
            subject=subject,
            thread_id=thread,
            reply_to=reply_to,
        )
    except (ValueError, FileNotFoundError) as exc:
        _print(f"\n  [red]Send failed:[/] {exc}\n")
        sys.exit(1)

    _print(f"\n  [green]Sent[/] [dim]{result['id']}[/]")
    _print(f"  [bold]{result['from_fqid']}[/] -> [bold]{result['to_fqid']}[/]")
    _print(f"  [dim]outbox:[/] {result['outbox_path']}")
    _print(f"  [dim]peer:  [/] {result['peer_inbox_path']}")
    _print("")


@main.command("inbox")
@click.option("--agent", "-a", default=None, help="Agent whose inbox to read.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def inbox(agent: Optional[str], json_out: bool):
    """List + verify signed messages in this agent's inbox.

    Reads SignedEnvelopes from ~/.skcapstone/skcomms/<realm>/<operator>/<agent>/inbox,
    verifying each signature against the sender's known public key.
    """
    from .mailbox import read_inbox

    items = read_inbox(agent=agent)

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [
                    {
                        "envelope": env.to_dict(),
                        "verified": v.valid,
                        "reason": v.reason,
                    }
                    for env, v in items
                ],
                indent=2,
            )
        )
        return

    if not items:
        _print("\n  [dim]Inbox empty.[/]\n")
        return

    _print(f"\n  [bold]{len(items)}[/] message(s):\n")
    for env, v in items:
        mark = "[green]✓[/]" if v.valid else "[red]✗[/]"
        subj = f" — {env.subject}" if env.subject else ""
        _print(f"  {mark} [cyan]{env.from_fqid}[/]{subj}")
        preview = env.body[:80] + ("..." if len(env.body) > 80 else "")
        _print(f"      [dim]{preview}[/]")
        if not v.valid:
            _print(f"      [red]{v.reason}[/]")
    _print("")


@main.group("peers", invoke_without_command=True)
@click.option("--agent", "-a", default=None, help="This agent (excluded from list).")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def peers(ctx: click.Context, agent: Optional[str], json_out: bool):
    """Realm peers — list the message tree, or add/show connectivity records.

    Run without a subcommand to list known peers in the ~/.skcapstone/skcomms realm
    tree (each <realm>/<operator>/<agent> dir other than this agent's, with
    its inbox message count). Use the ``add``/``show`` subcommands to manage
    the Syncthing-device + PGP-key bindings in ``peers.json`` (T8).
    """
    if ctx.invoked_subcommand is not None:
        return

    from .mailbox import list_peers

    found = list_peers(agent=agent)

    if json_out:
        import json as _json

        click.echo(_json.dumps(found, indent=2))
        return

    if not found:
        _print("\n  [dim]No peers known yet.[/]\n")
        return

    _print(f"\n  [bold]{len(found)}[/] peer(s):\n")
    for p in found:
        _print(f"  [cyan]{p['fqid']}[/]  [dim]({p['messages']} msg)[/]")
    _print("")


@peers.command("add")
@click.argument("peer_fqid")
@click.option(
    "--syncthing-device-id",
    "device_id",
    default=None,
    help="The peer's Syncthing device id (how the realm tree replicates).",
)
@click.option(
    "--pubkey",
    "pubkey",
    default=None,
    type=click.Path(),
    help="Path to the peer's ASCII-armored PGP public key.",
)
@click.option(
    "--via-registry",
    is_flag=True,
    help="Resolve the peer (device id + pubkey) via the T11 realm registry.",
)
@click.option(
    "--tailscale",
    "tailscale_node",
    default=None,
    help="Point/add the peer by Tailscale node (records the tailscale hint).",
)
def peers_add(
    peer_fqid: str,
    device_id: Optional[str],
    pubkey: Optional[str],
    via_registry: bool,
    tailscale_node: Optional[str],
):
    """Wire a peer's Syncthing device id + PGP key into ``peers.json``.

    Validates the FQID, derives the PGP fingerprint from --pubkey (pure pgpy,
    no keyring side effects), TOFU-binds fqid->fingerprint (a conflicting
    fingerprint on re-add is REFUSED), and records the peer (idempotent).

    With ``--via-registry`` the device id + public key are resolved from the
    T11 realm peer registry (sovereign syncthing-shared backend by default)
    instead of being passed explicitly. ``--tailscale <node>`` additionally
    records a Tailscale connectivity hint for the peer.

    Examples:

        skcomms peers add opus@casey.douno \\
            --syncthing-device-id ABCDEF1-...-2345678 \\
            --pubkey ./opus.asc

        skcomms peers add opus@casey.douno --via-registry

        skcomms peers add opus@casey.douno --via-registry --tailscale skcomms-opus-casey
    """
    import tempfile

    from .peers import add_peer

    resolved_tailscale: Optional[dict] = None

    if via_registry:
        from .registry import PeerRegistry

        reg = PeerRegistry.from_config()
        rec_resolved = reg.resolve(peer_fqid)
        if rec_resolved is None:
            _print(f"\n  [red]Registry could not resolve[/] [bold]{peer_fqid}[/]")
            _print(
                "  [dim]No enabled backend has this peer. Publish it to the "
                "shared realm file (_realm/peers.json) or add it explicitly "
                "with --syncthing-device-id + --pubkey.[/]\n"
            )
            raise SystemExit(1)

        device_id = device_id or rec_resolved.syncthing_device_id
        resolved_tailscale = rec_resolved.tailscale

        if not device_id:
            _print(
                f"\n  [red]Registry resolved[/] {peer_fqid} [red]but it has no "
                "Syncthing device id[/] — cannot wire the realm tree.\n"
            )
            raise SystemExit(1)

        if not pubkey:
            if not rec_resolved.pubkey:
                _print(
                    f"\n  [red]Registry resolved[/] {peer_fqid} [red]but carries "
                    "no public key[/] — supply --pubkey to TOFU-bind it.\n"
                )
                raise SystemExit(1)
            _tmp = tempfile.NamedTemporaryFile(
                "w", suffix=".asc", delete=False, encoding="utf-8"
            )
            _tmp.write(rec_resolved.pubkey)
            _tmp.close()
            pubkey = _tmp.name

    if tailscale_node:
        # Explicit --tailscale node sets/overrides the recorded hint.
        resolved_tailscale = {"node": tailscale_node}

    if not device_id or not pubkey:
        _print(
            "\n  [red]Both --syncthing-device-id and --pubkey are required[/] "
            "(or use --via-registry to resolve them).\n"
        )
        raise SystemExit(2)

    try:
        rec = add_peer(peer_fqid, syncthing_device_id=device_id, pubkey_path=pubkey)
    except (ValueError, FileNotFoundError) as exc:
        _print(f"\n  [red]Peer add failed:[/] {exc}\n")
        raise SystemExit(1)

    status_label = {
        "trust_new": "[green]new (TOFU-pinned)[/]",
        "trust_match": "[cyan]already trusted[/]",
    }.get(rec["status"], rec["status"])
    _print(f"\n  [green]Peer added[/] [bold]{rec['fqid']}[/]  {status_label}")
    _print(f"  Device:      [dim]{rec['syncthing_device_id']}[/]")
    _print(f"  Fingerprint: [dim]{rec['fingerprint']}[/]")
    if resolved_tailscale:
        _print(f"  Tailscale:   [dim]{resolved_tailscale.get('node') or '?'}[/]")
    _print(f"  Added:       [dim]{rec['added_at']}[/]\n")


@peers.command("show")
@click.argument("peer_fqid")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def peers_show(peer_fqid: str, json_out: bool):
    """Show a peer's stored connectivity record from ``peers.json``.

    Examples:

        skcomms peers show opus@casey.douno
    """
    from .peers import show_peer

    entry = show_peer(peer_fqid)
    if entry is None:
        if json_out:
            click.echo("null")
        else:
            _print(f"\n  [yellow]No peer record for[/] {peer_fqid}\n")
        raise SystemExit(1)

    if json_out:
        click.echo(json.dumps(entry, indent=2))
        return

    _print(f"\n  [bold cyan]{peer_fqid}[/]")
    _print(f"  Device:      [dim]{entry['syncthing_device_id']}[/]")
    _print(f"  Fingerprint: [dim]{entry['fingerprint']}[/]")
    _print(f"  Added:       [dim]{entry['added_at']}[/]\n")


@main.group("registry")
def registry_group():
    """Realm peer registry — inspect the multi-backend peer resolver (T11).

    The registry resolves an fqid to a connectivity record by consulting one
    or more pluggable backends (sovereign Syncthing-shared file by default,
    plus opt-in HTTPS + Tailscale) and merging their hints. Use ``list`` to
    enumerate known peers and ``resolve`` to inspect a single fqid.
    """


@registry_group.command("list")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def registry_list(json_out: bool):
    """List every peer the enabled registry backends know about.

    Examples:

        skcomms registry list

        skcomms registry list --json-out
    """
    from .registry import PeerRegistry

    recs = PeerRegistry.from_config().list()

    if json_out:
        click.echo(json.dumps([r.to_dict() for r in recs], indent=2))
        return

    if not recs:
        _print("\n  [dim]No peers known to any enabled registry backend.[/]\n")
        return

    _print(f"\n  [bold]{len(recs)}[/] registry peer(s):\n")
    for r in recs:
        hints = []
        if r.syncthing_device_id:
            hints.append("syncthing")
        if r.tailscale:
            hints.append("tailscale")
        if r.https:
            hints.append("https")
        via = ", ".join(r.sources) or "-"
        _print(
            f"  [cyan]{r.fqid}[/]  [dim]({', '.join(hints) or 'no hints'} — via {via})[/]"
        )
    _print("")


@registry_group.command("resolve")
@click.argument("peer_fqid")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def registry_resolve(peer_fqid: str, json_out: bool):
    """Resolve a single fqid across the enabled registry backends.

    Examples:

        skcomms registry resolve opus@casey.douno

        skcomms registry resolve opus@casey.douno --json-out
    """
    from .registry import PeerRegistry

    try:
        rec = PeerRegistry.from_config().resolve(peer_fqid)
    except ValueError as exc:
        _print(f"\n  [red]Invalid fqid:[/] {exc}\n")
        raise SystemExit(2)

    if rec is None:
        if json_out:
            click.echo("null")
        else:
            _print(f"\n  [yellow]Could not resolve[/] {peer_fqid} [dim](no backend has it)[/]\n")
        raise SystemExit(1)

    if json_out:
        click.echo(json.dumps(rec.to_dict(), indent=2))
        return

    _print(f"\n  [bold cyan]{rec.fqid}[/]")
    _print(f"  Operator:    [dim]{rec.operator}[/]")
    if rec.pgp_fingerprint:
        _print(f"  Fingerprint: [dim]{rec.pgp_fingerprint}[/]")
    if rec.syncthing_device_id:
        _print(f"  Device:      [dim]{rec.syncthing_device_id}[/]")
    if rec.tailscale:
        _print(f"  Tailscale:   [dim]{rec.tailscale}[/]")
    if rec.https:
        _print(f"  HTTPS:       [dim]{rec.https}[/]")
    _print(f"  Via:         [dim]{', '.join(rec.sources) or '-'}[/]\n")


@main.command("init-config")
@click.option("--name", default=None, help="Your agent identity name.")
@click.option("--fingerprint", default=None, help="PGP fingerprint for signing.")
@click.option("--force", "-f", is_flag=True, help="Overwrite existing config without prompt.")
def init_config(name: Optional[str], fingerprint: Optional[str], force: bool):
    """Initialize SKComms transport configuration (legacy ~/.skcapstone/skcomms/config.yml).

    Creates ~/.skcapstone/skcomms/config.yml with sensible defaults,
    auto-detects Syncthing, tests file transport connectivity,
    and prints a setup summary.

    Examples:

        skcomms init

        skcomms init --name jarvis

        skcomms init --name jarvis --fingerprint ABC123 --force
    """
    import yaml

    home = Path(_HOME).expanduser()
    home.mkdir(parents=True, exist_ok=True)

    config_path = home / "config.yml"

    if config_path.exists() and not force:
        if not click.confirm(f"Config already exists at {config_path}. Overwrite?", default=False):
            _print("[yellow]Aborted.[/]")
            return

    # Prompt for agent name if not provided
    if not name:
        import os

        default_name = os.environ.get("USER", "agent")
        name = click.prompt("Agent name", default=default_name)

    _print(f"\n  [bold]Initializing SKComms for [cyan]{name}[/]...[/]\n")

    # Detect Syncthing
    comms_root = _detect_syncthing()
    if comms_root:
        _print(f"  [green]✓[/] Syncthing comms root detected: [dim]{comms_root}[/]")
    else:
        comms_root = str(Path("~/.skcapstone/comms").expanduser())
        _print(f"  [yellow]![/] Syncthing not detected. Using default: [dim]{comms_root}[/]")
        _print("    Run [cyan]syncthing[/] and share a folder to enable P2P messaging.")

    # Setup directories
    filedrop = home / "filedrop"
    (home / "logs").mkdir(exist_ok=True)
    (filedrop / "inbox").mkdir(parents=True, exist_ok=True)
    (filedrop / "outbox").mkdir(parents=True, exist_ok=True)
    (home / "peers").mkdir(exist_ok=True)

    # Test file transport connectivity
    file_ok = _test_file_transport_ping(filedrop)
    if file_ok:
        _print(f"  [green]✓[/] File transport: OK [dim]({filedrop})[/]")
    else:
        _print(f"  [red]✗[/] File transport: write test failed at [dim]{filedrop}[/]")

    # Disk space check — Syncthing silently blocks sync below 1% free
    _check_disk_space_warning(Path(comms_root))

    config = {
        "skcomms": {
            "version": "1.0.0",
            "identity": {"name": name},
            "defaults": {
                "mode": "failover",
                "encrypt": True,
                "sign": True,
                "ack": True,
                "retry_max": 5,
                "ttl": 86400,
            },
            "transports": {
                "syncthing": {
                    "enabled": True,
                    "priority": 1,
                    "settings": {
                        "comms_root": comms_root,
                    },
                },
                "file": {
                    "enabled": True,
                    "priority": 2,
                    "settings": {
                        "drop_root": str(filedrop),
                    },
                },
            },
        }
    }

    if fingerprint:
        config["skcomms"]["identity"]["fingerprint"] = fingerprint

    config_path.write_text(yaml.dump(config, default_flow_style=False))
    _print(f"  [green]✓[/] Config written: [dim]{config_path}[/]")

    # Summary
    _print("\n  [bold green]SKComms ready![/]")
    _print(f"  Identity:   [bold cyan]{name}[/]")
    if fingerprint:
        _print(f"  Fingerprint: [dim]{fingerprint}[/]")
    _print("  Transports: syncthing (priority 1), file (priority 2)")
    _print(f"  Config:     [dim]{config_path}[/]")
    _print("  API:        [dim]skcomms serve[/] (port 9384)")
    _print("  Send test:  [dim]skcomms send <peer> 'hello'[/]")
    _print("")


@main.group("peer")
def peer_group():
    """Peer directory — add, list, and remove peers.

    Maps friendly agent names to transport addresses.
    Peers are stored in ~/.skcapstone/skcomms/peers/ and used by the router
    when resolving recipient names.
    """


@peer_group.command("add")
@click.argument("name")
@click.argument("address")
@click.option(
    "--transport",
    "-t",
    default="syncthing",
    type=click.Choice(["syncthing", "file", "nostr"]),
    help="Transport type (default: syncthing).",
)
@click.option("--fingerprint", default=None, help="PGP fingerprint for this peer.")
def peer_add(name: str, address: str, transport: str, fingerprint: Optional[str]):
    """Add or update a peer in the directory.

    Maps a friendly agent name to a transport address.
    The address is interpreted based on the transport type:
    - syncthing: path to the comms_root directory
    - file:      path to the shared inbox directory
    - nostr:     hex pubkey or relay URL

    Examples:

        skcomms peer add lumina ~/.skcapstone/comms --transport syncthing

        skcomms peer add opus /mnt/shared/inbox --transport file

        skcomms peer add hal9000 abc123...def --transport nostr
    """
    from .discovery import PeerInfo, PeerStore, PeerTransport

    settings: dict = {}
    if transport == "syncthing":
        settings = {"comms_root": address}
    elif transport == "file":
        settings = {"inbox_path": address}
    else:
        settings = {"address": address}

    peer = PeerInfo(
        name=name,
        fingerprint=fingerprint,
        transports=[PeerTransport(transport=transport, settings=settings)],
        discovered_via="manual",
    )

    store = PeerStore()
    store.add(peer)
    _print(f"\n  [green]Peer added:[/] [bold]{name}[/]")
    _print(f"  Transport: [cyan]{transport}[/]")
    _print(f"  Address:   [dim]{address}[/]")
    if fingerprint:
        _print(f"  Fingerprint: [dim]{fingerprint}[/]")
    _print("")


@peer_group.command("remove")
@click.argument("name")
def peer_remove(name: str):
    """Remove a peer from the directory.

    Examples:

        skcomms peer remove lumina
    """
    from .discovery import PeerStore

    store = PeerStore()
    removed = store.remove(name)
    if removed:
        _print(f"\n  [green]Removed peer:[/] {name}\n")
    else:
        _print(f"\n  [yellow]Peer not found:[/] {name}\n")


@peer_group.command("list")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def peer_list(json_out: bool):
    """List all peers in the directory.

    Shows peers stored via `skcomms peer add` or discovered
    automatically, with transport endpoints and last-seen times.
    """
    from .discovery import PeerStore

    store = PeerStore()
    all_peers = store.list_all()

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [p.model_dump(mode="json", exclude_none=True) for p in all_peers],
                indent=2,
            )
        )
        return

    if not all_peers:
        _print("\n  [dim]No peers in directory.[/]")
        _print("  [dim]Run [bold]skcomms peer add <name> <address>[/] to add one.[/]\n")
        return

    _print(f"\n  [bold]{len(all_peers)}[/] peer(s):\n")

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Name", style="cyan")
        table.add_column("Transports", style="dim")
        table.add_column("Via", style="dim")
        table.add_column("Last Seen")
        table.add_column("Fingerprint", style="dim", max_width=16)

        for p in all_peers:
            transports = ", ".join(t.transport for t in p.transports) or "-"
            seen = p.last_seen.strftime("%Y-%m-%d %H:%M") if p.last_seen else "-"
            fp = (
                (p.fingerprint[:16] + "...")
                if p.fingerprint and len(p.fingerprint) > 16
                else (p.fingerprint or "-")
            )
            table.add_row(p.name, transports, p.discovered_via, seen, fp)

        console.print(table)
    else:
        for p in all_peers:
            transports = ", ".join(t.transport for t in p.transports) or "none"
            click.echo(f"  {p.name}  [{transports}]  via {p.discovered_via}")

    _print("")


@peer_group.command("fetch")
@click.argument("name")
@click.option(
    "--url", default=None, help="Custom DID document URL (default: skworld.io registry)."
)
@click.option("--no-save", is_flag=True, help="Display only, don't save to peer store.")
def peer_fetch(name: str, url: Optional[str], no_save: bool):
    """Fetch a peer's identity from their published DID.

    Resolves the peer's DID document from the skworld.io registry
    (or a custom URL), extracts their identity info, and adds them
    to the local peer store.

    Examples:

        skcomms peer fetch lumina

        skcomms peer fetch opus --url https://custom.example/did.json

        skcomms peer fetch jarvis --url file:///path/to/did.json
    """
    from .key_exchange import KeyExchangeError, fetch_peer_from_did

    source = url or name
    try:
        peer = fetch_peer_from_did(source, save=not no_save)
    except KeyExchangeError as exc:
        _print(f"\n  [red]Error:[/] {exc}\n")
        raise SystemExit(1)

    _print("\n  [green]Peer fetched from DID:[/]")
    _print(f"    Name:        [bold]{peer.name}[/]")
    if peer.fingerprint:
        _print(f"    Fingerprint: [dim]{peer.fingerprint}[/]")
    _print(f"    Via:         [dim]{peer.discovered_via}[/]")
    if not no_save:
        _print("    [green]Saved to peer store[/]")
    _print("")


@peer_group.command("export")
@click.option(
    "--file", "-f", "file_path", default=None, help="Write bundle to file instead of stdout."
)
@click.option("--no-transports", is_flag=True, help="Exclude transport config from bundle.")
def peer_export(file_path: Optional[str], no_transports: bool):
    """Export your identity as a peer bundle for sharing.

    Generates a JSON bundle containing your name, PGP fingerprint,
    public key, and transport config. Share this file with peers
    who want to add you to their network.

    Examples:

        skcomms peer export

        skcomms peer export --file my-identity.json

        skcomms peer export | scp - user@host:~/peer-bundle.json
    """
    from .key_exchange import KeyExchangeError, export_peer_bundle

    try:
        bundle = export_peer_bundle(include_transports=not no_transports)
    except KeyExchangeError as exc:
        _print(f"\n  [red]Error:[/] {exc}\n")
        raise SystemExit(1)

    bundle_json = json.dumps(bundle, indent=2)

    if file_path:
        Path(file_path).write_text(bundle_json, encoding="utf-8")
        _print(f"\n  [green]Bundle written to:[/] {file_path}")
        _print(f"    Name:        [bold]{bundle['name']}[/]")
        _print(f"    Fingerprint: [dim]{bundle.get('fingerprint', 'N/A')}[/]")
        _print("")
    else:
        click.echo(bundle_json)


@peer_group.command("import")
@click.argument("source")
@click.option("--no-gpg", is_flag=True, help="Don't import public key to GPG keyring.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
def peer_import(source: str, no_gpg: bool, yes: bool):
    """Import a peer from a bundle file.

    Reads a JSON peer bundle (from `skcomms peer export`) and adds
    the peer to the local store. Also imports their public key to
    the GPG keyring for encrypted messaging.

    SOURCE can be a file path, URL, or '-' for stdin.

    Examples:

        skcomms peer import peer-bundle.json

        skcomms peer import https://example.com/bundle.json

        cat bundle.json | skcomms peer import -
    """
    import urllib.request

    from .key_exchange import KeyExchangeError, import_peer_bundle

    # Load bundle from source
    try:
        if source == "-":
            raw = sys.stdin.read()
        elif source.startswith("http://") or source.startswith("https://"):
            with urllib.request.urlopen(source, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
        else:
            raw = Path(source).read_text(encoding="utf-8")

        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        _print(f"\n  [red]Error:[/] Invalid JSON: {exc}\n")
        raise SystemExit(1)
    except Exception as exc:
        logger.warning("cli.py: %s", exc)
        _print(f"\n  [red]Error:[/] Could not read source: {exc}\n")
        raise SystemExit(1)

    # Show peer info and confirm
    _print("\n  [bold]Peer Bundle:[/]")
    _print(f"    Name:        [bold]{bundle.get('name', 'N/A')}[/]")
    _print(f"    Fingerprint: [dim]{bundle.get('fingerprint', 'N/A')}[/]")
    _print(f"    Email:       [dim]{bundle.get('email', 'N/A')}[/]")
    _print(f"    DID Key:     [dim]{bundle.get('did_key', 'N/A')}[/]")
    has_key = "Yes" if bundle.get("public_key") else "No"
    _print(f"    Public Key:  [dim]{has_key}[/]")
    _print("")

    if not yes:
        if not click.confirm("  Import this peer?", default=True):
            _print("  [dim]Cancelled.[/]\n")
            return

    try:
        peer = import_peer_bundle(bundle, gpg_import=not no_gpg)
    except KeyExchangeError as exc:
        _print(f"\n  [red]Error:[/] {exc}\n")
        raise SystemExit(1)

    _print(f"  [green]Imported:[/] [bold]{peer.name}[/]")
    if peer.fingerprint:
        _print(f"  Fingerprint: [dim]{peer.fingerprint}[/]")
    if not no_gpg:
        _print("  [dim]Public key imported to GPG keyring[/]")
    _print("")


@main.command("peers-transport")
@click.option("--config", "-c", default=None, help="Config file path.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def peers_transport(config: Optional[str], json_out: bool):
    """List known peers from the transport peer store (legacy).

    Shows all peers discovered via `skcomms discover` or added
    manually, with their transport endpoints and last-seen times.
    """
    from .discovery import PeerStore

    store = PeerStore()
    all_peers = store.list_all()

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [p.model_dump(mode="json", exclude_none=True) for p in all_peers],
                indent=2,
            )
        )
        return

    if not all_peers:
        _print("\n  [dim]No peers in store.[/]")
        _print("  [dim]Run [bold]skcomms discover[/] to scan for peers.[/]\n")
        return

    _print(f"\n  [bold]{len(all_peers)}[/] peer(s):\n")

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Name", style="cyan")
        table.add_column("Transports", style="dim")
        table.add_column("Via", style="dim")
        table.add_column("Last Seen")
        table.add_column("Fingerprint", style="dim", max_width=16)

        for p in all_peers:
            transports = ", ".join(t.transport for t in p.transports) or "-"
            seen = p.last_seen.strftime("%Y-%m-%d %H:%M") if p.last_seen else "-"
            fp = (
                (p.fingerprint[:16] + "...")
                if p.fingerprint and len(p.fingerprint) > 16
                else (p.fingerprint or "-")
            )
            table.add_row(p.name, transports, p.discovered_via, seen, fp)

        console.print(table)
    else:
        for p in all_peers:
            transports = ", ".join(t.transport for t in p.transports) or "none"
            click.echo(f"  {p.name}  [{transports}]  via {p.discovered_via}")

    _print("")


@main.command("discover")
@click.option("--config", "-c", default=None, help="Config file path.")
@click.option("--save/--no-save", default=True, help="Save to peer store.")
@click.option("--mdns/--no-mdns", default=False, help="Include mDNS LAN scan.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def discover(config: Optional[str], save: bool, mdns: bool, json_out: bool):
    """Discover peers on the network and Syncthing mesh.

    Scans Syncthing comms directories, file transport inboxes,
    and optionally the local network via mDNS. Discovered peers
    are saved to the peer store for use by the router.

    Examples:

        skcomms discover

        skcomms discover --mdns

        skcomms discover --json-out
    """
    from .discovery import PeerStore, discover_all

    peers_found = discover_all(skip_mdns=not mdns)

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [p.model_dump(mode="json", exclude_none=True) for p in peers_found],
                indent=2,
            )
        )
        if save:
            store = PeerStore()
            for p in peers_found:
                store.add(p)
        return

    if not peers_found:
        _print("\n  [dim]No peers discovered.[/]")
        _print("  [dim]Ensure Syncthing is running or send a message first.[/]\n")
        return

    _print(f"\n  [bold]{len(peers_found)}[/] peer(s) discovered:\n")

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Name", style="cyan")
        table.add_column("Transports", style="dim")
        table.add_column("Via", style="dim")
        table.add_column("Last Seen")

        for p in peers_found:
            transports = ", ".join(t.transport for t in p.transports) or "-"
            seen = p.last_seen.strftime("%Y-%m-%d %H:%M") if p.last_seen else "-"
            table.add_row(p.name, transports, p.discovered_via, seen)

        console.print(table)
    else:
        for p in peers_found:
            transports = ", ".join(t.transport for t in p.transports) or "none"
            click.echo(f"  {p.name}  [{transports}]  via {p.discovered_via}")

    if save:
        store = PeerStore()
        for p in peers_found:
            store.add(p)
        _print(f"  [green]Saved to {store.peers_dir}[/]\n")
    else:
        _print("")


@main.group("heartbeat", invoke_without_command=True)
@click.option("--config", "-c", default=None, help="Config file path.")
@click.option("--emit/--no-emit", default=True, help="Emit our heartbeat first (v1 legacy).")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.pass_context
def heartbeat_group(ctx: click.Context, config: Optional[str], emit: bool, json_out: bool):
    """Heartbeat commands — publish and monitor node health beacons.

    Run without a subcommand to emit a v1 heartbeat and show peer liveness
    (legacy mode). Use subcommands for the v2 rich state beacon.

    Examples:

        skcomms heartbeat

        skcomms heartbeat publish --node-id jarvis-desktop

        skcomms heartbeat status --node-id jarvis-desktop

        skcomms heartbeat nodes
    """
    if ctx.invoked_subcommand is not None:
        return

    from .config import load_config
    from .heartbeat import HeartbeatMonitor, PeerLiveness

    cfg = load_config(config)

    syncthing_cfg = cfg.transports.get("syncthing")
    comms_root_path = None
    if syncthing_cfg and syncthing_cfg.enabled:
        raw = syncthing_cfg.settings.get("comms_root")
        if raw:
            comms_root_path = Path(raw).expanduser()

    monitor = HeartbeatMonitor(
        agent_name=cfg.identity.name,
        fingerprint=cfg.identity.fingerprint,
        transports=[name for name, tc in cfg.transports.items() if tc.enabled],
        comms_root=comms_root_path,
    )

    if emit:
        monitor.emit()

    results = monitor.scan()

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [r.model_dump(mode="json", exclude_none=True) for r in results],
                indent=2,
            )
        )
        return

    if not results:
        if emit:
            _print(f"\n  [green]Heartbeat emitted[/] as [bold]{cfg.identity.name}[/]")
        _print("  [dim]No peer heartbeats found yet.[/]\n")
        return

    if emit:
        _print(f"\n  [green]Heartbeat emitted[/] as [bold]{cfg.identity.name}[/]\n")
    else:
        _print("")

    status_styles = {
        PeerLiveness.ALIVE: "green",
        PeerLiveness.STALE: "yellow",
        PeerLiveness.DEAD: "red",
        PeerLiveness.UNKNOWN: "dim",
    }

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Peer", style="cyan")
        table.add_column("Status")
        table.add_column("Age", justify="right")
        table.add_column("Transports", style="dim")

        for r in results:
            color = status_styles.get(r.status, "dim")
            age = f"{int(r.age_seconds)}s" if r.age_seconds is not None else "-"
            transports = ", ".join(r.transports) or "-"
            table.add_row(
                r.name,
                f"[{color}]{r.status.value.upper()}[/{color}]",
                age,
                transports,
            )

        console.print(table)
    else:
        for r in results:
            age = f"{int(r.age_seconds)}s" if r.age_seconds is not None else "?"
            click.echo(f"  {r.name:16} {r.status.value:8} {age}")

    alive = sum(1 for r in results if r.status == PeerLiveness.ALIVE)
    _print(f"\n  {alive}/{len(results)} peers alive\n")


@heartbeat_group.command("publish")
@click.option("--node-id", required=True, help="Node identifier (e.g. jarvis-desktop).")
@click.option("--agent-name", default="", help="Human-readable agent name.")
@click.option(
    "--capability",
    "-c",
    multiple=True,
    help="Capability to advertise (repeat for multiple).",
)
@click.option(
    "--sync-root",
    default=None,
    help="Override Syncthing sync root (default: ~/.skcapstone/sync).",
)
@click.option("--state", default="active", help="Node state (active/idle/busy).")
@click.option("--skcomms-status", default="online", help="SKComms connectivity state.")
@click.option("--ttl", default=120, help="Heartbeat TTL in seconds.")
@click.option("--json-out", is_flag=True, help="Print the written JSON.")
def heartbeat_publish(
    node_id: str,
    agent_name: str,
    capability: tuple,
    sync_root: Optional[str],
    state: str,
    skcomms_status: str,
    ttl: int,
    json_out: bool,
):
    """Publish a v2 heartbeat for this node (one-shot).

    Writes a rich heartbeat JSON file containing system resources,
    advertised capabilities, and claimed tasks. Safe to run from a cron
    job or systemd timer — each node writes only its own file.

    Examples:

        skcomms heartbeat publish --node-id jarvis-desktop \\
            --agent-name jarvis \\
            --capability code --capability gpu

        skcomms heartbeat publish --node-id lumina-laptop --ttl 60
    """
    from .heartbeat import HeartbeatConfig, HeartbeatPublisher

    cfg = HeartbeatConfig(
        node_id=node_id,
        agent_name=agent_name or node_id,
        capabilities=list(capability),
        ttl_seconds=ttl,
        sync_root=(
            Path(sync_root).expanduser() if sync_root else Path("~/.skcapstone/sync").expanduser()
        ),
        skcomms_status=skcomms_status,
    )

    publisher = HeartbeatPublisher(config=cfg, state=state)
    path = publisher.publish()

    if json_out:
        click.echo(path.read_text())
        return

    _print(f"\n  [green]Heartbeat published[/] → [dim]{path}[/]")
    _print(f"  Node:   [bold cyan]{node_id}[/]")
    _print(f"  State:  {state}")
    _print(f"  TTL:    {ttl}s")
    if capability:
        _print(f"  Caps:   {', '.join(capability)}")
    _print("")


@heartbeat_group.command("status")
@click.argument("node_id")
@click.option(
    "--sync-root",
    default=None,
    help="Override sync root (default: ~/.skcapstone/sync).",
)
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def heartbeat_status(node_id: str, sync_root: Optional[str], json_out: bool):
    """Show the v2 heartbeat for a specific node.

    Reads the node's heartbeat file and displays its state, resources,
    capabilities, and whether it has expired.

    Examples:

        skcomms heartbeat status jarvis-desktop

        skcomms heartbeat status lumina-laptop --json-out
    """
    from .heartbeat import NodeHeartbeatMonitor

    root = Path(sync_root).expanduser() if sync_root else None
    monitor = NodeHeartbeatMonitor(sync_root=root)
    hb = monitor.get_node(node_id)

    if hb is None:
        _print(f"\n  [yellow]No heartbeat found for node:[/] {node_id}\n")
        raise SystemExit(1)

    if json_out:
        click.echo(hb.model_dump_json(indent=2))
        return

    expired = hb.is_expired()
    state_color = "green" if not expired else "red"
    _print(f"\n  Node:     [bold cyan]{hb.node_id}[/]")
    _print(f"  Agent:    {hb.agent_name or '-'}")
    _print(f"  State:    [{state_color}]{hb.state}[/]{'  [red][EXPIRED][/]' if expired else ''}")
    _print(f"  SKComms:   {hb.skcomms_status}")
    _print(f"  Timestamp: {hb.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    _print(f"  TTL:       {hb.ttl_seconds}s")

    if hb.capabilities:
        _print(f"  Caps:      {', '.join(hb.capabilities)}")

    r = hb.resources
    _print(f"  CPU:       {r.cpu_percent:.1f}%")
    _print(f"  RAM:       {r.ram_used_gb:.1f} / {r.ram_total_gb:.1f} GB")
    _print(f"  Disk free: {r.disk_free_gb:.1f} GB")
    _print(f"  GPU:       {'yes' if r.gpu_available else 'no'}")

    if hb.claimed_tasks:
        _print(f"  Tasks:     {', '.join(hb.claimed_tasks)}")
    if hb.loaded_models:
        _print(f"  Models:    {', '.join(hb.loaded_models)}")
    _print("")


@heartbeat_group.command("nodes")
@click.option(
    "--sync-root",
    default=None,
    help="Override sync root (default: ~/.skcapstone/sync).",
)
@click.option("--capability", "-c", default=None, help="Filter to nodes with this capability.")
@click.option("--all", "show_all", is_flag=True, help="Include expired (stale) nodes.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def heartbeat_nodes(
    sync_root: Optional[str],
    capability: Optional[str],
    show_all: bool,
    json_out: bool,
):
    """List all live nodes on the mesh (v2 heartbeats).

    Scans the shared heartbeat directory and shows nodes that have
    published a v2 beacon within their TTL window.

    Examples:

        skcomms heartbeat nodes

        skcomms heartbeat nodes --capability gpu

        skcomms heartbeat nodes --all --json-out
    """
    from .heartbeat import NodeHeartbeatMonitor

    root = Path(sync_root).expanduser() if sync_root else None
    monitor = NodeHeartbeatMonitor(sync_root=root)

    if show_all:
        nodes = monitor.all_nodes()
    elif capability:
        nodes = monitor.find_capable(capability)
    else:
        nodes = monitor.discover_nodes()

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [n.model_dump(mode="json") for n in nodes],
                indent=2,
                default=str,
            )
        )
        return

    if not nodes:
        label = f"with capability '{capability}'" if capability else "live"
        _print(f"\n  [dim]No {label} nodes found.[/]\n")
        return

    _print(f"\n  [bold]{len(nodes)}[/] node(s):\n")

    if console:
        from datetime import datetime as _dt

        now = _dt.now(timezone.utc)
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Node", style="cyan")
        table.add_column("State")
        table.add_column("Age", justify="right")
        table.add_column("CPU", justify="right")
        table.add_column("RAM used", justify="right")
        table.add_column("GPU")
        table.add_column("Capabilities", style="dim")

        for n in nodes:
            age_s = (now - n.timestamp).total_seconds()
            age_str = f"{int(age_s)}s"
            expired = n.is_expired(now)
            state_fmt = f"[red]{n.state}[/]" if expired else f"[green]{n.state}[/]"
            cpu_str = f"{n.resources.cpu_percent:.0f}%"
            ram_str = f"{n.resources.ram_used_gb:.1f}G"
            gpu_str = "[green]yes[/]" if n.resources.gpu_available else "no"
            caps = ", ".join(n.capabilities) or "-"
            table.add_row(n.node_id, state_fmt, age_str, cpu_str, ram_str, gpu_str, caps)

        console.print(table)
    else:
        for n in nodes:
            caps = ", ".join(n.capabilities) or "none"
            click.echo(f"  {n.node_id:24} {n.state:8}  caps=[{caps}]")

    _print("")


# ---------------------------------------------------------------------------
# SKWorld marketplace commands
# ---------------------------------------------------------------------------


@main.group("skill")
def skill_group():
    """SKWorld marketplace — publish and discover agent skills.

    Browse, publish, and install sovereign agent skills via
    the Nostr-based marketplace.
    """


@skill_group.command("list")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def skill_list(json_out: bool):
    """List locally installed skills."""
    from .marketplace import SkillRegistry

    reg = SkillRegistry()
    skills = reg.list_all()

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [s.model_dump(mode="json", exclude_none=True) for s in skills],
                indent=2,
            )
        )
        return

    if not skills:
        _print("\n  [dim]No skills installed.[/]")
        _print("  [dim]Run [bold]skcomms skill search[/] to browse the marketplace.[/]\n")
        return

    _print(f"\n  [bold]{len(skills)}[/] skill(s) installed:\n")

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Author", style="dim")
        table.add_column("Tags", style="dim")

        for s in skills:
            table.add_row(s.name, s.version, s.author or "-", ", ".join(s.tags) or "-")

        console.print(table)
    else:
        for s in skills:
            click.echo(f"  {s.name:24} v{s.version:8} {s.author or '-'}")

    _print("")


@skill_group.command("search")
@click.argument("query", required=False, default=None)
@click.option("--relay", "-r", multiple=True, help="Override relay URLs.")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def skill_search(query: Optional[str], relay: tuple, json_out: bool):
    """Search the Nostr marketplace for skills.

    Queries configured relays for published skill manifests.

    Examples:

        skcomms skill search

        skcomms skill search security

        skcomms skill search email --json-out
    """
    from .marketplace import search_skills

    relays = list(relay) if relay else None
    results = search_skills(query=query, relays=relays)

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [s.model_dump(mode="json", exclude_none=True) for s in results],
                indent=2,
            )
        )
        return

    if not results:
        _print("\n  [dim]No skills found.[/]\n")
        return

    _print(f"\n  [bold]{len(results)}[/] skill(s) found:\n")

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Author", style="dim")
        table.add_column("Description", max_width=40)
        table.add_column("Tags", style="dim")

        for s in results:
            desc = (s.description[:37] + "...") if len(s.description) > 40 else s.description
            table.add_row(s.name, s.version, s.author or "-", desc, ", ".join(s.tags) or "-")

        console.print(table)
    else:
        for s in results:
            click.echo(f"  {s.name:24} v{s.version:8} {s.description[:50]}")

    _print("")


@skill_group.command("publish")
@click.argument("manifest_path", type=click.Path(exists=True))
@click.option(
    "--key", envvar="NOSTR_PRIVATE_KEY", help="Nostr private key hex (or NOSTR_PRIVATE_KEY env)."
)
@click.option("--relay", "-r", multiple=True, help="Override relay URLs.")
def skill_publish(manifest_path: str, key: Optional[str], relay: tuple):
    """Publish a skill manifest to the Nostr marketplace.

    Reads a YAML manifest file and publishes it as a Nostr
    event to configured relays.

    Examples:

        skcomms skill publish skill.yml --key $NOSTR_KEY

        NOSTR_PRIVATE_KEY=abc... skcomms skill publish skill.yml
    """
    from .marketplace import SkillManifest, publish_skill

    if not key:
        _print("\n  [red]Error:[/] Nostr private key required.")
        _print("  Set --key or NOSTR_PRIVATE_KEY env var.\n")
        raise SystemExit(1)

    manifest = SkillManifest.from_yaml_file(Path(manifest_path))
    relays = list(relay) if relay else None
    event_id = publish_skill(manifest, key, relays=relays)

    if event_id:
        _print(f"\n  [green]Published[/] [bold]{manifest.name}[/] v{manifest.version}")
        _print(f"  Event: [dim]{event_id}[/]\n")
    else:
        _print(f"\n  [red]Failed[/] to publish {manifest.name}.\n")
        raise SystemExit(1)


@skill_group.command("install")
@click.argument("name")
@click.option("--relay", "-r", multiple=True, help="Override relay URLs.")
def skill_install(name: str, relay: tuple):
    """Install a skill from the Nostr marketplace.

    Searches for the skill by name, downloads the manifest,
    and adds it to the local skill registry.

    Examples:

        skcomms skill install email-prescreening
    """
    from .marketplace import SkillRegistry, search_skills

    _print(f"\n  Searching for [bold]{name}[/]...")
    relays = list(relay) if relay else None
    results = search_skills(query=name, relays=relays)

    match = next((s for s in results if s.name == name), None)
    if not match and results:
        match = results[0]

    if not match:
        _print(f"  [red]Not found:[/] {name}\n")
        raise SystemExit(1)

    reg = SkillRegistry()
    reg.install(match)
    _print(f"  [green]Installed[/] [bold]{match.name}[/] v{match.version}")
    if match.install_cmd:
        _print(f"  Run: [cyan]{match.install_cmd}[/]")
    _print("")


# ---------------------------------------------------------------------------
# Consent grant commands (cross-operator collection read-consent — T10)
# ---------------------------------------------------------------------------


@main.group("grant")
def grant_group():
    """Mint cross-operator collection read-consent tokens.

    A grant lets a remote agent read one of this operator's memory
    collections across an operator/realm boundary. Tokens are PGP-signed
    by the granter so the consumer (skmemory) can verify them offline.
    """


@grant_group.command("collection-read")
@click.option("--collection", required=True, help="Collection <operator>.<realm>/<name>.")
@click.option("--to", "to_fqid", required=True, help="Reader FQID to grant access to.")
@click.option(
    "--expires", default="30d", help="Expiry: '<N>d' days (e.g. 30d) or an ISO-8601 date."
)
@click.option(
    "--out", "-o", "out_file", default=None, help="Write the signed token to a file (else stdout)."
)
def grant_collection_read(
    collection: str, to_fqid: str, expires: str, out_file: Optional[str]
):
    """Mint a signed collection read-consent token.

    Builds a token granting ``--to`` read access to ``--collection``,
    signs it with this agent's PGP key, and prints (or saves) the signed
    token JSON in the schema skmemory consumes.

    Examples:

        skcomms grant collection-read --collection chef.skworld/journal \\
            --to opus@casey.douno --expires 30d

        skcomms grant collection-read --collection chef.skworld/notes \\
            --to opus@casey.douno --expires 2026-12-31 -o grant.json
    """
    from .grants import mint_grant

    try:
        token = mint_grant(collection=collection, to_fqid=to_fqid, expires=expires)
    except (ValueError, FileNotFoundError) as exc:
        _print(f"\n  [red]Grant failed:[/] {exc}\n")
        raise SystemExit(1)

    token_json = json.dumps(token, indent=2)
    if out_file:
        Path(out_file).write_text(token_json + "\n", encoding="utf-8")
        _print(f"\n  [green]Grant minted[/] → [dim]{out_file}[/]")
        _print(f"  Collection: [cyan]{token['collection']}[/]")
        _print(f"  To:         [bold]{token['granted_to']}[/]")
        _print(f"  By:         [bold]{token['granted_by']}[/]")
        _print(f"  Expires:    [dim]{token['expires']}[/]\n")
    else:
        click.echo(token_json)


@main.group("grants")
def grants_group():
    """Manage held collection read-consent tokens.

    Accept tokens minted by peers and list the grants currently honored
    in ``${SKCOMMS_HOME:-~/.skcapstone/skcomms}/recall_collections_consent.json``.
    """


@grants_group.command("accept")
@click.argument("source")
def grants_accept(source: str):
    """Verify and accept a consent token into the consent file.

    SOURCE is a token file path, or '-' for stdin. The token's signature,
    granter trust (TOFU), and expiry are verified before it is merged
    (idempotently) into the consent file skmemory reads.

    Examples:

        skcomms grants accept grant.json

        cat grant.json | skcomms grants accept -
    """
    from .grants import accept_grant

    try:
        raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
        token = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        _print(f"\n  [red]Could not read token:[/] {exc}\n")
        raise SystemExit(1)

    try:
        accepted = accept_grant(token)
    except ValueError as exc:
        _print(f"\n  [red]Rejected:[/] {exc}\n")
        raise SystemExit(1)

    _print("\n  [green]Grant accepted[/]")
    _print(f"  Collection: [cyan]{accepted['collection']}[/]")
    _print(f"  To:         [bold]{accepted['granted_to']}[/]")
    _print(f"  By:         [bold]{accepted['granted_by']}[/]")
    _print(f"  Expires:    [dim]{accepted['expires']}[/]\n")


@grants_group.command("list")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def grants_list(json_out: bool):
    """List the consent tokens currently held."""
    from .grants import list_grants

    grants = list_grants()

    if json_out:
        click.echo(json.dumps(grants, indent=2))
        return

    if not grants:
        _print("\n  [dim]No grants held.[/]\n")
        return

    _print(f"\n  [bold]{len(grants)}[/] grant(s) held:\n")
    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Collection", style="cyan")
        table.add_column("Granted To")
        table.add_column("Granted By", style="dim")
        table.add_column("Expires", style="dim")
        for g in grants:
            table.add_row(
                g.get("collection", "-"),
                g.get("granted_to", "-"),
                g.get("granted_by", "-"),
                g.get("expires", "-"),
            )
        console.print(table)
    else:
        for g in grants:
            click.echo(
                f"  {g.get('collection')}  ->  {g.get('granted_to')}  "
                f"(by {g.get('granted_by')}, exp {g.get('expires')})"
            )
    _print("")


# ---------------------------------------------------------------------------
# Queue commands
# ---------------------------------------------------------------------------


@main.group("queue")
def queue_group():
    """Message queue — manage undeliverable envelopes.

    View, drain, and purge the persistent outbox queue
    for messages that couldn't be delivered.
    """


@queue_group.command("list")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
def queue_list(json_out: bool):
    """List all queued envelopes."""
    from .queue import MessageQueue

    q = MessageQueue()
    items = q.list_all()

    if json_out:
        import json as _json

        click.echo(
            _json.dumps(
                [m.model_dump(mode="json", exclude_none=True) for m in items],
                indent=2,
            )
        )
        return

    if not items:
        _print("\n  [dim]Queue is empty.[/]\n")
        return

    _print(f"\n  [bold]{len(items)}[/] envelope(s) queued:\n")

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("ID", style="cyan", max_width=12)
        table.add_column("Recipient")
        table.add_column("Attempts", justify="right")
        table.add_column("Queued")
        table.add_column("Status")

        for m in items:
            eid = m.envelope_id[:12]
            queued = m.queued_at.strftime("%H:%M:%S") if m.queued_at else "-"
            if m.is_expired:
                status = "[red]EXPIRED[/]"
            elif m.is_ready:
                status = "[green]READY[/]"
            else:
                status = "[yellow]WAITING[/]"
            table.add_row(eid, m.recipient, str(m.attempts), queued, status)

        console.print(table)
    else:
        for m in items:
            click.echo(f"  {m.envelope_id[:12]:14} -> {m.recipient:16} attempts={m.attempts}")

    _print("")


@queue_group.command("drain")
@click.option("--config", "-c", default=None, help="Config file path.")
def queue_drain(config: Optional[str]):
    """Attempt to deliver all pending queued envelopes.

    Retries each ready envelope through the configured transports.
    Successfully delivered envelopes are removed from the queue.
    """
    from .core import SKComms
    from .queue import MessageQueue

    comm = SKComms.from_config(config)
    q = MessageQueue()

    if q.size == 0:
        _print("\n  [dim]Queue is empty — nothing to drain.[/]\n")
        return

    _print(f"\n  Draining {q.size} envelope(s)...\n")

    def try_send(envelope_bytes: bytes, recipient: str) -> bool:
        from .models import MessageEnvelope

        try:
            envelope = MessageEnvelope.from_bytes(envelope_bytes)
            report = comm.send_envelope(envelope)
            return report.delivered
        except Exception as e:
            logger.warning("cli.py: %s", e)
            return False

    delivered, failed = q.drain(try_send)
    _print(
        f"  [green]{delivered}[/] delivered, [red]{failed}[/] failed, [dim]{q.size}[/] remaining\n"
    )


@queue_group.command("purge")
@click.option("--expired", is_flag=True, default=False, help="Only purge expired envelopes.")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
def queue_purge(expired: bool, yes: bool):
    """Remove envelopes from the queue.

    By default, removes ALL queued envelopes. Use --expired
    to only remove envelopes that have exceeded their TTL.
    """
    from .queue import MessageQueue

    q = MessageQueue()

    if q.size == 0:
        _print("\n  [dim]Queue is empty.[/]\n")
        return

    if expired:
        removed = q.purge_expired()
        _print(f"\n  Purged [bold]{removed}[/] expired envelope(s). {q.size} remaining.\n")
    else:
        if not yes:
            if not click.confirm(f"  Remove all {q.size} queued envelopes?", default=False):
                _print("  [dim]Cancelled.[/]\n")
                return
        items = q.list_all()
        for m in items:
            q.dequeue(m.envelope_id)
        _print(f"\n  Purged [bold]{len(items)}[/] envelope(s).\n")


@main.command("serve")
@click.option("--host", default="127.0.0.1", help="Host to bind to.")
@click.option("--port", "-p", default=9384, help="Port to bind to.")
@click.option("--reload", is_flag=True, help="Enable auto-reload (dev mode).")
def serve(host: str, port: int, reload: bool):
    """Start the SKComms REST API server.

    Runs a FastAPI server that wraps the SKComms Python API
    and exposes HTTP endpoints for Flutter/desktop clients.

    Examples:

        skcomms serve

        skcomms serve --port 8080

        skcomms serve --reload  # Dev mode with auto-reload
    """
    try:
        import uvicorn
    except ImportError:
        _print("\n  [red]Error:[/] uvicorn not installed.")
        _print("  Install with: [cyan]pip install skcomms[api][/]\n")
        raise SystemExit(1)

    _print("\n  [green]Starting SKComms API server[/]")
    _print(f"  Host: [cyan]{host}[/]")
    _print(f"  Port: [cyan]{port}[/]")
    _print(f"  Docs: [cyan]http://{host}:{port}/docs[/]\n")

    uvicorn.run(
        "skcomms.api:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@main.command("stats")
@click.option("--json-out", is_flag=True, help="Output as JSON.")
@click.option("--reset", is_flag=True, help="Reset all metrics.")
def stats_cmd(json_out: bool, reset: bool):
    """Show per-transport delivery metrics.

    Displays success/failure counts, latency, and error
    history for each transport.

    Examples:

        skcomms stats

        skcomms stats --json-out

        skcomms stats --reset
    """
    from .metrics import MetricsCollector

    mc = MetricsCollector()

    if reset:
        mc.reset()
        _print("\n  [green]Metrics reset.[/]\n")
        return

    if json_out:
        import json as _json

        click.echo(_json.dumps(mc.summary(), indent=2, default=str))
        return

    all_stats = mc.all_stats()
    if not all_stats:
        _print("\n  [dim]No transport metrics yet.[/]")
        _print("  [dim]Send or receive a message to start tracking.[/]\n")
        return

    summary = mc.summary()
    _print(
        f"\n  [bold]Transport Metrics[/]  "
        f"[green]{summary['total_sends_ok']}[/] sent  "
        f"[red]{summary['total_sends_fail']}[/] failed  "
        f"[cyan]{summary['total_receives']}[/] received  "
        f"({summary['overall_success_rate']} success)\n"
    )

    if console:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Transport", style="cyan")
        table.add_column("Sent", justify="right")
        table.add_column("Failed", justify="right")
        table.add_column("Recv", justify="right")
        table.add_column("Rate")
        table.add_column("Avg Latency", justify="right")
        table.add_column("Last Error", style="dim", max_width=30)

        for s in all_stats:
            rate_color = (
                "green" if s.success_rate >= 90 else "yellow" if s.success_rate >= 50 else "red"
            )
            avg = f"{s.avg_latency_ms:.1f}ms" if s.avg_latency_ms > 0 else "-"
            err = (
                (s.last_error[:27] + "...")
                if s.last_error and len(s.last_error) > 30
                else (s.last_error or "-")
            )
            table.add_row(
                s.transport,
                str(s.sends_ok),
                str(s.sends_fail),
                str(s.receives),
                f"[{rate_color}]{s.success_rate:.0f}%[/{rate_color}]",
                avg,
                err,
            )

        console.print(table)
    else:
        for s in all_stats:
            click.echo(
                f"  {s.transport:16} ok={s.sends_ok} fail={s.sends_fail} "
                f"recv={s.receives} rate={s.success_rate:.0f}%"
            )

    _print("")


# ---------------------------------------------------------------------------
# Pub/sub commands
# ---------------------------------------------------------------------------


@main.group("pubsub")
def pubsub_group():
    """Sovereign pub/sub — real-time event distribution across agents.

    Subscribe to topics, publish events, and inspect the live topic
    registry. Uses the in-process PubSubBroker with optional transport
    forwarding to remote nodes.

    Topic naming convention:  <domain>.<entity>.<action>

    Wildcards:
        *  matches exactly one level   (agent.* matches agent.heartbeat)
        #  matches all remaining levels (coord.# matches coord.task.claimed)

    Predefined topics:
        agent.heartbeat         alive signals
        agent.status            status changes
        memory.stored           new memory created
        memory.promoted         memory promoted to higher tier
        coord.task.created      new task on board
        coord.task.claimed      task claimed by agent
        coord.task.completed    task marked done
        sync.push               sync state pushed
        sync.pull               sync state pulled
        trust.updated           trust level changed

    Examples:

        skcomms pubsub listen agent.*

        skcomms pubsub publish memory.stored '{\"content\": \"hello\"}'

        skcomms pubsub topics
    """


@pubsub_group.command("listen")
@click.argument("topic")
@click.option("--timeout", "-t", default=0, help="Stop after N seconds (0 = run forever).")
@click.option("--json-out", is_flag=True, help="Print each message as raw JSON.")
@click.option("--count", "-n", default=0, help="Stop after receiving N messages (0 = unlimited).")
def pubsub_listen(topic: str, timeout: int, json_out: bool, count: int):
    """Subscribe and print messages on TOPIC in real-time.

    Blocks until Ctrl-C, --timeout seconds elapse, or --count messages
    are received. Use wildcards to listen across topic families.

    Examples:

        skcomms pubsub listen agent.*

        skcomms pubsub listen coord.# --timeout 30

        skcomms pubsub listen memory.stored --count 5 --json-out
    """
    import signal
    import time

    from .pubsub import PubSubBroker, PubSubMessage

    broker = PubSubBroker(name="cli-listen")
    received: list[PubSubMessage] = []
    stop_event = threading.Event()

    def _handler(msg: PubSubMessage) -> None:
        received.append(msg)
        if json_out:
            click.echo(msg.model_dump_json(indent=2))
        else:
            ts = msg.timestamp.strftime("%H:%M:%S")
            if console:
                console.print(
                    f"  [dim]{ts}[/]  [cyan]{msg.topic}[/]  "
                    f"[dim]from[/] [bold]{msg.sender}[/]  "
                    f"{msg.payload}"
                )
            else:
                click.echo(f"  {ts}  {msg.topic}  from={msg.sender}  {msg.payload}")

        if count and len(received) >= count:
            stop_event.set()

    broker.subscribe(topic, _handler)

    if not json_out:
        _print(f"\n  Listening on [bold cyan]{topic}[/]")
        _print("  Press Ctrl-C to stop.\n")

    deadline = time.monotonic() + timeout if timeout else None

    def _sigint_handler(sig, frame):  # noqa: ANN001
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, _sigint_handler)

    try:
        while not stop_event.is_set():
            if deadline and time.monotonic() >= deadline:
                break
            time.sleep(0.1)
    finally:
        signal.signal(signal.SIGINT, old_handler)
        broker.unsubscribe(topic, _handler)

    if not json_out:
        _print(f"\n  Received [bold]{len(received)}[/] message(s).\n")


@pubsub_group.command("publish")
@click.argument("topic")
@click.argument("payload_json")
@click.option("--sender", "-s", default=None, help="Sender name (defaults to local identity).")
@click.option("--config", "-c", default=None, help="Config file path (for identity resolution).")
def pubsub_publish(topic: str, payload_json: str, sender: Optional[str], config: Optional[str]):
    """Publish a message to TOPIC with PAYLOAD_JSON.

    PAYLOAD_JSON must be a valid JSON object string.
    The message is dispatched synchronously to all local subscribers.

    Examples:

        skcomms pubsub publish agent.heartbeat '{\"state\": \"active\"}'

        skcomms pubsub publish memory.stored '{\"content\": \"hello world\"}'

        skcomms pubsub publish coord.task.created '{\"task_id\": \"abc-123\"}' --sender opus
    """
    import json as _json

    from .pubsub import PubSubBroker

    try:
        payload = _json.loads(payload_json)
    except _json.JSONDecodeError as exc:
        _print(f"\n  [red]Invalid JSON payload:[/] {exc}\n")
        raise SystemExit(1)

    if not isinstance(payload, dict):
        _print("\n  [red]Payload must be a JSON object (dict), not a list or scalar.[/]\n")
        raise SystemExit(1)

    if not sender:
        try:
            from .config import load_config

            cfg = load_config(config)
            sender = cfg.identity.name
        except Exception as e:
            logger.warning("cli.py: %s", e)
            sender = "cli"

    broker = PubSubBroker(name="cli-publish")
    invoked = broker.publish(topic=topic, message=payload, sender=sender)

    _print(f"\n  [green]Published[/] to [bold cyan]{topic}[/]")
    _print(f"  Sender:      {sender}")
    _print(f"  Subscribers: {invoked}")
    _print(f"  Payload:     {payload}\n")


@pubsub_group.command("topics")
@click.option("--pattern", "-p", default=None, help="Filter topics matching this pattern.")
def pubsub_topics(pattern: Optional[str]):
    """List active topics with subscriber counts.

    Shows topics that have had at least one message published in this
    session, along with the number of registered subscribers.

    Examples:

        skcomms pubsub topics

        skcomms pubsub topics --pattern agent.*
    """
    import fnmatch

    from .pubsub import PubSubBroker

    broker = PubSubBroker(name="cli-topics")
    topics = broker.list_topics()

    if pattern:
        topics = [t for t in topics if fnmatch.fnmatch(t, pattern)]

    if not topics:
        label = f" matching [bold]{pattern}[/]" if pattern else ""
        _print(f"\n  [dim]No active topics{label}.[/]")
        _print("  [dim]Topics appear after at least one message is published.[/]\n")
        return

    _print(f"\n  [bold]{len(topics)}[/] active topic(s):\n")

    if console:
        from rich.table import Table as _Table

        table = _Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Topic", style="cyan")
        table.add_column("Subscribers", justify="right")

        for t in sorted(topics):
            sub_count = broker.subscriber_count(t)
            table.add_row(t, str(sub_count))

        console.print(table)
    else:
        for t in sorted(topics):
            sub_count = broker.subscriber_count(t)
            click.echo(f"  {t:40} subs={sub_count}")

    _print("")


@main.group("pair")
def pair_group():
    """QR device-pairing: show your invite, accept a scanned one."""


@pair_group.command("show")
@click.option("--embed-key", is_flag=True, help="Embed the full public key (self-contained, offline; larger QR).")
@click.option("-o", "--out", type=click.Path(), default=None, help="Save the QR to a .png/.svg file.")
@click.option("-a", "--agent", default=None, help="Agent name (default: resolved self).")
def pair_show(embed_key, out, agent):
    from .pairing import bundle_from_self, make_pairing_qr
    bundle = bundle_from_self(agent, embed_key=embed_key)
    uri, qr = make_pairing_qr(bundle)
    click.echo(qr.terminal(compact=True))
    click.echo(uri)
    if out:
        qr.save(out)
        click.echo(f"saved QR -> {out}")


@pair_group.command("accept")
@click.argument("source")  # an skp:// URI or a file path containing one
def pair_accept(source):
    from .pairing import accept_pairing
    res = accept_pairing(source)
    click.echo(f"paired with {res['fqid']} (fingerprint {res['fingerprint']})")

@main.command(name="pqc-report")
@click.option("--format", "output_format", default="text",
              type=click.Choice(["text", "json"]))
@click.option("--static", is_flag=True, default=False,
              help="Show the model-DEFAULT posture instead of the live fleet.")
def pqc_report_cmd(output_format, static):
    """Show skcomms' OWN PQC (quantum-resistance) posture.

    Reports skcomms' owned surfaces (per-message envelope signature + the
    envelope-payload KEM) with the active suite + status + FIPS refs. Delegates to the
    sksecurity honesty engine (build_project_report) so the claim discipline is
    identical: a surface is hybrid-pq only when its live suite truly is, and no
    global / end-to-end / "quantum-proof" claim is ever made.
    """
    import json as _json
    try:
        from sksecurity.pqc_report import (
            build_project_report, format_project_report,
        )
    except Exception:
        _print(
            "\n  [yellow]sksecurity is not installed[/] — the PQC self-report "
            "lives in sksecurity (the honesty engine).\n"
            "  Install it, then re-run, or use: [cyan]sksecurity pqc-report "
            "--project skcomms[/]\n"
        )
        raise SystemExit(1)
    rpt = build_project_report("skcomms", live=not static)
    if output_format == "json":
        click.echo(_json.dumps(rpt, indent=2))
    else:
        click.echo(format_project_report(rpt))


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# consent — first-contact request management (skfed-consent-design gate 5+)
# ---------------------------------------------------------------------------


def _consent_agent() -> str:
    """Resolve this CLI's agent (SKAGENT, else the self identity, else 'local')."""
    import os

    a = os.environ.get("SKAGENT")
    if a:
        return a
    try:
        from .identity import resolve_self_identity

        return resolve_self_identity().get("agent") or "local"
    except Exception:
        return "local"


@main.group("consent")
def consent_group():
    """First-contact consent — manage quarantined requests and contacts."""


@consent_group.command("requests")
def consent_requests_cmd():
    """List quarantined first-contact requests (the knock queue)."""
    from .consent_requests import list_requests

    reqs = list_requests(_consent_agent())
    if not reqs:
        click.echo("No pending requests.")
        return
    for r in reqs:
        click.echo(f"  {r['sender']}  (env {r['envelope_id']})")


@consent_group.command("accept")
@click.argument("sender")
def consent_accept_cmd(sender):
    """Accept a request → promote to a known contact and mint its delivery token."""
    from .consent_requests import accept_request
    from .consent_tokens import TokenStore

    agent = _consent_agent()
    accept_request(agent, sender)
    token = TokenStore(agent).issue(sender)
    click.echo(f"Accepted {sender}. Delivery token: {token}")


@consent_group.command("decline")
@click.argument("sender")
@click.option("--block", is_flag=True, help="Also block the sender.")
def consent_decline_cmd(sender, block):
    """Decline a request; with --block, also block the sender."""
    from .consent_requests import decline_request

    decline_request(_consent_agent(), sender, block=block)
    click.echo(f"Declined {sender}" + (" + blocked" if block else ""))


@consent_group.command("block")
@click.argument("sender")
def consent_block_cmd(sender):
    """Block a sender (its traffic is dropped)."""
    from .consent_requests import block_sender

    block_sender(_consent_agent(), sender)
    click.echo(f"Blocked {sender}")


@consent_group.command("unblock")
@click.argument("sender")
def consent_unblock_cmd(sender):
    """Unblock a previously-blocked sender."""
    from .consent_requests import unblock

    unblock(_consent_agent(), sender)
    click.echo(f"Unblocked {sender}")


@consent_group.command("known")
def consent_known_cmd():
    """List known/accepted contacts."""
    from .consent_requests import list_known

    known = list_known(_consent_agent())
    if not known:
        click.echo("No known contacts.")
        return
    for k in known:
        click.echo(f"  {k}")
