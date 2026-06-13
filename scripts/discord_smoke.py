"""
Discord smoke-test — read-only connectivity check.

Logs in as the configured bot, prints the bot user identity, and lists the
guilds + channels visible to the bot.

NO messages are sent. This script NEVER imports inside the test suite.

Usage::

    DISCORD_BOT_TOKEN=Bot.your.token.here python scripts/discord_smoke.py

    # Or pass the token directly
    python scripts/discord_smoke.py --token "Bot .your.token.here"

Creds (in priority order):
  1. --token flag
  2. DISCORD_BOT_TOKEN environment variable
  3. ~/.skcomm/config.yml  adapters.discord.bot_token

The bot must be:
  - Created at https://discord.com/developers/applications
  - Have MESSAGE_CONTENT + GUILD_MESSAGES + DIRECT_MESSAGES privileged intents
    enabled in the Bot settings page
  - Added to at least one guild via the OAuth2 invite URL
    (see docs/DISCORD_SETUP.md for the full setup guide)

See docs/DISCORD_SETUP.md for the complete setup walkthrough.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def _load_config_yml() -> dict:
    """
    Load ~/.skcomm/config.yml and return the adapters.discord section.
    Returns an empty dict if the file does not exist or has no discord block.
    """
    config_path = Path("~/.skcomm/config.yml").expanduser()
    if not config_path.exists():
        return {}
    try:
        import yaml

        raw = yaml.safe_load(config_path.read_text()) or {}
        top = raw.get("skcomm", raw)
        return top.get("adapters", {}).get("discord", {})
    except Exception as exc:
        print(f"[warn] could not parse {config_path}: {exc}", file=sys.stderr)
        return {}


def _resolve_token(args: argparse.Namespace) -> str:
    """
    Resolve bot token in priority order.
    Raises SystemExit with a clear message if not found.
    """
    cfg = _load_config_yml()

    token = (
        args.token
        or os.environ.get("DISCORD_BOT_TOKEN")
        or cfg.get("bot_token", "")
    )

    if not token:
        print(
            "ERROR: Discord bot token not found.\n"
            "Provide it via:\n"
            "  --token  flag\n"
            "  DISCORD_BOT_TOKEN  environment variable\n"
            "  ~/.skcomm/config.yml  adapters.discord.bot_token\n"
            "\nSee docs/DISCORD_SETUP.md for how to create a bot and get a token.",
            file=sys.stderr,
        )
        sys.exit(1)

    return token


async def run_smoke(token: str) -> None:
    """Connect as the bot, print identity and visible guilds/channels."""
    try:
        import discord
    except ImportError:
        print(
            "ERROR: discord.py is not installed.\n"
            "Install it: pip install 'skcomms[discord]'  (or: pip install discord.py)",
            file=sys.stderr,
        )
        sys.exit(1)

    intents = discord.Intents.default()
    intents.message_content = True
    intents.guild_messages = True
    intents.dm_messages = True
    intents.guilds = True

    client = discord.Client(intents=intents)

    ready_event = asyncio.Event()
    results: dict = {"guilds": [], "me": None, "error": None}

    @client.event
    async def on_ready() -> None:
        me = client.user
        results["me"] = me
        print(
            f"\n[discord_smoke] Connected as: {me.name} (id={me.id})"
        )
        print(f"[discord_smoke] Bot account: {me.bot}\n")

        guilds = list(client.guilds)
        if not guilds:
            print("[discord_smoke] No guilds visible — the bot has not been added to any server yet.")
            print("  See docs/DISCORD_SETUP.md for the invite URL steps.")
        else:
            print(f"[discord_smoke] Visible guilds ({len(guilds)}):")
            for guild in guilds:
                results["guilds"].append(guild)
                print(f"  Guild: {guild.name!r}  (id={guild.id}, members~{guild.member_count})")
                channels = [
                    ch for ch in guild.channels
                    if isinstance(ch, (discord.TextChannel, discord.DMChannel))
                ]
                if channels:
                    for ch in channels[:10]:
                        perms = ch.permissions_for(guild.me)
                        can_read = getattr(perms, "read_messages", False)
                        can_send = getattr(perms, "send_messages", False)
                        print(
                            f"    #{ch.name}  (id={ch.id})"
                            f"  read={can_read}  send={can_send}"
                        )
                    if len(channels) > 10:
                        print(f"    ... and {len(channels) - 10} more channels")
                else:
                    print("    (no text channels visible)")

        print("\n[discord_smoke] OK — read-only smoke test complete.\n")
        ready_event.set()
        await client.close()

    @client.event
    async def on_error(event: str, *args: object, **kwargs: object) -> None:
        results["error"] = f"Gateway error in {event}"
        ready_event.set()
        await client.close()

    try:
        await client.start(token)
    except discord.LoginFailure:
        print(
            "ERROR: Discord login failed — token is invalid or malformed.\n"
            "Check that DISCORD_BOT_TOKEN is the bot token (not OAuth client secret).",
            file=sys.stderr,
        )
        sys.exit(1)
    except discord.PrivilegedIntentsRequired:
        print(
            "ERROR: Privileged intents required.\n"
            "Enable MESSAGE_CONTENT + GUILD_MEMBERS intents at:\n"
            "  https://discord.com/developers/applications/<YOUR_APP_ID>/bot\n"
            "See docs/DISCORD_SETUP.md for details.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: unexpected error: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discord read-only smoke test (no messages sent)"
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Discord bot token (overrides env/config). Include 'Bot ' prefix or omit it.",
    )
    args = parser.parse_args()

    token = _resolve_token(args)
    asyncio.run(run_smoke(token))


if __name__ == "__main__":
    main()
