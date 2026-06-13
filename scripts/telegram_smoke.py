"""
Telegram smoke-test — read-only connectivity check.

Connects with the Telethon user session, prints ``get_me()`` info, lists
the first 20 dialogs, and (optionally) reads the last 5 messages from a
given chat through the TelegramAdapter's ``_normalize_telethon`` pipeline.

NO messages are sent. This script NEVER imports inside the test suite.

Usage::

    # Basic — just connect and list dialogs
    TELEGRAM_API_ID=12345 TELEGRAM_API_HASH=abc123 \\
        python scripts/telegram_smoke.py

    # Also read recent messages from DR-Chiro and run them through _normalize
    TELEGRAM_API_ID=12345 TELEGRAM_API_HASH=abc123 \\
        python scripts/telegram_smoke.py --chat -5134021983

    # Use a different session file
    TELEGRAM_API_ID=12345 TELEGRAM_API_HASH=abc123 \\
        python scripts/telegram_smoke.py \\
            --session ~/.skcapstone/agents/lumina/telegram.session \\
            --chat -5134021983

Creds (in priority order):
  1. Command-line flags --api-id / --api-hash
  2. Environment variables TELEGRAM_API_ID / TELEGRAM_API_HASH
  3. ~/.skcomm/config.yml  adapters.telegram.api_id / api_hash

Session file:
  Default: ~/.skcapstone/agents/lumina/telegram.session
  The account must already be authorized (run ``python -m telethon.sync``
  or use the Telethon auth flow once to create the .session file).

Note on DR-Chiro group (-5134021983):
  The Lumina user account must be a member of that group before ``--chat``
  will return any messages.  If the account is not yet a member you will
  see an empty dialog list for that chat or a ``ChannelPrivateError``.
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
    Load ~/.skcomm/config.yml and return the adapters.telegram section.
    Returns an empty dict if the file does not exist or has no telegram block.
    """
    config_path = Path("~/.skcomm/config.yml").expanduser()
    if not config_path.exists():
        return {}
    try:
        import yaml

        raw = yaml.safe_load(config_path.read_text()) or {}
        # Support both top-level and nested under "skcomm:"
        top = raw.get("skcomm", raw)
        return top.get("adapters", {}).get("telegram", {})
    except Exception as exc:
        print(f"[warn] could not parse {config_path}: {exc}", file=sys.stderr)
        return {}


def _resolve_creds(args: argparse.Namespace) -> tuple[str, str, str]:
    """
    Resolve api_id, api_hash, session_file in priority order.
    Raises SystemExit with a clear message if required creds are missing.
    """
    cfg = _load_config_yml()

    api_id = (
        args.api_id
        or os.environ.get("TELEGRAM_API_ID")
        or cfg.get("api_id", "")
    )
    api_hash = (
        args.api_hash
        or os.environ.get("TELEGRAM_API_HASH")
        or cfg.get("api_hash", "")
    )
    session_file = (
        args.session
        or os.environ.get("TELEGRAM_SESSION")
        or cfg.get("session_file", "~/.skcapstone/agents/lumina/telegram.session")
    )

    if not api_id or not api_hash:
        print(
            "ERROR: Telegram API credentials not found.\n"
            "Provide them via:\n"
            "  --api-id / --api-hash  flags\n"
            "  TELEGRAM_API_ID / TELEGRAM_API_HASH  environment variables\n"
            "  ~/.skcomm/config.yml  adapters.telegram.api_id / api_hash\n",
            file=sys.stderr,
        )
        sys.exit(1)

    return str(api_id), str(api_hash), str(session_file)


async def run_smoke(
    api_id: str,
    api_hash: str,
    session_file: str,
    chat_id: str | None,
) -> None:
    """Connect, print identity + dialogs, optionally normalize recent messages."""
    try:
        from telethon import TelegramClient
    except ImportError:
        print(
            "ERROR: telethon is not installed.\n"
            "Install it: pip install 'skcomms[telegram]'  (or: pip install telethon)",
            file=sys.stderr,
        )
        sys.exit(1)

    session_path = str(Path(session_file).expanduser())
    print(f"[telegram_smoke] session: {session_path}")
    print(f"[telegram_smoke] api_id:  {api_id}")

    client = TelegramClient(session_path, int(api_id), api_hash)

    try:
        await client.connect()
        authorized = await client.is_user_authorized()
        if not authorized:
            print(
                "ERROR: The session file exists but the account is NOT authorized.\n"
                "Run the Telethon interactive auth flow once:\n"
                "  python -c \"from telethon.sync import TelegramClient; "
                f"c = TelegramClient('{session_path}', {api_id}, '{api_hash}'); "
                "c.start()\"",
                file=sys.stderr,
            )
            sys.exit(1)

        me = await client.get_me()
        print(
            f"\n[telegram_smoke] Connected as: {me.first_name} {me.last_name or ''}"
            f" (@{me.username or 'no-username'}, id={me.id})\n"
        )

        # List first 20 dialogs
        print("[telegram_smoke] First 20 dialogs:")
        dialog_count = 0
        async for dialog in client.iter_dialogs(limit=20):
            unread = getattr(dialog, "unread_count", 0)
            print(f"  [{dialog.id:>15}]  {dialog.name}  (unread={unread})")
            dialog_count += 1
        if dialog_count == 0:
            print("  (no dialogs found — account may have no chats)")

        # Optional: read last messages and run through _normalize_telethon
        if chat_id is not None:
            print(f"\n[telegram_smoke] Reading last 5 messages from chat {chat_id} ...")
            from skcomms.adapters.telegram import TelegramAdapter

            adapter = TelegramAdapter(
                config={
                    "api_id": api_id,
                    "api_hash": api_hash,
                    "session_file": session_file,
                    "rooms": {
                        "smoke_chat": {
                            "chat_id": chat_id,
                            "agent_fqid": "lumina@skworld.io",
                        }
                    },
                },
                telethon_client=client,  # reuse the already-connected client
                bindings_store={},
            )

            room_cfg = {"chat_id": chat_id, "agent_fqid": "lumina@skworld.io"}
            msg_count = 0
            try:
                async for tg_msg in client.iter_messages(chat_id, limit=5):
                    normalized = adapter._normalize_telethon(tg_msg, chat_id, room_cfg)
                    if normalized is not None:
                        print(
                            f"  msg_id={normalized.platform_msg_id}"
                            f"  kind={normalized.kind.value}"
                            f"  sender={normalized.sender.platform_name!r}"
                            f"  text={normalized.text[:80]!r}"
                        )
                    else:
                        print("  [dropped — no sender or unhandled type]")
                    msg_count += 1
            except Exception as exc:
                print(
                    f"[warn] could not read messages from {chat_id}: {exc}\n"
                    "  The account may not be a member of that chat yet.",
                    file=sys.stderr,
                )
            if msg_count == 0:
                print(
                    f"  (no messages returned for chat {chat_id} — "
                    "account may not be a member)"
                )

        print("\n[telegram_smoke] OK — read-only smoke test complete.\n")

    finally:
        await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Telegram read-only smoke test (no messages sent)"
    )
    parser.add_argument("--api-id", help="Telegram API ID (overrides env/config)")
    parser.add_argument("--api-hash", help="Telegram API hash (overrides env/config)")
    parser.add_argument(
        "--session",
        default=None,
        help="Path to Telethon .session file (default: ~/.skcapstone/agents/lumina/telegram.session)",
    )
    parser.add_argument(
        "--chat",
        default=None,
        metavar="CHAT_ID",
        help=(
            "Optional chat/group id to read last 5 messages from and run through "
            "_normalize_telethon. Example: --chat -5134021983"
        ),
    )
    args = parser.parse_args()

    api_id, api_hash, session_file = _resolve_creds(args)
    asyncio.run(run_smoke(api_id, api_hash, session_file, args.chat))


if __name__ == "__main__":
    main()
