# Discord Bot Setup Guide

Step-by-step walkthrough for creating a Discord application, configuring the
bot, and wiring it into `DiscordAdapter`.

---

## 1. Create a Discord Application

1. Go to <https://discord.com/developers/applications> and sign in.
2. Click **New Application** (top-right).
3. Give it a name (e.g. `Lumina`), accept the ToS, and click **Create**.

---

## 2. Create the Bot User

1. In the left sidebar click **Bot**.
2. Click **Add Bot** → **Yes, do it!**.
3. Under the bot's username, click **Reset Token**, confirm, and **copy the
   token** — you will only see it once.  Store it as `DISCORD_BOT_TOKEN`.

> **Never** commit the token to git.  Store it in an env var or in
> `~/.skcomm/config.yml` under `adapters.discord.bot_token`.

---

## 3. Enable Privileged Gateway Intents

On the **Bot** page, scroll to **Privileged Gateway Intents** and toggle ON:

| Intent | Required for |
|--------|-------------|
| **PRESENCE INTENT** | Optional (rich presence) |
| **SERVER MEMBERS INTENT** | Member name resolution |
| **MESSAGE CONTENT INTENT** | **Required** — reading message bodies |

Click **Save Changes**.

Without `MESSAGE_CONTENT`, the bot will receive messages with empty `content`
and `DiscordAdapter._normalize()` will produce empty-text `ChannelMessage` objects.

---

## 4. Set Bot Permissions

1. In the left sidebar click **OAuth2 → URL Generator**.
2. Under **Scopes** check `bot`.
3. Under **Bot Permissions** check at minimum:

   - Read Messages / View Channels
   - Send Messages
   - Read Message History
   - Attach Files
   - Add Reactions
   - Use Slash Commands (optional, for future interaction events)

4. Copy the generated **OAuth2 URL** at the bottom of the page.

---

## 5. Invite the Bot to Your Guild

1. Paste the OAuth2 URL in a browser.
2. Choose the target Discord server (guild) from the dropdown.
3. Confirm the permissions and click **Authorize**.

The bot will now appear as an offline member of that guild.

---

## 6. Configure the Token

**Option A — environment variable (recommended):**

```bash
export DISCORD_BOT_TOKEN="Bot MTEx...your_token"
```

The `Bot ` prefix is optional — `discord.py` handles it either way.

**Option B — `~/.skcomm/config.yml`:**

```yaml
skcomm:
  adapters:
    discord:
      enabled: true
      bot_token: "MTEx...your_token"   # or "${DISCORD_BOT_TOKEN}"
      poll_interval_s: 1
      guilds:
        skworld:
          guild_id: "1234567890123456789"
          channels:
            general:
              channel_id: "9876543210987654321"
              agent_fqid: "lumina@skworld.io"
      identity_store: "~/.skcomm/adapters/discord-ids.yaml"
```

Obtain `guild_id` and `channel_id` from Discord: right-click a server/channel
with **Developer Mode** enabled (User Settings → Advanced → Developer Mode).

---

## 7. Install the Python Dependency

```bash
pip install "skcomms[discord]"
# or just:
pip install "discord.py>=2.3"
```

---

## 8. Test with the Smoke Script

```bash
python scripts/discord_smoke.py
```

Expected output (successful):

```
[discord_smoke] Connected as: Lumina (id=123456789012345678)
[discord_smoke] Bot account: True

[discord_smoke] Visible guilds (1):
  Guild: 'SKWorld'  (id=1234567890123456789, members~5)
    #general  (id=9876543210987654321)  read=True  send=True
    #bot-testing  (id=...)  read=True  send=True

[discord_smoke] OK — read-only smoke test complete.
```

If you see **"No guilds visible"** the bot has not been added to a server yet —
repeat step 5.

If you see **"Privileged intents required"** re-check step 3.

---

## 9. Telegram Note

For the Telegram adapter's DR-Chiro group (`-5134021983`), the Lumina **user
account** (not a bot — Telethon uses a user session) must be a member of the
group before any messages will appear.

Steps:
1. Have Chef add `@lumina_account` (or the phone number) to the group in
   Telegram.
2. Run the Telegram smoke test:

   ```bash
   TELEGRAM_API_ID=12345 TELEGRAM_API_HASH=abc123 \
       python scripts/telegram_smoke.py --chat -5134021983
   ```

3. Confirm you see messages printed with `kind=text sender=...`.

If the account is not yet a member, `iter_messages` returns 0 messages (or a
`ChannelPrivateError`).  This is expected — add the account first.

---

## Summary: Commands Chef Runs to Test Live

**Telegram (read-only):**

```bash
# Minimal — just connect and list dialogs
TELEGRAM_API_ID=12345 TELEGRAM_API_HASH=abc123 \
    python scripts/telegram_smoke.py

# With DR-Chiro group normalization check
TELEGRAM_API_ID=12345 TELEGRAM_API_HASH=abc123 \
    python scripts/telegram_smoke.py --chat -5134021983
```

**Discord (read-only):**

```bash
DISCORD_BOT_TOKEN="Bot MTEx...your_token" \
    python scripts/discord_smoke.py
```
