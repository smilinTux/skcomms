# Tier 3 — Channel-adapter runtime plumbing (config → registry → lifecycle)

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Repo: `skcomms`, branch `integration/skcomms-unified`. Tests: `cd ~ && ~/.skenv/bin/python -m pytest /home/cbrd21/clawd/skcapstone-repos/skcomms/tests/<file> -q`.

**Goal:** Close the audit's "beautiful library with no plumbing" gap. The adapters
(`telegram`/`discord`/`slack`/`matrix`) and `AdapterRegistry` (with `start/stop/health_all`)
exist and are unit-tested, but the registry is **never instantiated from config**. Build
the missing runtime path: `BUILTIN_ADAPTERS` factory + `build_registry_from_config()` +
a token-free `FakeAdapter` so the whole runtime is testable **without any bot tokens**.
Live bridging to real TG/Discord/Slack stays GATED on Chef's creds.

**Architecture:** Mirror `core.py`'s `BUILTIN_TRANSPORTS` pattern. A factory maps
`adapter_type → constructor`, expands `${ENV_VAR}` placeholders in config values, and
constructs the right adapter (handling the heterogeneous constructor shapes). A builder
reads the `adapters:` block of `~/.skcomms/config.yml`, builds each **enabled** adapter,
and **skips** adapters whose required token is missing/empty (so it never crashes without
creds — the GATED-friendly behaviour). A `FakeAdapter` implements the ABC with no network
so the registry + lifecycle are CI-testable.

**Files:**
- Create `src/skcomms/adapters/fake.py` — `FakeAdapter`.
- Create `src/skcomms/adapters/factory.py` — `BUILTIN_ADAPTERS`, `expand_env`, `build_adapter`, `build_registry_from_config`.
- Modify `src/skcomms/adapters/__init__.py` — export the new names.
- Tests: `tests/test_adapter_fake.py`, `tests/test_adapter_factory.py`.

---

## Task 0: Discovery (report before coding)

Read and record EXACT signatures — do not assume:
1. `src/skcomms/adapters/base.py` — every `@abstractmethod` on `ChannelAdapter` (names + full signatures + return types), and the class attrs `channel_type` / `adapter_name`. `FakeAdapter` must implement ALL abstract methods.
2. Constructor signatures of `TelegramAdapter`, `DiscordAdapter`, `SlackAdapter`, `MatrixAdapter` (first positional arg: config-dict vs bare token — discord is `__init__(self, token: str)`, others take a config dict; confirm exact param names).
3. `AdapterRegistry.__init__` signature (what it needs — e.g. a dispatch callback / hub) and `register()`.
4. `ChannelType` enum members; `AdapterHealth` and `AdapterCapabilities` constructors (FakeAdapter.health must return a real `AdapterHealth`).
5. `ChannelMessage` minimal constructor (FakeAdapter.send takes one, returns a str id; inbound yields them).

Report these before STEP 3 of each task.

---

## Task 1: `FakeAdapter` — token-free ABC implementation

**Files:** Create `src/skcomms/adapters/fake.py`. Test `tests/test_adapter_fake.py`.

- [ ] **Step 1: Failing test** — `tests/test_adapter_fake.py`:

```python
import pytest

from skcomms.adapters.fake import FakeAdapter


@pytest.mark.asyncio
async def test_fake_connects_and_reports_healthy():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    assert a.adapter_name == "fake-1"
    await a.connect()
    h = await a.health()
    assert h.connected is True
    await a.disconnect()
    h2 = await a.health()
    assert h2.connected is False


@pytest.mark.asyncio
async def test_fake_send_returns_id_and_records():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    await a.connect()
    mid = await a.send(a.make_message("hello"))
    assert isinstance(mid, str) and mid
    assert a.sent and a.sent[-1] is not None


@pytest.mark.asyncio
async def test_fake_inbound_yields_injected_messages():
    a = FakeAdapter(config={"adapter_name": "fake-1"})
    await a.connect()
    a.inject(a.make_message("ping"))
    got = []
    async for m in a.inbound():
        got.append(m)
        break
    assert got
```

> NOTE: confirm the health field is named `connected` in `AdapterHealth` during Task 0;
> if the real field differs (e.g. `is_healthy`/`ok`), adjust BOTH the test and impl to
> the real name and say so in your report.

- [ ] **Step 2: FAIL.** **Step 3: Implement** `fake.py`: a `ChannelAdapter` subclass setting `channel_type` (use a real `ChannelType` member — pick the most generic, or reuse an existing one) and `adapter_name` (from `config["adapter_name"]`, default `"fake"`). Implement every abstract method: `connect` sets `self._connected=True`; `disconnect` sets False; `health` returns a real `AdapterHealth(connected=self._connected, ...)`; `inbound` is an async generator draining an internal `asyncio.Queue` (the `inject()` helper puts onto it); `send` appends to `self.sent` and returns a uuid4 hex str; `resolve_fqid`/`bind_fqid` return simple stubs (None / echo). Add non-ABC helpers `make_message(text)` (builds a minimal valid `ChannelMessage`), `inject(msg)`, and lists `self.sent`. Keep it import-light (no network libs).

- [ ] **Step 4: PASS** (`pytest tests/test_adapter_fake.py -q`; needs `pytest-asyncio` — confirm it's available, the repo already uses async tests). **Step 5: Commit** `feat(adapters): FakeAdapter — token-free ABC impl for runtime tests`.

---

## Task 2: factory + `build_registry_from_config` + env expansion

**Files:** Create `src/skcomms/adapters/factory.py`. Modify `src/skcomms/adapters/__init__.py`. Test `tests/test_adapter_factory.py`.

- [ ] **Step 1: Failing test** — `tests/test_adapter_factory.py`:

```python
import pytest

from skcomms.adapters.factory import (
    BUILTIN_ADAPTERS,
    build_adapter,
    build_registry_from_config,
    expand_env,
)


def test_builtin_adapters_has_all_known_types():
    assert {"telegram", "discord", "slack", "matrix", "fake"} <= set(BUILTIN_ADAPTERS)


def test_expand_env_substitutes(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "secret-xyz")
    out = expand_env({"bot_token": "${MY_TOKEN}", "plain": "x"})
    assert out == {"bot_token": "secret-xyz", "plain": "x"}


def test_expand_env_missing_var_becomes_empty(monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    assert expand_env({"t": "${NOPE}"}) == {"t": ""}


def test_build_fake_adapter():
    a = build_adapter("fake", {"adapter_name": "fake-A"})
    assert a.adapter_name == "fake-A"


def test_build_unknown_type_raises():
    with pytest.raises(ValueError, match="unknown adapter"):
        build_adapter("bogus", {})


def test_registry_builds_only_enabled_with_tokens(monkeypatch):
    cfg = {
        "adapters": {
            "fake": {"enabled": True, "adapter_name": "fake-A"},
            "discord": {"enabled": True, "bot_token": ""},      # no token → SKIP
            "slack": {"enabled": False, "bot_token": "x"},      # disabled → SKIP
        }
    }
    reg, built, skipped = build_registry_from_config(cfg)
    assert "fake-A" in built
    assert "discord" in skipped and "slack" in skipped
    assert reg.get("fake-A") is not None


def test_registry_empty_config_is_empty():
    reg, built, skipped = build_registry_from_config({})
    assert built == [] and reg is not None
```

> Adjust `reg.get(...)` key to the real registry key (adapter_name) per Task 0. If
> `AdapterRegistry()` needs a required arg (e.g. a dispatch callback), pass a no-op
> default inside `build_registry_from_config` and note it.

- [ ] **Step 2: FAIL.** **Step 3: Implement** `factory.py`:
  - `BUILTIN_ADAPTERS: dict[str, str]` mapping type → dotted `module:Class` (like `BUILTIN_TRANSPORTS`), OR a dict type→callable. Include `fake`.
  - `expand_env(config: dict) -> dict`: replace any string value exactly matching `${VAR}` with `os.environ.get(VAR, "")`; recurse one level into nested dicts; leave non-`${...}` strings as-is.
  - `build_adapter(adapter_type, config) -> ChannelAdapter`: `expand_env` the config, then construct the right class handling the heterogeneous shape discovered in Task 0 (e.g. `discord` → `DiscordAdapter(config["bot_token"])`; others → `Class(config)`). Raise `ValueError(f"unknown adapter type {adapter_type!r}")` otherwise.
  - `build_registry_from_config(cfg, *, registry=None) -> tuple[registry, built_names, skipped_types]`: iterate `cfg.get("adapters", {})`; skip if `enabled is False`; determine the required token field per type (telegram/discord/slack: `bot_token`; matrix: `access_token`; fake: none) and **skip with reason** if required token is empty after env-expansion; else `build_adapter` + `registry.register(...)`. Return the registry, list of built adapter_names, and list of skipped types. Never raise on a missing token — that's the GATED path.
  - Export all four names from `adapters/__init__.py`.

- [ ] **Step 4: PASS** + **no regression** in existing adapter tests: `pytest tests/test_channel_adapter.py tests/test_adapter_factory.py tests/test_adapter_fake.py -q`. **Step 5: Commit** `feat(adapters): config→registry factory + env expansion + graceful token-gating`.

---

## Final verification

- [ ] `cd ~ && ~/.skenv/bin/python -m pytest /home/cbrd21/clawd/skcapstone-repos/skcomms/tests/test_adapter_*.py /home/cbrd21/clawd/skcapstone-repos/skcomms/tests/test_channel_adapter.py /home/cbrd21/clawd/skcapstone-repos/skcomms/tests/test_telegram_adapter.py -q` → all pass.
- [ ] `~/.skenv/bin/ruff check src/skcomms/adapters/fake.py src/skcomms/adapters/factory.py tests/test_adapter_*.py` → clean.

## What this delivers + what stays GATED

**Delivered (CI, no tokens):** a tested path from config → live `AdapterRegistry` with
lifecycle, plus graceful skip of unconfigured adapters. The plumbing the audit said was
missing.

**Still GATED on Chef's creds / follow-on (NOT in this slice, documented for honesty):**
(a) real Discord/Slack client internals (`discord.py`/`slack_sdk`) — stubs remain until a
token exists to test against; (b) a daemon/service that calls `build_registry_from_config`
+ `registry.start()` and bridges inbound→skchat; (c) a `/adapters` status REST endpoint in
skchat webui + a UI surface. These are filed as Tier-3 follow-ons in the QA matrix.
