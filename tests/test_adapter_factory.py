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
