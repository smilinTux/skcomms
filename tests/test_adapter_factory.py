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


def test_expand_env_recurses_one_level_into_nested_dict(monkeypatch):
    monkeypatch.setenv("NESTED_TOKEN", "deep-secret")
    out = expand_env({"opts": {"k": "${NESTED_TOKEN}", "plain": "v"}, "x": "y"})
    assert out["opts"] == {"k": "deep-secret", "plain": "v"}
    assert out["x"] == "y"


def test_expand_env_leaves_non_string_values_untouched():
    out = expand_env({"n": 5, "flag": True, "lst": [1, 2]})
    assert out == {"n": 5, "flag": True, "lst": [1, 2]}


def test_enabled_omitted_defaults_to_built(monkeypatch):
    # No `enabled` key at all → not skipped (only `enabled is False` skips).
    cfg = {"adapters": {"fake": {"adapter_name": "fake-default"}}}
    reg, built, skipped = build_registry_from_config(cfg)
    assert "fake-default" in built
    assert "fake" not in skipped


def test_token_gating_skips_when_env_token_empty(monkeypatch):
    # An env-var token that is unset expands to "" → token-gated skip (no crash).
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    cfg = {
        "adapters": {
            "discord": {"enabled": True, "bot_token": "${DISCORD_BOT_TOKEN}"},
        }
    }
    reg, built, skipped = build_registry_from_config(cfg)
    assert built == []
    assert "discord" in skipped


def test_token_gating_builds_when_env_token_present(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "real-token")
    cfg = {
        "adapters": {
            "discord": {"enabled": True, "bot_token": "${DISCORD_BOT_TOKEN}"},
        }
    }
    reg, built, skipped = build_registry_from_config(cfg)
    assert "discord" in skipped or "discord" not in skipped  # type guard
    # discord builds (token present); its adapter_name lands in built.
    assert built and "discord" not in skipped


def test_unknown_adapter_type_in_config_is_skipped_not_raised():
    cfg = {"adapters": {"carrier-pigeon": {"enabled": True, "bot_token": "x"}}}
    reg, built, skipped = build_registry_from_config(cfg)
    assert built == []
    assert "carrier-pigeon" in skipped


def test_matrix_uses_access_token_field_for_gating(monkeypatch):
    # matrix's required field is access_token, NOT bot_token.
    cfg = {
        "adapters": {
            "matrix": {"enabled": True, "bot_token": "wrong-field"},  # no access_token
        }
    }
    reg, built, skipped = build_registry_from_config(cfg)
    assert "matrix" in skipped  # gated on the MISSING access_token


def test_build_registry_reuses_supplied_registry():
    from skcomms.adapters.registry import AdapterRegistry

    pre = AdapterRegistry()
    cfg = {"adapters": {"fake": {"adapter_name": "fake-X"}}}
    reg, built, _ = build_registry_from_config(cfg, registry=pre)
    assert reg is pre
    assert "fake-X" in built
    assert pre.get("fake-X") is not None


def test_none_entry_treated_as_empty(monkeypatch):
    # `fake: ` (null) in YAML → entry is None → coerced to {} → builds (no token).
    cfg = {"adapters": {"fake": None}}
    reg, built, skipped = build_registry_from_config(cfg)
    assert "fake" in built  # FakeAdapter default adapter_name == "fake"
