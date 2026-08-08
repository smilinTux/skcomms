"""_load_recipient_key must resolve a same-box agent's local key even when the
peer fqid's realm string has drifted from the cluster realm (operator-component
match), while still rejecting a cross-operator name collision."""

import skcomms.mailbox as mb


def test_same_box_match_is_operator_component_not_exact_realm(monkeypatch, tmp_path):
    monkeypatch.setattr(mb, "get_operator", lambda: "chef")
    monkeypatch.setattr(mb, "get_realm", lambda: "skworld.io")

    # A local agent key on disk, addressed by bare agent name.
    key_dir = tmp_path / "agents" / "lumina" / "capauth" / "identity"
    key_dir.mkdir(parents=True)
    (key_dir / "public.asc").write_text("REAL-LUMINA-KEY")
    monkeypatch.setattr(
        mb, "_agent_identity_dir", lambda a: tmp_path / "agents" / a / "capauth" / "identity"
    )
    monkeypatch.setattr(mb, "skcomms_home", lambda: tmp_path / "home")

    # Drifted realm on the fqid (chef.skworld, cluster says chef.skworld.io):
    # operator component still "chef", so the local key MUST resolve.
    assert mb._load_recipient_key("lumina@chef.skworld") == "REAL-LUMINA-KEY"
    # Current realm form also resolves.
    assert mb._load_recipient_key("lumina@chef.skworld.io") == "REAL-LUMINA-KEY"


def test_cross_operator_name_collision_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(mb, "get_operator", lambda: "chef")
    monkeypatch.setattr(mb, "get_realm", lambda: "skworld.io")
    key_dir = tmp_path / "agents" / "lumina" / "capauth" / "identity"
    key_dir.mkdir(parents=True)
    (key_dir / "public.asc").write_text("LOCAL-LUMINA-KEY")
    monkeypatch.setattr(
        mb, "_agent_identity_dir", lambda a: tmp_path / "agents" / a / "capauth" / "identity"
    )
    monkeypatch.setattr(mb, "skcomms_home", lambda: tmp_path / "home")

    # A DIFFERENT operator's agent that happens to be named "lumina" must NOT
    # seal to the local lumina key (no peers/<fqid>.asc exists -> None).
    assert mb._load_recipient_key("lumina@stranger.otherrealm") is None
