"""Tests for the `skcomms skfed` CLI group (announce + show).

These cover the wiring only: announce delegates to skfed_announce.announce_self,
show reads the persisted directory. The crypto/persistence is covered by
test_skfed_announce.py / test_skfed_directory.py.
"""

from __future__ import annotations

from click.testing import CliRunner


def test_skfed_announce_dry_run(monkeypatch):
    from skcomms import cli

    monkeypatch.setenv("SKFED_BASE_URL", "https://node.ts.net")
    monkeypatch.setattr(
        "skcomms.identity.resolve_self_identity",
        lambda agent=None: {"fqid": "jarvis@chef.skworld"},
    )
    runner = CliRunner()
    res = runner.invoke(cli.main, ["skfed", "announce", "--dry-run", "--cap", "dm"])
    assert res.exit_code == 0, res.output
    assert "DRY-RUN" in res.output
    assert "jarvis@chef.skworld" in res.output
    assert "https://node.ts.net/api/v1/inbox" in res.output
    assert "https://node.ts.net/api/v1/prekey" in res.output


def test_skfed_announce_invokes_announce_self(monkeypatch):
    from skcomms import cli, skfed_announce

    captured = {}

    class _SD:
        realm = "skworld"
        signer_fingerprint = "ABCDEF0123456789abcdef"
        entries = []

    def fake_announce_self(agent, **kw):
        captured["agent"] = agent
        captured.update(kw)
        return _SD()

    monkeypatch.setattr(skfed_announce, "announce_self", fake_announce_self)
    monkeypatch.setattr(
        "skcomms.identity.resolve_self_identity",
        lambda agent=None: {"fqid": "lumina@chef.skworld"},
    )
    runner = CliRunner()
    res = runner.invoke(
        cli.main,
        ["skfed", "announce", "--agent", "lumina", "--base", "https://l.ts.net", "--cap", "dm", "--cap", "files"],
    )
    assert res.exit_code == 0, res.output
    assert captured["agent"] == "lumina"
    assert captured["base"] == "https://l.ts.net"
    assert captured["caps"] == ["dm", "files"]
    assert "announced lumina@chef.skworld" in res.output


def test_skfed_show_empty(tmp_path, monkeypatch):
    from skcomms import cli

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    runner = CliRunner()
    res = runner.invoke(cli.main, ["skfed", "show"])
    assert res.exit_code == 0, res.output
    assert "No realm directory yet" in res.output


def test_skfed_show_lists_entries(tmp_path, monkeypatch):
    from skcomms import cli
    from skcomms import skfed_directory as sfd
    from skcomms.skfed_directory import DirectoryEntry, SignedDirectory

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    sd = SignedDirectory(
        realm="skworld",
        operator="chef",
        entries=[
            DirectoryEntry(
                fqid="jarvis@chef.skworld",
                inbox_url="https://j.ts.net/api/v1/inbox",
                prekey_url="https://j.ts.net/api/v1/prekey",
                caps=["dm"],
            )
        ],
    )
    sfd.save_directory(sd)

    runner = CliRunner()
    res = runner.invoke(cli.main, ["skfed", "show"])
    assert res.exit_code == 0, res.output
    assert "jarvis@chef.skworld" in res.output
    assert "https://j.ts.net/api/v1/inbox" in res.output

    res_json = runner.invoke(cli.main, ["skfed", "show", "--json"])
    assert res_json.exit_code == 0
    assert '"realm": "skworld"' in res_json.output
