"""Per-agent path scoping through the single resolver (coord 119b49f1).

Storage historically mixed per-user and per-agent scoping: transfers lived at
the per-user ``~/.skcapstone/transfers``, the federation inbox write used a
hardcoded ``~/.skcapstone/agents/<recipient>/comms/inbox`` template that
bypassed ``SKCOMMS_HOME``, and ``api._fed_inbox_dir`` computed a different
base that the code then overrode. These tests prove the unified behavior:

* the default layout stays byte-identical to the legacy convention,
* a custom ``SKCOMMS_HOME`` keeps writer (S2S inbox gate) and reader (daemon
  config transport paths) in ONE agreeing tree (the old split is dead),
* two agents on one node get fully separated storage trees,
* the peer-controlled recipient component fails closed on traversal,
* in-home legacy queue / retry-outbox / transfer-state entries are adopted,
  not stranded, while adoption never reaches into a fixed ``~/.skcapstone``
  path from a custom ``SKCOMMS_HOME`` (that migration is manual, by design),
* queue adoption is pair-atomic: concurrent adopting daemons can never split
  an envelope/meta pair across two agents' trees.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clean_scoping_env(monkeypatch):
    """Every test starts with no home/agent selectors set."""
    for var in (
        "SKCOMMS_HOME",
        "SKAGENT",
        "SKCAPSTONE_AGENT",
        "SKCOMMS_CONSENT_MODE",
        "SKCOMMS_OUTBOX_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


# --- resolver layout ---------------------------------------------------------


def test_default_layout_matches_legacy_convention(monkeypatch, tmp_path):
    """SKCOMMS_HOME unset: the legacy skcapstone layout is preserved byte for byte."""
    monkeypatch.setenv("HOME", str(tmp_path))
    from skcomms import paths

    skc = tmp_path / ".skcapstone"
    assert paths.agents_root() == skc / "agents"
    assert paths.fed_inbox_dir("lumina") == skc / "agents" / "lumina" / "comms" / "inbox"
    assert paths.agent_comms_outbox("lumina") == skc / "agents" / "lumina" / "comms" / "outbox"
    # Agentless fallbacks keep the historical per-user / node-shared spots.
    assert paths.transfers_dir() == skc / "transfers"
    assert paths.queue_dir() == skc / "skcomms" / "queue"
    assert paths.retry_outbox_dir() == skc / "skcomms" / "outbox"
    assert paths.fed_inbox_base() == skc / "skcomms" / "inbox"


def test_custom_home_scopes_everything_inside_it(monkeypatch, tmp_path):
    """SKCOMMS_HOME set: ALL per-agent state lives inside that home."""
    home = tmp_path / "custom-home"
    monkeypatch.setenv("SKCOMMS_HOME", str(home))
    monkeypatch.setenv("SKAGENT", "opus")
    from skcomms import paths

    for p in (
        paths.agents_root(),
        paths.fed_inbox_dir("opus"),
        paths.transfers_dir(),
        paths.queue_dir(),
        paths.retry_outbox_dir(),
        paths.fed_inbox_base(),
        paths.file_transport_inbox(),
        paths.file_transport_outbox(),
    ):
        assert p.is_relative_to(home), f"{p} escaped the custom SKCOMMS_HOME"


def test_two_agents_get_fully_separated_trees(monkeypatch, tmp_path):
    """Two agents on one node never share a storage directory."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms import paths

    def tree(agent):
        return {
            paths.fed_inbox_dir(agent),
            paths.agent_comms_outbox(agent),
            paths.transfers_dir(agent),
            paths.queue_dir(agent),
            paths.retry_outbox_dir(agent),
        }

    opus, jarvis = tree("opus"), tree("jarvis")
    assert opus.isdisjoint(jarvis)
    for p in opus:
        assert p.is_relative_to(paths.agents_root() / "opus")
    for p in jarvis:
        assert p.is_relative_to(paths.agents_root() / "jarvis")


def test_env_selector_scopes_defaults(monkeypatch, tmp_path):
    """SKAGENT (and the SKCAPSTONE_AGENT fallback) drive the default scoping."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms import paths

    monkeypatch.setenv("SKAGENT", "opus")
    assert paths.queue_dir() == paths.agents_root() / "opus" / "comms" / "queue"
    assert paths.transfers_dir() == paths.agents_root() / "opus" / "transfers"

    monkeypatch.delenv("SKAGENT")
    monkeypatch.setenv("SKCAPSTONE_AGENT", "jarvis")
    assert paths.queue_dir() == paths.agents_root() / "jarvis" / "comms" / "queue"


# --- fail-closed component validation ----------------------------------------


@pytest.mark.parametrize("bad", ["..", ".", "../evil", "a/b", "a\\b", "a\x00b", "", "  "])
def test_unsafe_components_raise(bad):
    from skcomms import paths

    with pytest.raises(ValueError):
        paths.safe_component(bad)


def test_fed_inbox_dir_rejects_traversal_recipient():
    from skcomms import paths

    with pytest.raises(ValueError):
        paths.fed_inbox_dir("../../evil")


def test_unsafe_skagent_fails_closed(monkeypatch):
    """A path-unsafe SKAGENT raises loudly instead of scoping a rogue tree."""
    monkeypatch.setenv("SKAGENT", "../evil")
    from skcomms import paths

    with pytest.raises(ValueError):
        paths.resolve_agent()


# --- reader/writer agreement (the historical split, now dead) ----------------


def _write_config(path: Path) -> Path:
    path.write_text(
        "skcomms:\n"
        "  identity:\n"
        "    name: lumina\n"
        "  transports:\n"
        "    file:\n"
        "      enabled: true\n",
        encoding="utf-8",
    )
    return path


def test_reader_and_writer_agree_under_custom_home(monkeypatch, tmp_path):
    """The daemon's configured inbox (reader) and the S2S gate's write target
    (writer) resolve to the SAME directory under a non-default SKCOMMS_HOME."""
    home = tmp_path / "home"
    monkeypatch.setenv("SKCOMMS_HOME", str(home))
    monkeypatch.setenv("SKAGENT", "lumina")

    from skcomms import paths
    from skcomms.config import load_config

    cfg = load_config(str(_write_config(tmp_path / "config.yml")))
    reader = Path(cfg.transports["file"].settings["inbox_path"])
    writer = paths.fed_inbox_dir("lumina")

    assert reader == writer
    assert reader.is_relative_to(home)
    # The outbox and log paths live in the same agent tree.
    assert Path(cfg.transports["file"].settings["outbox_path"]).is_relative_to(home)
    assert Path(cfg.daemon.log_file).is_relative_to(home)


def test_s2s_write_lands_in_reader_inbox_under_custom_home(monkeypatch, tmp_path):
    """End to end: the API inbox write file lands exactly where the recipient
    daemon's configured inbox_path points. The hardcoded
    ``~/.skcapstone/agents/<recipient>/comms/inbox`` template is gone: nothing
    is written under HOME anymore when SKCOMMS_HOME is elsewhere."""
    home = tmp_path / "home"
    fake_user_home = tmp_path / "user-home"
    fake_user_home.mkdir()
    monkeypatch.setenv("SKCOMMS_HOME", str(home))
    monkeypatch.setenv("HOME", str(fake_user_home))
    monkeypatch.setenv("SKAGENT", "lumina")

    from skcomms import api
    from skcomms.config import load_config
    from skcomms.envelope import Envelope

    env = Envelope(
        from_fqid="jarvis@chef.skworld",
        to_fqid="lumina@chef.skworld",
        body="hello across the seam",
    )
    written = Path(api._write_to_recipient_inbox(env))

    cfg = load_config(str(_write_config(tmp_path / "config.yml")))
    reader = Path(cfg.transports["file"].settings["inbox_path"])
    assert written.parent == reader
    assert written.exists()
    assert written.is_relative_to(home)
    # The old bad behavior is dead: nothing landed under the user's HOME.
    assert not (fake_user_home / ".skcapstone").exists()


def test_traversal_to_fqid_fails_closed_to_base_inbox(monkeypatch, tmp_path):
    """A peer-controlled to_fqid with traversal never escapes the home tree:
    the write falls back to the recipient-less base fed inbox."""
    home = tmp_path / "home"
    monkeypatch.setenv("SKCOMMS_HOME", str(home))

    from skcomms import api, paths
    from skcomms.envelope import Envelope

    env = Envelope(
        from_fqid="jarvis@chef.skworld",
        to_fqid="../../evil@x.y",
        body="escape attempt",
    )
    written = Path(api._write_to_recipient_inbox(env))
    assert written.parent == paths.fed_inbox_base()
    assert written.is_relative_to(home)
    # No attacker-chosen directory materialized anywhere in tmp.
    assert not list(tmp_path.rglob("evil"))


# --- per-store defaults route through the resolver ----------------------------


def test_message_queue_default_is_per_agent_and_adopts_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "opus")

    # Entries queued at the legacy node-shared location before the upgrade.
    legacy = tmp_path / "queue"
    legacy.mkdir(parents=True)
    (legacy / "abc.skc.json").write_bytes(b"{}")
    (legacy / "abc.skc.meta.json").write_bytes(b"{}")

    from skcomms import paths
    from skcomms.queue import MessageQueue

    q = MessageQueue()
    assert q.queue_dir == paths.queue_dir()
    assert q.queue_dir.is_relative_to(paths.agents_root() / "opus")
    # Legacy entries were adopted, not stranded.
    assert (q.queue_dir / "abc.skc.json").exists()
    assert (q.queue_dir / "abc.skc.meta.json").exists()
    assert not (legacy / "abc.skc.json").exists()


def test_concurrent_queue_adoption_never_splits_a_pair(monkeypatch, tmp_path):
    """Two agent daemons adopting the same legacy queue concurrently must
    never split an envelope/meta pair across their trees (the demonstrated
    live race). The meta rename is the claim token: the loser of that rename
    never touches either half of the pair."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms import paths
    from skcomms.queue import ENVELOPE_SUFFIX, META_SUFFIX

    legacy = tmp_path / "queue"
    legacy.mkdir(parents=True)
    (legacy / f"abc{ENVELOPE_SUFFIX}").write_bytes(b"{}")
    (legacy / f"abc{META_SUFFIX}").write_bytes(b"{}")

    dir_a = paths.queue_dir("opus")
    dir_b = paths.queue_dir("jarvis")

    real_rename = Path.rename
    fired = {"done": False}

    def racing_rename(self, target):
        # The instant agent A reaches for its meta claim, agent B adopts the
        # whole legacy queue first. A's claim then loses; it must skip the
        # pair entirely instead of moving the now-orphaned envelope.
        if not fired["done"] and self.name.endswith(META_SUFFIX):
            fired["done"] = True
            paths.adopt_legacy_pairs(legacy, dir_b, META_SUFFIX, ENVELOPE_SUFFIX)
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", racing_rename)
    claimed_a = paths.adopt_legacy_pairs(legacy, dir_a, META_SUFFIX, ENVELOPE_SUFFIX)

    assert claimed_a == 0
    # The whole pair landed in exactly one tree (agent B's), nothing split.
    assert (dir_b / f"abc{ENVELOPE_SUFFIX}").exists()
    assert (dir_b / f"abc{META_SUFFIX}").exists()
    assert not dir_a.exists() or not list(dir_a.iterdir())
    assert not list(legacy.glob("abc*"))


def test_adoption_loser_never_touches_an_orphaned_envelope(monkeypatch, tmp_path):
    """A meta already claimed by another agent means the envelope is theirs:
    the loser leaves it in place for the winner to collect."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms import paths
    from skcomms.queue import ENVELOPE_SUFFIX, META_SUFFIX

    legacy = tmp_path / "queue"
    legacy.mkdir(parents=True)
    # Envelope whose meta was already renamed away by the race winner.
    (legacy / f"abc{ENVELOPE_SUFFIX}").write_bytes(b"{}")

    claimed = paths.adopt_legacy_pairs(
        legacy, paths.queue_dir("opus"), META_SUFFIX, ENVELOPE_SUFFIX
    )
    assert claimed == 0
    assert (legacy / f"abc{ENVELOPE_SUFFIX}").exists()


def test_transfer_state_adopted_into_per_agent_dir(monkeypatch, tmp_path):
    """In-flight resumable transfer state at the legacy shared location is
    adopted by the agent-scoped default, so resume_file still finds it after
    the upgrade (no restarted transfers)."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "opus")

    from skcomms import paths
    from skcomms.transports.file import FileTransport

    legacy = paths.legacy_transfers_dir()
    legacy.mkdir(parents=True)
    (legacy / "abc123.json").write_text("{}", encoding="utf-8")

    t = FileTransport(outbox_path=tmp_path / "o", inbox_path=tmp_path / "i")
    sdir = t._default_state_dir()
    assert sdir == paths.agents_root() / "opus" / "transfers"
    assert (sdir / "abc123.json").exists()
    assert not (legacy / "abc123.json").exists()


def test_persistent_outbox_default_is_per_agent_and_adopts_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "opus")

    legacy_pending = tmp_path / "outbox" / "pending"
    legacy_pending.mkdir(parents=True)
    (legacy_pending / "entry.json").write_text("{}", encoding="utf-8")

    from skcomms import paths
    from skcomms.outbox import PersistentOutbox

    ob = PersistentOutbox()
    assert ob.root == paths.retry_outbox_dir()
    assert ob.root.is_relative_to(paths.agents_root() / "opus")
    assert (ob.pending_dir / "entry.json").exists()
    assert not (legacy_pending / "entry.json").exists()


def test_explicit_dirs_still_win(monkeypatch, tmp_path):
    """Passing an explicit directory bypasses the resolver (backward compat)."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKAGENT", "opus")

    from skcomms.outbox import PersistentOutbox
    from skcomms.queue import MessageQueue

    q = MessageQueue(queue_dir=tmp_path / "explicit-q")
    assert q.queue_dir == tmp_path / "explicit-q"
    ob = PersistentOutbox(outbox_dir=tmp_path / "explicit-ob")
    assert ob.root == tmp_path / "explicit-ob"


def test_file_transfer_state_dir_is_per_agent(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "opus")

    from skcomms import paths
    from skcomms.transports.file import FileTransport

    t = FileTransport(outbox_path=tmp_path / "o", inbox_path=tmp_path / "i")
    assert t._default_state_dir() == paths.agents_root() / "opus" / "transfers"

    # Agentless invocations keep the legacy per-user location under HOME
    # (or the custom home when one is set).
    monkeypatch.delenv("SKAGENT")
    assert t._default_state_dir() == Path(tmp_path) / "transfers"


def test_file_transport_defaults_meet_the_api_writer(monkeypatch, tmp_path):
    """An unconfigured FileTransport polls exactly where the S2S gate writes."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "lumina")

    from skcomms import paths
    from skcomms.transports.file import FileTransport

    t = FileTransport()
    assert t._inbox == paths.fed_inbox_dir("lumina")


def test_discovery_defaults_follow_agent_scoping(monkeypatch, tmp_path):
    """Peer-trace discovery scans where per-agent envelopes actually land,
    not the stale node-shared inbox/outbox."""
    import json

    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "lumina")

    from skcomms import paths
    from skcomms.discovery import discover_file_transport

    inbox = paths.file_transport_inbox()
    inbox.mkdir(parents=True)
    (inbox / "e1.skc.json").write_text(
        json.dumps({"sender": "jarvis", "recipient": "lumina"}), encoding="utf-8"
    )

    peers = discover_file_transport()
    assert [p.name for p in peers] == ["jarvis"]

    # Agentless nodes keep the legacy node-shared scan locations.
    monkeypatch.delenv("SKAGENT")
    base_inbox = tmp_path / "inbox"
    base_inbox.mkdir()
    (base_inbox / "e2.skc.json").write_text(json.dumps({"sender": "ava"}), encoding="utf-8")
    assert "ava" in [p.name for p in discover_file_transport()]


# --- SKCOMMS_OUTBOX_DIR override wins over per-agent scoping (coord 40c50478
#     reconcile) ---------------------------------------------------------------


def test_outbox_env_override_wins_over_agent_scoping(monkeypatch, tmp_path):
    """SKCOMMS_OUTBOX_DIR pins the retry store verbatim, over per-agent scoping.

    Keeps ``retry_outbox_dir``, ``outbox.default_outbox_dir`` and a
    default-constructed ``PersistentOutbox`` in agreement so the dead-letter
    tooling (coord 40c50478) and the daemon resolve the SAME root."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKAGENT", "opus")
    override = tmp_path / "pinned-outbox"
    monkeypatch.setenv("SKCOMMS_OUTBOX_DIR", str(override))

    from skcomms import paths
    from skcomms.outbox import PersistentOutbox, default_outbox_dir

    assert paths.retry_outbox_dir() == override
    assert paths.retry_outbox_dir("opus") == override  # even with an explicit agent
    assert default_outbox_dir() == override
    ob = PersistentOutbox()
    assert ob.root == override


def test_outbox_env_override_skips_home_adoption(monkeypatch, tmp_path):
    """With SKCOMMS_OUTBOX_DIR set, the in-home legacy outbox is NOT swept into
    the pinned root: an operator who relocated the queue keeps it clean."""
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKAGENT", "opus")
    override = tmp_path / "pinned-outbox"
    monkeypatch.setenv("SKCOMMS_OUTBOX_DIR", str(override))

    legacy_pending = (tmp_path / "home") / "outbox" / "pending"
    legacy_pending.mkdir(parents=True)
    (legacy_pending / "entry.json").write_text("{}", encoding="utf-8")

    from skcomms.outbox import PersistentOutbox

    ob = PersistentOutbox()
    assert ob.root == override
    # The in-home legacy entry stays put (not adopted into the pinned root).
    assert (legacy_pending / "entry.json").exists()
    assert not (override / "pending" / "entry.json").exists()


# --- Custom-home adoption boundary (coord 119b49f1 review, issue #2):
#     adoption never reaches into the fixed ~/.skcapstone path from a custom
#     SKCOMMS_HOME (that migration is manual, by design) ----------------------


def test_custom_home_does_not_adopt_fixed_legacy_transfer_state(monkeypatch, tmp_path):
    """Under a custom SKCOMMS_HOME, transfer state left at the FIXED old
    ~/.skcapstone/transfers is NOT auto-adopted (reaching into a fixed
    production path from a custom home would relocate unrelated state); only
    in-home legacy state is adopted. Documented in ``legacy_transfers_dir``."""
    user_home = tmp_path / "user-home"
    custom_home = tmp_path / "custom-home"
    monkeypatch.setenv("HOME", str(user_home))
    monkeypatch.setenv("SKCOMMS_HOME", str(custom_home))
    monkeypatch.setenv("SKAGENT", "opus")

    from skcomms import paths
    from skcomms.transports.file import FileTransport

    # State at the true FIXED pre-scoping location (regardless of SKCOMMS_HOME).
    fixed = user_home / ".skcapstone" / "transfers"
    fixed.mkdir(parents=True)
    (fixed / "fixed-state.json").write_text("{}", encoding="utf-8")

    # State at the in-home legacy location (what legacy_transfers_dir names).
    in_home = paths.legacy_transfers_dir()
    in_home.mkdir(parents=True, exist_ok=True)
    (in_home / "in-home-state.json").write_text("{}", encoding="utf-8")

    t = FileTransport(outbox_path=tmp_path / "o", inbox_path=tmp_path / "i")
    sdir = t._default_state_dir()
    assert sdir == paths.agents_root() / "opus" / "transfers"

    # In-home state adopted; fixed-location state deliberately left untouched.
    assert (sdir / "in-home-state.json").exists()
    assert (fixed / "fixed-state.json").exists()
    assert not (sdir / "fixed-state.json").exists()


def test_custom_home_does_not_adopt_fixed_legacy_outbox(monkeypatch, tmp_path):
    """Same boundary for the retry outbox: a custom SKCOMMS_HOME never reaches
    into the fixed ~/.skcapstone/skcomms/outbox. Documented in PersistentOutbox."""
    user_home = tmp_path / "user-home"
    custom_home = tmp_path / "custom-home"
    monkeypatch.setenv("HOME", str(user_home))
    monkeypatch.setenv("SKCOMMS_HOME", str(custom_home))
    monkeypatch.setenv("SKAGENT", "opus")

    from skcomms import paths
    from skcomms.outbox import PersistentOutbox

    fixed_pending = user_home / ".skcapstone" / "skcomms" / "outbox" / "pending"
    fixed_pending.mkdir(parents=True)
    (fixed_pending / "fixed.json").write_text("{}", encoding="utf-8")

    in_home_pending = custom_home / "outbox" / "pending"
    in_home_pending.mkdir(parents=True)
    (in_home_pending / "in-home.json").write_text("{}", encoding="utf-8")

    ob = PersistentOutbox()
    assert ob.root == paths.retry_outbox_dir()
    assert (ob.pending_dir / "in-home.json").exists()
    assert (fixed_pending / "fixed.json").exists()
    assert not (ob.pending_dir / "fixed.json").exists()
