"""Security — peer_inbox() must not let a peer-controlled FQID escape the tree.

The bug: peer_inbox() validated only that to_fqid contained "@" and ".", then
built ``home/<realm>/<operator>/<agent>/inbox`` directly. A crafted FQID like
``x@../../../../tmp/evil.z`` (has both "@" and ".") resolved OUTSIDE the home
tree, and mailbox.send_message would mkdir + write attacker-controlled .json
there — arbitrary-location file write from a remote sender's to_fqid.
"""

from __future__ import annotations

import pytest

from skcomms import home


def _under_home(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    return tmp_path


def test_legit_fqid_resolves_under_home(monkeypatch, tmp_path):
    _under_home(monkeypatch, tmp_path)
    p = home.peer_inbox("lumina@chef.skworld")
    assert p == (tmp_path / "skworld" / "chef" / "lumina" / "inbox").resolve()
    assert tmp_path.resolve() in p.parents


@pytest.mark.parametrize(
    "evil",
    [
        "x@../../../../tmp/evil.z",
        "..@op.realm",
        "agent@...realm",  # operator becomes empty / dotted
        "a@b/c.realm",
    ],
)
def test_traversal_and_bad_components_rejected(monkeypatch, tmp_path, evil):
    _under_home(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        home.peer_inbox(evil)
