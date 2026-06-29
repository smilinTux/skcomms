"""`skcomms consent` CLI — operator request management (gate-5 surface)."""
import pytest
from click.testing import CliRunner

from skcomms.cli import main
from skcomms.consent import ContactStore, RequestQueue


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKAGENT", "lumina")


def _run(*args):
    return CliRunner().invoke(main, ["consent", *args])


def test_requests_empty():
    r = _run("requests")
    assert r.exit_code == 0 and "No pending requests" in r.output


def test_request_then_accept_mints_token_and_promotes():
    RequestQueue(agent="lumina").enqueue("stranger@x.y", b"hi", envelope_id="e1")
    assert "stranger@x.y" in _run("requests").output

    a = _run("accept", "stranger@x.y")
    assert a.exit_code == 0 and "Delivery token:" in a.output
    assert ContactStore("lumina").is_known("stranger@x.y")
    # accepting cleared the queue and the contact now shows as known
    assert "No pending requests" in _run("requests").output
    assert "stranger@x.y" in _run("known").output


def test_decline_with_block():
    RequestQueue(agent="lumina").enqueue("spam@x.y", b"buy", envelope_id="e2")
    r = _run("decline", "spam@x.y", "--block")
    assert r.exit_code == 0 and "blocked" in r.output
    assert ContactStore("lumina").is_blocked("spam@x.y")
    assert "No pending requests" in _run("requests").output


def test_block_then_unblock():
    assert "Blocked" in _run("block", "x@y.z").output
    assert ContactStore("lumina").is_blocked("x@y.z")
    assert "Unblocked" in _run("unblock", "x@y.z").output
    assert not ContactStore("lumina").is_blocked("x@y.z")
