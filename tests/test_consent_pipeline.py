"""ConsentPipeline composition — the full gate stack in order."""
import pytest

from skcomms.consent import ContactStore
from skcomms.consent_greylist import Greylist
from skcomms.consent_pipeline import ConsentPipeline

S = "stranger@x.y"
O = "opus@chef.skworld"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))


def test_blocked_drops():
    ContactStore("lumina").block(S)
    assert ConsentPipeline("lumina").decide(S).decision == "drop"


def test_known_delivers():
    ContactStore("lumina").accept(O)
    assert ConsentPipeline("lumina").decide(O).decision == "deliver"


def test_tailnet_delivers_unknown():
    assert ConsentPipeline("lumina", mode="tailnet").decide(S).decision == "deliver"


def test_unknown_anonymous_is_greylisted_first():
    out = ConsentPipeline("lumina").decide(S)
    assert out.decision == "defer" and out.reason == "greylist"


def test_unknown_quarantines_after_greylist_admit():
    g = Greylist("lumina")
    g.see(S, now=0)          # first sighting → records first_seen
    g.see(S, now=10_000)     # past the window → admit (sticky)
    out = ConsentPipeline("lumina").decide(S)
    assert out.decision == "quarantine" and out.reason == "knock"


def test_on_accept_issues_token_and_known_delivers():
    p = ConsentPipeline("lumina")
    tok = p.on_accept(O)
    assert tok and ContactStore("lumina").is_known(O)
    assert p.decide(O).decision == "deliver"
    # a forged token from a known contact is rejected (gate-4)
    assert p.decide(O, token="deadbeef").decision == "drop"


def test_node_policy_can_disable_greylist():
    # Operator policy overrides the per-tier friction → unknown goes straight to knock.
    from skcomms.consent_tiering import FrictionPolicy, SenderTier
    overrides = {
        SenderTier.ANONYMOUS: FrictionPolicy(
            greylist=False, rate_per_day=3, require_token=True
        )
    }
    out = ConsentPipeline("lumina", node_policy=overrides).decide(S)
    assert out.decision == "quarantine"
