"""Per-contact capability tokens (skfed-consent-design gate 4, problem (A)).

The directory entry is only ever a *knock* endpoint; the token is the *delivery*
credential — issued one-per-accepted-contact, derived as
``HKDF-SHA256(per-agent secret seed, contact_fqid)`` and independently revocable.
Blocking ONE contact drops THAT one token from the valid set without re-sharing a
single profile-key with everyone (the explicit fix vs Signal's single token).
"""
import pytest

from skcomms.consent_tokens import TokenStore

L = "lumina@chef.skworld"
O = "opus@chef.skworld"
J = "jarvis@chef.skworld"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    return tmp_path


def test_issue_verify_roundtrip(home):
    ts = TokenStore(agent="lumina")
    tok = ts.issue(O)
    assert isinstance(tok, str) and tok  # hex string
    # hex-decodable
    bytes.fromhex(tok)
    assert ts.verify(O, tok) is True


def test_wrong_token_rejected(home):
    ts = TokenStore(agent="lumina")
    tok = ts.issue(O)
    assert ts.verify(O, "deadbeef") is False
    # right contact, a token that was never issued for it
    assert ts.verify(O, tok[:-1] + ("0" if tok[-1] != "0" else "1")) is False


def test_token_for_unissued_contact_rejected(home):
    ts = TokenStore(agent="lumina")
    ts.issue(O)
    # J never got a token — even O's token must not authenticate J.
    assert ts.verify(J, ts.issue(O)) is False


def test_per_contact_distinct_tokens(home):
    ts = TokenStore(agent="lumina")
    t_o = ts.issue(O)
    t_j = ts.issue(J)
    assert t_o != t_j
    # a token issued for one contact never verifies for another (the Signal fix)
    assert ts.verify(O, t_j) is False
    assert ts.verify(J, t_o) is False


def test_revoke_then_verify_fails(home):
    ts = TokenStore(agent="lumina")
    tok = ts.issue(O)
    assert ts.verify(O, tok) is True
    ts.revoke(O)
    assert ts.verify(O, tok) is False


def test_revoke_one_leaves_others_valid(home):
    ts = TokenStore(agent="lumina")
    t_o = ts.issue(O)
    t_j = ts.issue(J)
    ts.revoke(O)
    # blocking ONE contact never affects the others
    assert ts.verify(O, t_o) is False
    assert ts.verify(J, t_j) is True


def test_persistence_across_store_instances(home):
    ts = TokenStore(agent="lumina")
    tok = ts.issue(O)
    # a fresh store over the same home re-derives the same seed → same token verifies
    ts2 = TokenStore(agent="lumina")
    assert ts2.verify(O, tok) is True
    assert ts2.issue(O) == tok  # deterministic re-issue (same seed + contact)


def test_per_agent_isolation(home):
    ts_l = TokenStore(agent="lumina")
    ts_o = TokenStore(agent="opus")
    tok_l = ts_l.issue(O)
    # opus has its OWN seed → lumina's token for a contact is meaningless to opus,
    # and opus's token for the same contact differs.
    assert ts_o.verify(O, tok_l) is False
    tok_o = ts_o.issue(O)
    assert tok_o != tok_l


def test_seed_persisted_once_and_reused(home):
    ts = TokenStore(agent="lumina")
    seed_path = home / "consent" / "lumina" / "token_seed.bin"
    assert seed_path.exists()
    seed1 = seed_path.read_bytes()
    # re-opening the store must NOT rotate the seed (tokens would all break)
    TokenStore(agent="lumina")
    assert seed_path.read_bytes() == seed1
    assert len(seed1) >= 32  # >= 256-bit secret
