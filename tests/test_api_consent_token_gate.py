"""Gate-4 closes the loop: the recipient inbox gate reads the envelope ``consent_token``.

The sender lifts its held per-contact token onto the OUTER envelope
(:attr:`skcomms.envelope.Envelope.consent_token`); these tests pin that the
recipient's ``api._consent_classify`` extracts it and fast-paths gate-4:

* a KNOWN contact presenting a VALID token → ``deliver``,
* the existing KNOWN-WITHOUT-token path still → ``deliver`` (no regression),
* a KNOWN contact presenting a FORGED token → ``drop`` (bad-token),
* ``_write_to_recipient_inbox`` plumbs ``env.consent_token`` into the gate.

Opt-in: everything below runs with ``SKCOMMS_CONSENT_MODE=public`` set; with the
gate OFF the path is byte-for-byte the legacy deliver-everything behaviour.
"""

from __future__ import annotations

import importlib

import pytest


SELF_AGENT = "lumina"
SENDER = "jarvis@chef.skworld"


@pytest.fixture
def api_mod(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    monkeypatch.setenv("SKCOMMS_CONSENT_MODE", "public")

    import skcomms.api as api

    importlib.reload(api)
    monkeypatch.setattr(api, "_self_agent", lambda: SELF_AGENT)
    return api


def _accept_and_get_token() -> str:
    """Promote SENDER to a known contact of SELF_AGENT and mint its gate-4 token."""
    from skcomms.consent_pipeline import ConsentPipeline

    return ConsentPipeline(SELF_AGENT).on_accept(SENDER)


def test_known_with_valid_token_delivers(api_mod):
    token = _accept_and_get_token()
    assert api_mod._consent_classify(SELF_AGENT, SENDER, token=token) == "deliver"


def test_known_without_token_still_delivers(api_mod):
    _accept_and_get_token()
    # No token presented at all — the known-contact path must still deliver.
    assert api_mod._consent_classify(SELF_AGENT, SENDER, token=None) == "deliver"
    # And the positional/legacy 2-arg call shape must keep working.
    assert api_mod._consent_classify(SELF_AGENT, SENDER) == "deliver"


def test_known_with_forged_token_is_dropped(api_mod):
    _accept_and_get_token()
    forged = "f" * 64
    assert api_mod._consent_classify(SELF_AGENT, SENDER, token=forged) == "drop"


def test_write_to_inbox_lifts_envelope_consent_token(api_mod, monkeypatch):
    """``_write_to_recipient_inbox`` must pass ``env.consent_token`` into the gate."""
    token = _accept_and_get_token()

    seen = {}

    def _spy(recipient, sender, token=None):
        seen["recipient"] = recipient
        seen["sender"] = sender
        seen["token"] = token
        return "drop"  # short-circuit before any real write

    monkeypatch.setattr(api_mod, "_consent_classify", _spy)

    class _Env:
        id = "env-xyz"
        to_fqid = f"{SELF_AGENT}@chef.skworld"
        from_fqid = SENDER
        body = "hi"
        consent_token = token

    out = api_mod._write_to_recipient_inbox(_Env())
    assert out == ""  # dropped
    assert seen["token"] == token
    assert seen["recipient"] == SELF_AGENT
    assert seen["sender"] == SENDER
