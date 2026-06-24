"""skcomms PQC cut-over: provider-driven hybrid negotiation (Entry #6).

Verifies that EnvelopeCrypto, given a hybrid_provider, negotiates hybrid
X25519+ML-KEM-768 by default for a recipient that advertises a prekey, opens it
back, and falls back to classical (unchanged) when there is no prekey.
"""

from __future__ import annotations

import pytest

from skcomms.models import MessageEnvelope, MessagePayload
from skcomms import pqkem

pytestmark = pytest.mark.skipif(not pqkem.is_available(), reason="liboqs unavailable")


class _Provider:
    """In-memory hybrid provider: our keypair + a peer's published bundle."""

    def __init__(self):
        kp = pqkem.hybrid_keypair()
        self._pub = kp.public_key
        self._priv = kp.private_key
        self._peers = {}

    def add_peer(self, short, pub):
        self._peers[short] = {"suite": "x25519-mlkem768", "hybrid_public_hex": pub.hex()}

    def short(self, identity):
        s = identity[len("capauth:"):] if identity.startswith("capauth:") else identity
        return s.split("@")[0]

    def own_short(self):
        return "me"

    def own_private(self):
        return self._priv

    def own_public(self):
        return self._pub

    def resolve_bundle(self, identity):
        return self._peers.get(self.short(identity))


def _envelope(sender, recipient, body="secret payload"):
    return MessageEnvelope(
        sender=sender,
        recipient=recipient,
        payload=MessagePayload(content=body),
    )


def _crypto(provider):
    from skcomms.crypto import EnvelopeCrypto

    # No real PGP key needed for the hybrid path; pass empty armor.
    return EnvelopeCrypto(private_key_armor="", passphrase="", hybrid_provider=provider)


def test_provider_negotiates_hybrid_when_peer_has_prekey():
    prov = _Provider()
    # The recipient's keypair is what we seal to; reuse our provider's own key as
    # the "peer" so we can also decrypt (symmetric setup for a round-trip test).
    prov.add_peer("bob", prov.own_public())
    c = _crypto(prov)

    env = _envelope("capauth:me@skworld.io", "capauth:bob@skworld.io")
    sealed, suite = c.encrypt_payload_provider(env, recipient_public_armor="")
    assert suite == "x25519-mlkem768"
    assert c.is_hybrid_payload(sealed)
    assert sealed.payload.content.startswith("pqdm1:")

    # Round-trip: open it back with our private key (bob == us here).
    opened = c.decrypt_payload(sealed)
    assert opened.payload.content == "secret payload"
    assert opened.payload.encrypted is False


def test_provider_falls_back_classical_without_prekey():
    prov = _Provider()  # no peers registered
    c = _crypto(prov)
    env = _envelope("capauth:me@skworld.io", "capauth:bob@skworld.io")
    sealed, suite = c.encrypt_payload_provider(env, recipient_public_armor="")
    # No prekey → classical negotiated suite, payload not hybrid-sealed.
    assert suite == "x25519-pgp-wrap-v1"
    assert not c.is_hybrid_payload(sealed)


def test_no_provider_is_classical_unchanged():
    from skcomms.crypto import EnvelopeCrypto

    c = EnvelopeCrypto(private_key_armor="", passphrase="", hybrid_provider=None)
    env = _envelope("capauth:me@skworld.io", "capauth:bob@skworld.io")
    sealed, suite = c.encrypt_payload_provider(env, recipient_public_armor="")
    assert suite == "x25519-pgp-wrap-v1"
    assert not c.is_hybrid_payload(sealed)
