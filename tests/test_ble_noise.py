from skcomms.transports.ble.identity import MeshIdentity
from skcomms.transports.ble.noise import NoiseSession


def _drive_handshake(initiator: NoiseSession, responder: NoiseSession):
    """XX is a 3-message handshake: i->r, r->i, i->r."""
    m1 = initiator.write_handshake()       # -> e
    responder.read_handshake(m1)
    m2 = responder.write_handshake()       # -> e, ee, s, es
    initiator.read_handshake(m2)
    m3 = initiator.write_handshake()       # -> s, se
    responder.read_handshake(m3)
    assert initiator.handshake_complete
    assert responder.handshake_complete


def test_xx_handshake_then_encrypted_roundtrip():
    a_id = MeshIdentity.generate("a@x.y")
    b_id = MeshIdentity.generate("b@x.y")
    a = NoiseSession.initiator(a_id.noise_static_private_bytes())
    b = NoiseSession.responder(b_id.noise_static_private_bytes())

    _drive_handshake(a, b)

    ct = a.encrypt(b"secret over ble")
    assert ct != b"secret over ble"
    assert b.decrypt(ct) == b"secret over ble"

    # reverse direction
    ct2 = b.encrypt(b"reply")
    assert a.decrypt(ct2) == b"reply"


def test_peer_static_key_is_learned_after_handshake():
    a_id = MeshIdentity.generate("a@x.y")
    b_id = MeshIdentity.generate("b@x.y")
    a = NoiseSession.initiator(a_id.noise_static_private_bytes())
    b = NoiseSession.responder(b_id.noise_static_private_bytes())
    _drive_handshake(a, b)
    # initiator learns responder's static pubkey (XX authenticates both)
    assert a.peer_static_pub == b_id.noise_static_pub
    assert b.peer_static_pub == a_id.noise_static_pub
