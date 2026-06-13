from skcomms.transports.lora.addressing import SK_CHANNEL, NodeMap


def test_map_and_lookup_roundtrip(tmp_path):
    m = NodeMap(path=tmp_path / "nodes.json")
    m.bind("lumina@chef.skworld", "!abcd1234")
    assert m.node_for("lumina@chef.skworld") == "!abcd1234"
    assert m.fqid_for("!abcd1234") == "lumina@chef.skworld"


def test_unknown_returns_none(tmp_path):
    m = NodeMap(path=tmp_path / "nodes.json")
    assert m.node_for("ghost@nowhere") is None
    assert m.fqid_for("!nope") is None


def test_persists(tmp_path):
    p = tmp_path / "nodes.json"
    NodeMap(path=p).bind("a@b.c", "!n1")
    assert NodeMap(path=p).node_for("a@b.c") == "!n1"


def test_channel_default():
    assert SK_CHANNEL == "skworld"
