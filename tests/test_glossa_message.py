from skcomms.glossa.message import Message


def test_message_fields_and_defaults():
    m = Message(intent="coord.claim")
    assert m.intent == "coord.claim"
    assert m.args == {}
    assert m.refs == []
    assert m.text == ""


def test_message_equality_and_dict_roundtrip():
    m = Message(intent="status.report", args={"oof": 42}, refs=["task-1"], text="hi")
    assert Message.from_dict(m.to_dict()) == m
    assert m.to_dict() == {"i": "status.report", "a": {"oof": 42},
                           "r": ["task-1"], "t": "hi"}
