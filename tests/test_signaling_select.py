"""Dual-path signaling selection (sub-project B — 'if you need one, get two').

The sovereign mailbox backend is always available; the broker is an optional
low-latency fast path. select_signaling() picks the broker when it's reachable,
else falls back to the mailbox — no single point of failure.
"""
from skcomms.transports.signaling_base import SignalingChannel, select_signaling
from skcomms.transports.signaling_mailbox import MailboxSignaling


class _FakeBroker:
    def __init__(self, reachable: bool) -> None:
        self._reachable = reachable

    def is_reachable(self) -> bool:
        return self._reachable

    def send_signal(self, to_fqid, kind, payload):  # conform to the protocol
        return {"id": "b"}

    def poll_signals(self):
        return []


def test_mailbox_conforms_to_protocol():
    assert isinstance(MailboxSignaling(agent="opus"), SignalingChannel)


def test_selects_broker_when_reachable():
    mailbox = MailboxSignaling(agent="opus")
    broker = _FakeBroker(reachable=True)
    assert select_signaling(mailbox, broker) is broker


def test_falls_back_to_mailbox_when_broker_unreachable():
    mailbox = MailboxSignaling(agent="opus")
    broker = _FakeBroker(reachable=False)
    assert select_signaling(mailbox, broker) is mailbox


def test_mailbox_only_when_no_broker():
    mailbox = MailboxSignaling(agent="opus")
    assert select_signaling(mailbox, None) is mailbox


def test_prefer_broker_false_keeps_mailbox():
    mailbox = MailboxSignaling(agent="opus")
    broker = _FakeBroker(reachable=True)
    assert select_signaling(mailbox, broker, prefer_broker=False) is mailbox
