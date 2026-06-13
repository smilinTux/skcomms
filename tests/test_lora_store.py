from skcomms.transports.lora.store import AirtimeBudget, ForwardQueue


def test_budget_allows_until_exhausted():
    b = AirtimeBudget(max_bytes=100, window_s=3600)
    assert b.can_send(40, now=0) is True
    b.record(40, now=0)
    assert b.can_send(50, now=0) is True
    b.record(50, now=0)
    assert b.can_send(20, now=0) is False     # 90+20 > 100


def test_budget_refreshes_after_window():
    b = AirtimeBudget(max_bytes=100, window_s=3600)
    b.record(100, now=0)
    assert b.can_send(10, now=0) is False
    assert b.can_send(10, now=3601) is True   # window rolled over


def test_queue_drains_within_budget():
    b = AirtimeBudget(max_bytes=100, window_s=3600)
    q = ForwardQueue(budget=b)
    q.enqueue(b"a" * 60)
    q.enqueue(b"b" * 60)   # 120 total > 100 budget
    sent = q.drain(now=0)
    assert sent == [b"a" * 60]                # only the first fits this window
    assert q.pending() == 1
    sent2 = q.drain(now=3601)                 # next window
    assert sent2 == [b"b" * 60]
    assert q.pending() == 0
