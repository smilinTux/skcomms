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


def test_drain_with_dest_preserves_per_recipient_dest():
    b = AirtimeBudget(max_bytes=1000, window_s=3600)
    q = ForwardQueue(budget=b)
    q.enqueue(b"to-x", dest="node-x")
    q.enqueue(b"to-y", dest="node-y")
    pairs = q.drain_with_dest(now=0)
    assert pairs == [(b"to-x", "node-x"), (b"to-y", "node-y")]
    assert q.pending() == 0


def test_tumbling_window_resets_used_exactly_at_boundary():
    # Window is tumbling (not sliding): used resets only once now advances past
    # window_s from the window start, not on every call.
    b = AirtimeBudget(max_bytes=100, window_s=10)
    b.record(100, now=0.0)
    assert b.can_send(1, now=5.0) is False    # mid-window: still exhausted
    assert b.can_send(1, now=9.999) is False  # just before boundary
    assert b.can_send(1, now=10.0) is True    # boundary reached -> fresh window


def test_can_send_does_not_consume_budget():
    b = AirtimeBudget(max_bytes=100, window_s=3600)
    assert b.can_send(80, now=0) is True
    assert b.can_send(80, now=0) is True  # querying twice doesn't consume
    b.record(80, now=0)
    assert b.can_send(80, now=0) is False  # now it's actually consumed


def test_oversized_head_frame_is_dropped_no_wedge():
    # A frame larger than max_bytes can NEVER fit; it must be dropped so the
    # queue makes progress instead of starving everything behind it forever.
    b = AirtimeBudget(max_bytes=100, window_s=3600)
    q = ForwardQueue(budget=b)
    q.enqueue(b"x" * 250)   # oversized head — impossible to ever send
    q.enqueue(b"y" * 50)    # small trailing frame
    sent = q.drain(now=0)
    assert sent == [b"y" * 50]   # oversized dropped, trailing frame sent
    assert q.pending() == 0
