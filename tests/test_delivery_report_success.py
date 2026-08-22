"""DeliveryReport.success compatibility alias (chiap08 send-path stopgap).

The aggregate report's canonical field is ``delivered``; ``success`` exists
only on the per-attempt SendResult. skcapstone's MCP comm tools read
``report.success``, so the alias is pinned here against both states.
"""

from __future__ import annotations

from skcomms.transport import DeliveryReport, SendResult


def test_success_mirrors_delivered_true() -> None:
    report = DeliveryReport(
        envelope_id="env-1",
        delivered=True,
        attempts=[SendResult(success=True, transport_name="file", envelope_id="env-1")],
    )
    assert report.delivered is True
    assert report.success is True


def test_success_mirrors_delivered_false() -> None:
    report = DeliveryReport(
        envelope_id="env-2",
        delivered=False,
        attempts=[SendResult(success=False, transport_name="file", envelope_id="env-2")],
    )
    assert report.delivered is False
    assert report.success is False


def test_success_is_a_read_only_alias() -> None:
    report = DeliveryReport(envelope_id="env-3", delivered=True)
    try:
        report.success = False  # type: ignore[assignment]
    except (AttributeError, ValueError):
        pass
    assert report.success is True
