from datetime import date

from ctscan.ct.log_list import (
    _builtin_fallback_logs,
    log_overlaps_interval,
    select_logs_for_interval,
)
from ctscan.models import CtLogInfo


def _log(start: str, end: str, state: str = "usable") -> CtLogInfo:
    return CtLogInfo(
        description=f"log {start}",
        url=f"https://example.com/{start}/",
        year=start[:4],
        start=start,
        end=end,
        state=state,
        operator="Test",
    )


def test_log_overlaps_interval_half_open_end():
    log = _log("2026-01-01", "2026-07-01")
    assert log_overlaps_interval(log, date(2026, 1, 1), date(2026, 6, 30))
    assert not log_overlaps_interval(log, date(2026, 7, 1), date(2026, 12, 31))


def test_select_logs_for_interval_usable_only():
    logs = [
        _log("2026-01-01", "2026-07-01", "usable"),
        _log("2026-01-01", "2026-07-01", "retired"),
        _log("2025-07-01", "2026-01-01", "usable"),
    ]
    picked = select_logs_for_interval(
        logs, date(2026, 1, 1), date(2026, 3, 1), usable_only=True
    )
    assert len(picked) == 1
    assert picked[0].start == "2026-01-01"


def test_select_logs_for_interval_builtin_fallback():
    logs = _builtin_fallback_logs()
    picked = select_logs_for_interval(
        logs, date(2026, 1, 1), date(2026, 6, 30), usable_only=True
    )
    assert any("2026" in log.start for log in picked)
    assert all(log.state == "usable" for log in picked)
