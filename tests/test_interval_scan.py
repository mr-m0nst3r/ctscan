from ctscan.pipeline.interval_scan import (
    ScanLogTarget,
    group_targets_by_operator,
    resolve_operator_concurrency,
)
from ctscan.storage.db import Database


def test_group_targets_by_operator():
    targets = [
        ScanLogTarget("https://a/", "A1", "Google"),
        ScanLogTarget("https://b/", "A2", "Google"),
        ScanLogTarget("https://c/", "C1", "Cloudflare"),
    ]
    grouped = group_targets_by_operator(targets)
    assert len(grouped["Google"]) == 2
    assert len(grouped["Cloudflare"]) == 1


def test_resolve_operator_concurrency_defaults_to_operator_count():
    assert resolve_operator_concurrency(5, None) == 5
    assert resolve_operator_concurrency(5, 0) == 5


def test_resolve_operator_concurrency_caps_workers():
    assert resolve_operator_concurrency(9, 2) == 2
    assert resolve_operator_concurrency(1, 4) == 1


def test_scan_session_dedup_and_resume(tmp_path):
    db = Database(tmp_path / "test.db")
    try:
        session_id = db.create_session(
            "2026-01-01", "2026-06-30", 10, "issuer_cn = 'X'", False
        )
        job1 = db.create_job(
            "https://log/a/",
            100,
            10,
            "issuer_cn = 'X'",
            False,
            session_id=session_id,
        )
        job2 = db.create_job(
            "https://log/b/",
            100,
            10,
            "issuer_cn = 'X'",
            False,
            session_id=session_id,
        )
        assert db.add_match(
            job1, 1, "example.com", "CN", "ORG", "2026-01-01", "2027-01-01", "q"
        )
        assert db.add_match(
            job2, 2, "example.com", "CN", "ORG", "2026-01-01", "2027-01-01", "q"
        )
        assert db.add_match(
            job2, 3, "other.com", "CN", "ORG", "2026-01-01", "2027-01-01", "q"
        )
        assert db.count_unique_domains_for_session(session_id) == 2
        assert db.known_domains_for_session(session_id) == {
            "example.com",
            "other.com",
        }

        row = db.find_running_session(
            "2026-01-01", "2026-06-30", "issuer_cn = 'X'", False
        )
        assert row is not None
        assert int(row["id"]) == session_id

        db.complete_job(job1)
        assert db.get_completed_job_for_log_in_session("https://log/a/", session_id)
        assert db.get_running_job_for_log("https://log/b/", session_id) is not None
    finally:
        db.close()
