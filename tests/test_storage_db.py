"""SQLite storage: jobs / purge / latest completed."""

from pathlib import Path

import pytest

from ctscan.storage.db import Database


def _make_db(tmp_path: Path) -> Database:
    return Database(tmp_path / "t.db")


def test_latest_completed_and_list_jobs(tmp_path):
    db = _make_db(tmp_path)
    try:
        j1 = db.create_job("https://log/a/", 100, 10, None, False)
        j2 = db.create_job("https://log/b/", 100, 10, "issuer_org=X", False)
        db.complete_job(j1)
        db.complete_job(j2)
        assert db.get_latest_completed_job_id() == j2
        rows = db.list_jobs(10)
        assert len(rows) == 2
        assert rows[0]["id"] == j2
        assert rows[1]["id"] == j1
        assert rows[0]["hit_count"] == 0
    finally:
        db.close()


def test_purge_job(tmp_path):
    db = _make_db(tmp_path)
    try:
        j = db.create_job("https://log/a/", 100, 5, None, False)
        db.complete_job(j)
        ok = db.add_match(j, 1, "a.example", "", "", "", "", "r")
        assert ok
        assert db.count_matches(j) == 1
        assert db.purge_job(j)
        assert db.get_job(j) is None
        assert db.count_matches() == 0
    finally:
        db.close()


def test_purge_completed_keeps_running(tmp_path):
    db = _make_db(tmp_path)
    try:
        r = db.create_job("https://log/a/", 100, 5, None, False)
        c = db.create_job("https://log/b/", 100, 5, None, False)
        db.complete_job(c)
        db.add_match(c, 1, "x.test", "", "", "", "", "r")
        n_m, n_j = db.purge_completed_jobs()
        assert n_j == 1
        assert n_m >= 1
        assert db.get_job(c) is None
        assert db.get_job(r) is not None
    finally:
        db.close()


def test_purge_all(tmp_path):
    db = _make_db(tmp_path)
    try:
        j = db.create_job("https://log/a/", 100, 5, None, False)
        db.add_match(j, 1, "x.test", "", "", "", "", "r")
        db.purge_all()
        assert db.list_jobs(10) == []
        assert db.count_matches() == 0
    finally:
        db.close()


def test_get_latest_completed_none_when_only_running(tmp_path):
    db = _make_db(tmp_path)
    try:
        db.create_job("https://log/a/", 100, 5, None, False)
        assert db.get_latest_completed_job_id() is None
    finally:
        db.close()


@pytest.mark.parametrize(
    ("export_job_id", "expect_rows"),
    [
        (None, 2),
        (1, 0),
        (2, 1),
        (3, 1),
    ],
)
def test_export_csv_scope(tmp_path, export_job_id, expect_rows):
    out = tmp_path / "out.csv"
    db = _make_db(tmp_path)
    try:
        db.create_job("https://log/a/", 100, 5, None, False)  # id 1, running — no export default
        j2 = db.create_job("https://log/b/", 100, 5, None, False)
        j3 = db.create_job("https://log/c/", 100, 5, None, False)
        db.complete_job(j2)
        db.complete_job(j3)
        db.add_match(j2, 1, "a.test", "", "", "", "", "r")
        db.add_match(j3, 2, "b.test", "", "", "", "", "r")
        n = db.export_csv(out, export_job_id)
        assert n == expect_rows
        text = out.read_text(encoding="utf-8")
        assert text.count("\n") >= expect_rows + 1  # header + lines
    finally:
        db.close()
