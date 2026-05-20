"""SQLite persistence: scan jobs, matches, deduplicated domains."""

from __future__ import annotations

import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def default_data_dir() -> Path:
    return Path.home() / ".ctscan"


class Database:
    def __init__(self, path: Path | None = None):
        self.path = path or (default_data_dir() / "ctscan.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_uri TEXT NOT NULL,
                tree_size_at_start INTEGER NOT NULL,
                next_end_index INTEGER NOT NULL,
                target_count INTEGER NOT NULL,
                matched_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running',
                query TEXT,
                nxdomain_mode INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                log_index INTEGER NOT NULL,
                domain TEXT NOT NULL,
                issuer_cn TEXT,
                issuer_org TEXT,
                not_before TEXT,
                not_after TEXT,
                rule_name TEXT,
                matched_at TEXT NOT NULL,
                UNIQUE(job_id, domain),
                FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
            );

            CREATE INDEX IF NOT EXISTS idx_matches_job ON matches(job_id);
            """
        )
        self._conn.commit()

    def create_job(
        self,
        log_uri: str,
        tree_size: int,
        target_count: int,
        query: str | None,
        nxdomain_mode: bool,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            """
            INSERT INTO scan_jobs
            (log_uri, tree_size_at_start, next_end_index, target_count,
             matched_count, status, query, nxdomain_mode, created_at, updated_at)
            VALUES (?, ?, ?, ?, 0, 'running', ?, ?, ?, ?)
            """,
            (
                log_uri,
                tree_size,
                tree_size - 1,
                target_count,
                query,
                1 if nxdomain_mode else 0,
                now,
                now,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def get_active_job(self) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM scan_jobs WHERE status = 'running' ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def get_job(self, job_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM scan_jobs WHERE id = ?", (job_id,)
        ).fetchone()

    def update_checkpoint(self, job_id: int, next_end_index: int, matched_count: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            UPDATE scan_jobs
            SET next_end_index = ?, matched_count = ?, updated_at = ?
            WHERE id = ?
            """,
            (next_end_index, matched_count, now, job_id),
        )
        self._conn.commit()

    def complete_job(self, job_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE scan_jobs SET status = 'completed', updated_at = ? WHERE id = ?",
            (now, job_id),
        )
        self._conn.commit()

    def list_match_log_indices(self, job_id: int) -> list[int]:
        rows = self._conn.execute(
            """
            SELECT DISTINCT log_index FROM matches
            WHERE job_id = ?
            ORDER BY log_index
            """,
            (job_id,),
        ).fetchall()
        return [int(r["log_index"]) for r in rows]

    def known_domains(self, job_id: int) -> set[str]:
        rows = self._conn.execute(
            "SELECT domain FROM matches WHERE job_id = ?", (job_id,)
        ).fetchall()
        return {r["domain"] for r in rows}

    def add_match(
        self,
        job_id: int,
        log_index: int,
        domain: str,
        issuer_cn: str,
        issuer_org: str,
        not_before: str,
        not_after: str,
        rule_name: str,
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        try:
            self._conn.execute(
                """
                INSERT INTO matches
                (job_id, log_index, domain, issuer_cn, issuer_org,
                 not_before, not_after, rule_name, matched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    log_index,
                    domain,
                    issuer_cn,
                    issuer_org,
                    not_before,
                    not_after,
                    rule_name,
                    now,
                ),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def count_matches(self, job_id: int | None = None) -> int:
        if job_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM matches").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM matches WHERE job_id = ?", (job_id,)
            ).fetchone()
        return int(row["c"])

    def get_latest_completed_job_id(self) -> int | None:
        row = self._conn.execute(
            """
            SELECT id FROM scan_jobs
            WHERE status = 'completed'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        return int(row["id"]) if row else None

    def list_jobs(self, limit: int = 100) -> list[sqlite3.Row]:
        return self._conn.execute(
            """
            SELECT j.*,
                   (SELECT COUNT(*) FROM matches m WHERE m.job_id = j.id) AS hit_count
            FROM scan_jobs j
            ORDER BY j.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def purge_job(self, job_id: int) -> bool:
        """Delete a job and its matches. Returns whether the job row was removed."""
        self._conn.execute("DELETE FROM matches WHERE job_id = ?", (job_id,))
        cur = self._conn.execute("DELETE FROM scan_jobs WHERE id = ?", (job_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def purge_all(self) -> None:
        self._conn.execute("DELETE FROM matches")
        self._conn.execute("DELETE FROM scan_jobs")
        self._conn.commit()

    def purge_completed_jobs(self) -> tuple[int, int]:
        """Delete all completed jobs and matches. Returns (matches_deleted, jobs_deleted)."""
        cur_m = self._conn.execute(
            """
            DELETE FROM matches WHERE job_id IN (
                SELECT id FROM scan_jobs WHERE status = 'completed'
            )
            """
        )
        cur_j = self._conn.execute(
            "DELETE FROM scan_jobs WHERE status = 'completed'"
        )
        self._conn.commit()
        return (cur_m.rowcount, cur_j.rowcount)

    def export_csv(self, output: Path, job_id: int | None = None) -> int:
        if job_id is None:
            rows = self._conn.execute(
                """
                SELECT m.*, j.log_uri FROM matches m
                JOIN scan_jobs j ON j.id = m.job_id
                ORDER BY m.id
                """
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM matches WHERE job_id = ? ORDER BY id",
                (job_id,),
            ).fetchall()

        fieldnames = [
            "index",
            "job_id",
            "log_index",
            "domain",
            "issuer_cn",
            "issuer_org",
            "not_before",
            "not_after",
            "matched_rule",
        ]
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for i, row in enumerate(rows, 1):
                writer.writerow(
                    {
                        "index": i,
                        "job_id": row["job_id"],
                        "log_index": row["log_index"],
                        "domain": row["domain"],
                        "issuer_cn": row["issuer_cn"],
                        "issuer_org": row["issuer_org"],
                        "not_before": row["not_before"],
                        "not_after": row["not_after"],
                        "matched_rule": row["rule_name"],
                    }
                )
        return len(rows)
