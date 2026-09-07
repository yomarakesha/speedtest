"""SQLite-backed job result storage. No ORM — stdlib sqlite3 is enough for
one table with a JSON blob column."""
import json
import sqlite3
from contextlib import closing


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    def save_job(self, job_id: str, kind: str, result: dict) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO jobs (job_id, kind, result_json) VALUES (?, ?, ?)",
                (job_id, kind, json.dumps(result)),
            )
            conn.commit()

    def get_job(self, job_id: str) -> dict | None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT kind, result_json FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        if row is None:
            return None
        kind, result_json = row
        return {"kind": kind, "result": json.loads(result_json)}
