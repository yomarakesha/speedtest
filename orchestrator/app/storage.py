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
                """
                INSERT INTO jobs (job_id, kind, result_json) VALUES (?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    kind = excluded.kind,
                    result_json = excluded.result_json
                """,
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

    def list_jobs(self, limit: int = 50) -> list[dict]:
        """Newest-first job summaries for a monitoring view — light enough to
        list regularly, unlike get_job's full per-host result payload."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT job_id, kind, result_json, created_at FROM jobs "
                "ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for job_id, kind, result_json, created_at in rows:
            result = json.loads(result_json)
            out.append(
                {
                    "job_id": job_id,
                    "kind": kind,
                    "created_at": created_at,
                    "status": result.get("status"),
                    "cidr": result.get("cidr"),
                    "host_count": len(result.get("hosts", [])),
                }
            )
        return out
