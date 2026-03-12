from __future__ import annotations

"""SQLite-backed operational memory for Freddy."""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from config import MEMORY_DB_PATH


@dataclass(slots=True)
class ScanRecord:
    id: int
    target: str
    command: str
    timestamp: str
    findings_summary: str
    severity: str
    remediation_summary: str


class MemoryEngine:
    """Stores and retrieves Freddy scan history."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or MEMORY_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    command TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    findings_summary TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    remediation_summary TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def save_scan_record(
        self,
        target: str,
        command: str,
        findings_summary: str,
        severity: str,
        remediation_summary: str,
    ) -> int:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_history (
                    target,
                    command,
                    timestamp,
                    findings_summary,
                    severity,
                    remediation_summary
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (target or "local", command, timestamp, findings_summary, severity, remediation_summary),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def get_recent_scan_history(self, limit: int = 20, target: str | None = None) -> list[ScanRecord]:
        query = """
            SELECT id, target, command, timestamp, findings_summary, severity, remediation_summary
            FROM scan_history
        """
        params: tuple[object, ...] = ()
        if target:
            query += " WHERE target = ?"
            params = (target,)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params = (*params, limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def search_prior_findings(self, target: str) -> list[ScanRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, target, command, timestamp, findings_summary, severity, remediation_summary
                FROM scan_history
                WHERE target LIKE ?
                ORDER BY timestamp DESC
                """,
                (f"%{target}%",),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            id=int(row["id"]),
            target=str(row["target"]),
            command=str(row["command"]),
            timestamp=str(row["timestamp"]),
            findings_summary=str(row["findings_summary"]),
            severity=str(row["severity"]),
            remediation_summary=str(row["remediation_summary"]),
        )
