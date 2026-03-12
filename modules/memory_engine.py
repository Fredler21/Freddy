from __future__ import annotations

"""SQLite-backed operational memory for Freddy with structured scan storage."""

import json
import re
from collections import Counter
from dataclasses import dataclass, field
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
    raw_output_path: str = ""
    findings: list = field(default_factory=list)


@dataclass(slots=True)
class MemoryStats:
    total_scans: int
    unique_targets: int
    top_vulnerabilities: list
    recent_targets: list


class MemoryEngine:
    """Stores and retrieves Freddy scan history with deduplication and correlation."""

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
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    command TEXT NOT NULL,
                    raw_output_path TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    findings TEXT NOT NULL DEFAULT '[]',
                    remediation TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL UNIQUE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            # Migrate from old scan_history table when present
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "scan_history" in tables:
                existing = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                if existing == 0:
                    connection.execute(
                        """
                        INSERT INTO scans
                            (target, timestamp, command, summary, severity, findings, remediation, raw_output_path)
                        SELECT target, timestamp, command, findings_summary, severity, '[]', remediation_summary, ''
                        FROM scan_history
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
        raw_output_path: str = "",
        findings: list[str] | None = None,
    ) -> int:
        """Persist a scan record with deduplication.

        If the most recent record for the same target already carries identical
        structured findings the method updates only the timestamp and returns
        the existing record id instead of inserting a duplicate row.
        """
        findings = findings or []
        findings_json = json.dumps(findings)
        target = target or "local"
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            last_row = connection.execute(
                """
                SELECT id, findings FROM scans
                WHERE target = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (target,),
            ).fetchone()

            if last_row and last_row["findings"] == findings_json and findings_json != "[]":
                connection.execute(
                    "UPDATE scans SET timestamp = ? WHERE id = ?",
                    (timestamp, last_row["id"]),
                )
                record_id = int(last_row["id"])
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO scans
                        (target, timestamp, command, raw_output_path, summary, severity, findings, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        target,
                        timestamp,
                        command,
                        raw_output_path,
                        findings_summary,
                        severity,
                        findings_json,
                        remediation_summary,
                    ),
                )
                record_id = int(cursor.lastrowid)

            existing_target = connection.execute(
                "SELECT id FROM targets WHERE hostname = ?",
                (target,),
            ).fetchone()
            if existing_target:
                connection.execute(
                    "UPDATE targets SET last_seen = ?, scan_count = scan_count + 1 WHERE hostname = ?",
                    (timestamp, target),
                )
            else:
                connection.execute(
                    "INSERT INTO targets (hostname, first_seen, last_seen, scan_count) VALUES (?, ?, ?, 1)",
                    (target, timestamp, timestamp),
                )

            connection.commit()

        return record_id

    def get_recent_scan_history(self, limit: int = 20, target: str | None = None) -> list[ScanRecord]:
        query = """
            SELECT id, target, command, timestamp, summary, severity, remediation, raw_output_path, findings
            FROM scans
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
                SELECT id, target, command, timestamp, summary, severity, remediation, raw_output_path, findings
                FROM scans
                WHERE target LIKE ?
                ORDER BY timestamp DESC
                """,
                (f"%{target}%",),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_memory_stats(self) -> MemoryStats:
        """Return aggregate statistics across all stored scan records."""
        with self._connect() as connection:
            total_scans = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            unique_targets = connection.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
            recent_target_rows = connection.execute(
                "SELECT hostname FROM targets ORDER BY last_seen DESC LIMIT 10"
            ).fetchall()
            all_findings_rows = connection.execute("SELECT findings FROM scans").fetchall()

        term_counter: Counter[str] = Counter()
        for row in all_findings_rows:
            try:
                parsed = json.loads(row[0])
                for finding in parsed:
                    normalized = re.sub(r"^[-*•·\d.):]+\s*", "", str(finding)).strip().lower()
                    if normalized:
                        term_counter[normalized] += 1
            except (json.JSONDecodeError, TypeError):
                pass

        return MemoryStats(
            total_scans=int(total_scans),
            unique_targets=int(unique_targets),
            top_vulnerabilities=term_counter.most_common(10),
            recent_targets=[row["hostname"] for row in recent_target_rows],
        )

    def get_correlation_summary(self, target: str) -> str:
        """Build a short pattern summary for a target across all historical scans."""
        records = self.search_prior_findings(target)
        if not records:
            return ""

        term_counter: Counter[str] = Counter()
        for record in records:
            for finding in record.findings:
                normalized = re.sub(r"^[-*•·\d.):]+\s*", "", str(finding)).strip().lower()
                if normalized:
                    term_counter[normalized] += 1

        scan_count = len(records)
        first_seen = records[-1].timestamp[:10]
        last_seen = records[0].timestamp[:10]

        lines: list[str] = [
            f"Target '{target}' has {scan_count} prior scan(s) on record (earliest: {first_seen}, latest: {last_seen})."
        ]
        for finding, count in term_counter.most_common(5):
            if count > 1:
                lines.append(f"Recurring finding across {count} scans: {finding}")

        return "\n".join(lines)

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        try:
            findings = json.loads(row["findings"])
            if not isinstance(findings, list):
                findings = []
        except (json.JSONDecodeError, TypeError, KeyError):
            findings = []
        return ScanRecord(
            id=int(row["id"]),
            target=str(row["target"]),
            command=str(row["command"]),
            timestamp=str(row["timestamp"]),
            findings_summary=str(row["summary"]),
            severity=str(row["severity"]),
            remediation_summary=str(row["remediation"]),
            raw_output_path=str(row["raw_output_path"]) if row["raw_output_path"] else "",
            findings=findings,
        )
