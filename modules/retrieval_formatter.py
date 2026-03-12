from __future__ import annotations

"""Prompt and terminal formatting helpers for Freddy intelligence features."""

from typing import Iterable

from modules.knowledge_engine import KnowledgeMatch
from modules.rule_engine import RuleFinding
from modules.memory_engine import ScanRecord


def format_rule_findings(findings: Iterable[RuleFinding]) -> str:
    serialized = []
    for finding in findings:
        serialized.append(
            "\n".join(
                [
                    f"Title: {finding.title}",
                    f"Severity: {finding.severity}",
                    f"Confidence: {finding.confidence}",
                    f"Rationale: {finding.rationale}",
                    f"Inspect: {finding.recommended_inspection_area}",
                ]
            )
        )
    return "\n\n".join(serialized) if serialized else "No deterministic rule findings generated."


def format_knowledge_context(matches: Iterable[KnowledgeMatch]) -> str:
    rendered = []
    for match in matches:
        rendered.append(
            f"[{match.category.upper()}] {match.title} ({match.source}, score={match.score:.2f})\n{match.document}"
        )
    return "\n\n".join(rendered) if rendered else "No retrieved knowledge context available."


def format_history(records: Iterable[ScanRecord]) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for record in records:
        rows.append(
            (
                record.timestamp.replace("T", " ")[:19],
                record.target,
                record.command,
                record.severity,
            )
        )
    return rows


def format_prior_history(records: Iterable[ScanRecord], correlation_summary: str = "") -> str:
    """Format prior scan records for inclusion in the AI analysis prompt."""
    record_list = list(records)[:5]
    if not record_list:
        return ""
    lines: list[str] = []
    if correlation_summary:
        lines.append(correlation_summary)
    for record in record_list:
        lines.append(
            f"[{record.timestamp[:10]}] {record.command} → Severity: {record.severity}\n"
            f"Summary: {record.findings_summary}\n"
            f"Remediation: {record.remediation_summary}"
        )
    return "\n\n".join(lines)
