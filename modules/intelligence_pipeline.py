from __future__ import annotations

"""Shared pre-AI intelligence pipeline for Freddy commands."""

from dataclasses import dataclass

from ai_engine import analyze
from modules.knowledge_engine import KnowledgeEngine, KnowledgeMatch
from modules.memory_engine import MemoryEngine
from modules.retrieval_formatter import format_knowledge_context, format_rule_findings
from modules.rule_engine import RuleEngine, RuleFinding


@dataclass(slots=True)
class AnalysisResult:
    report: str
    rule_findings: list[RuleFinding]
    knowledge_matches: list[KnowledgeMatch]
    memory_record_id: int | None

    @property
    def knowledge_used(self) -> bool:
        return bool(self.knowledge_matches)


def run_intelligence_analysis(
    *,
    raw_evidence: str,
    system_prompt: str,
    command_name: str,
    task_instruction: str,
    target: str | None = None,
) -> AnalysisResult:
    if not raw_evidence.strip():
        return AnalysisResult(
            report="[!] No evidence provided for analysis.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    rule_engine = RuleEngine()
    knowledge_engine = KnowledgeEngine()
    memory_engine = MemoryEngine()

    rule_findings = rule_engine.evaluate(raw_evidence)
    query = knowledge_engine.recommended_query(
        evidence=raw_evidence,
        command_name=command_name,
        target=target,
        rule_titles=[finding.title for finding in rule_findings],
    )
    knowledge_matches = knowledge_engine.query(query)

    report = analyze(
        raw_evidence=raw_evidence,
        system_prompt=system_prompt,
        rule_findings=format_rule_findings(rule_findings),
        knowledge_context=format_knowledge_context(knowledge_matches),
        command_metadata={"command": command_name, "target": target or "local", "query": query},
        task_instruction=task_instruction,
    )

    record_id = memory_engine.save_scan_record(
        target=target or "local",
        command=command_name,
        findings_summary=_extract_summary(report),
        severity=_extract_severity(report, rule_findings),
        remediation_summary=_extract_remediation(report),
    )

    return AnalysisResult(
        report=report,
        rule_findings=rule_findings,
        knowledge_matches=knowledge_matches,
        memory_record_id=record_id,
    )


def _extract_summary(report: str) -> str:
    lines = [line.strip() for line in report.splitlines() if line.strip()]
    return " ".join(lines[:3])[:500] if lines else "No summary available."


def _extract_severity(report: str, findings: list[RuleFinding]) -> str:
    report_upper = report.upper()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if level in report_upper:
            return level
    if findings:
        ordering = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return max(findings, key=lambda item: ordering.get(item.severity.upper(), 0)).severity.upper()
    return "INFO"


def _extract_remediation(report: str) -> str:
    lines = [line.strip() for line in report.splitlines() if line.strip()]
    remediation_lines = [line for line in lines if line.lower().startswith(("1.", "2.", "3.", "- "))]
    if remediation_lines:
        return " ".join(remediation_lines[:4])[:500]
    return "Review report remediation and hardening recommendations."
