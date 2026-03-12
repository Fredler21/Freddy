from __future__ import annotations

"""Shared pre-AI intelligence pipeline for Freddy commands."""

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ai_engine import analyze
from modules.knowledge_engine import KnowledgeEngine, KnowledgeMatch
from modules.memory_engine import MemoryEngine
from modules.retrieval_formatter import format_knowledge_context, format_prior_history, format_rule_findings
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

    # Retrieve prior history and build correlation summary before analysis
    resolved_target = target or "local"
    prior_records = memory_engine.search_prior_findings(resolved_target)
    correlation = memory_engine.get_correlation_summary(resolved_target) if prior_records else ""
    history_context = format_prior_history(prior_records, correlation)

    # Persist raw tool output to data/raw/
    raw_output_path = _save_raw_output(raw_evidence, command_name, resolved_target)

    report = analyze(
        raw_evidence=raw_evidence,
        system_prompt=system_prompt,
        rule_findings=format_rule_findings(rule_findings),
        knowledge_context=format_knowledge_context(knowledge_matches),
        command_metadata={"command": command_name, "target": resolved_target, "query": query},
        task_instruction=task_instruction,
        prior_history=history_context,
    )

    record_id = memory_engine.save_scan_record(
        target=resolved_target,
        command=command_name,
        findings_summary=_extract_summary(report),
        severity=_extract_severity(report, rule_findings),
        remediation_summary=_extract_remediation(report),
        raw_output_path=raw_output_path,
        findings=_extract_findings(report),
    )

    return AnalysisResult(
        report=report,
        rule_findings=rule_findings,
        knowledge_matches=knowledge_matches,
        memory_record_id=record_id,
    )


def _save_raw_output(raw_evidence: str, command_name: str, target: str) -> str:
    """Write raw tool output to data/raw/ and return the file path string."""
    from config import DATA_RAW_DIR  # imported here to avoid circular import at module load

    try:
        DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
        safe_target = re.sub(r"[^\w.-]", "_", target)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = DATA_RAW_DIR / f"{command_name}_{safe_target}_{timestamp}.txt"
        output_path.write_text(raw_evidence, encoding="utf-8")
        return str(output_path)
    except OSError:
        return ""


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


def _extract_findings(report: str) -> list[str]:
    """Extract structured bullet-point findings from the AI report (max 20)."""
    findings: list[str] = []
    for line in report.splitlines():
        stripped = line.strip()
        is_bullet = stripped.startswith(("- ", "• ", "* ", "· "))
        is_numbered = len(stripped) > 2 and stripped[0].isdigit() and stripped[1] in ".):"
        if is_bullet or is_numbered:
            finding = re.sub(r"^[-•*·\d.):]+\s*", "", stripped).strip()
            if finding:
                findings.append(finding)
        if len(findings) >= 20:
            break
    return findings
