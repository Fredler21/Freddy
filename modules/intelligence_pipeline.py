from __future__ import annotations

"""Shared pre-AI intelligence pipeline for Freddy commands."""

import re
from dataclasses import dataclass, field
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
    # New SOC-grade enrichment fields
    mitre_mappings: list = field(default_factory=list)
    timeline_events: list = field(default_factory=list)
    ioc_report: object = None
    correlation_findings: list = field(default_factory=list)
    posture_score: object = None
    learning_notes: list = field(default_factory=list)
    threat_intel_report: object = None

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

    # --- SOC-Grade Enrichment Layer ---

    # 1. MITRE ATT&CK Mapping
    from modules.mitre_mapper import MitreMapper, format_mitre_mappings
    mitre_mapper = MitreMapper()
    mitre_mappings = mitre_mapper.map_evidence(
        raw_evidence, rule_titles=[f.title for f in rule_findings]
    )

    # 2. IOC Extraction
    from modules.ioc_extractor import IOCExtractor, format_ioc_report
    ioc_extractor = IOCExtractor()
    ioc_report = ioc_extractor.extract(raw_evidence)

    # 3. Incident Timeline Reconstruction
    from modules.timeline_reconstructor import TimelineReconstructor, format_timeline
    timeline = TimelineReconstructor()
    timeline_events = timeline.build_timeline(raw_evidence)

    # 4. SIEM-Style Correlation
    from modules.siem_correlator import SIEMCorrelator, format_correlation_findings
    correlator = SIEMCorrelator()
    correlation_findings = correlator.correlate(
        raw_evidence,
        rule_findings=rule_findings,
        ioc_ips=ioc_report.ip_addresses,
        timeline_events=timeline_events,
        mitre_mappings=mitre_mappings,
    )

    # 5. Security Posture Scoring
    from modules.posture_scorer import PostureScorer
    scorer = PostureScorer()
    posture_score = scorer.score(
        rule_findings=rule_findings,
        mitre_mappings=mitre_mappings,
        ioc_count=ioc_report.total_iocs,
        correlation_findings=correlation_findings,
        raw_evidence=raw_evidence,
    )

    # 6. Security Mentor Learning Notes
    from modules.security_mentor import SecurityMentor
    mentor = SecurityMentor()
    learning_notes = mentor.generate_notes(
        rule_findings=rule_findings,
        mitre_mappings=mitre_mappings,
        raw_evidence=raw_evidence,
    )

    # --- Build enriched AI context ---
    enrichment_context = _build_enrichment_context(
        mitre_mappings=mitre_mappings,
        ioc_report=ioc_report,
        timeline_events=timeline_events,
        correlation_findings=correlation_findings,
        posture_score=posture_score,
    )

    # Retrieve prior history and build correlation summary before analysis
    resolved_target = target or "local"
    prior_records = memory_engine.search_prior_findings(resolved_target)
    correlation = memory_engine.get_correlation_summary(resolved_target) if prior_records else ""
    history_context = format_prior_history(prior_records, correlation)

    # Persist raw tool output to data/raw/
    raw_output_path = _save_raw_output(raw_evidence, command_name, resolved_target)

    # Enhanced task instruction with enrichment context
    enhanced_instruction = (
        f"{task_instruction}\n\n"
        f"ENRICHMENT ANALYSIS (pre-computed by Freddy SOC engine):\n{enrichment_context}"
    )

    report = analyze(
        raw_evidence=raw_evidence,
        system_prompt=system_prompt,
        rule_findings=format_rule_findings(rule_findings),
        knowledge_context=format_knowledge_context(knowledge_matches),
        command_metadata={"command": command_name, "target": resolved_target, "query": query},
        task_instruction=enhanced_instruction,
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

    # 7. Threat Intelligence (async-safe, runs after main analysis to avoid blocking)
    threat_intel_report = None
    if ioc_report.ip_addresses or ioc_report.domains:
        try:
            from modules.threat_intel import ThreatIntelligence
            ti = ThreatIntelligence()
            threat_intel_report = ti.check_indicators(
                ips=ioc_report.ip_addresses[:5],
                domains=ioc_report.domains[:5],
            )
        except Exception:
            pass  # Threat intel is best-effort, do not fail the analysis

    return AnalysisResult(
        report=report,
        rule_findings=rule_findings,
        knowledge_matches=knowledge_matches,
        memory_record_id=record_id,
        mitre_mappings=mitre_mappings,
        timeline_events=timeline_events,
        ioc_report=ioc_report,
        correlation_findings=correlation_findings,
        posture_score=posture_score,
        learning_notes=learning_notes,
        threat_intel_report=threat_intel_report,
    )


def _build_enrichment_context(
    *,
    mitre_mappings: list,
    ioc_report: object,
    timeline_events: list,
    correlation_findings: list,
    posture_score: object,
) -> str:
    """Build a combined enrichment context string for AI prompt injection."""
    from modules.mitre_mapper import format_mitre_mappings
    from modules.ioc_extractor import format_ioc_report
    from modules.timeline_reconstructor import format_timeline
    from modules.siem_correlator import format_correlation_findings
    from modules.posture_scorer import format_posture_score

    sections: list[str] = []

    mitre_text = format_mitre_mappings(mitre_mappings)
    if "No MITRE" not in mitre_text:
        sections.append(f"MITRE ATT&CK MAPPINGS:\n{mitre_text}")

    ioc_text = format_ioc_report(ioc_report)
    if "No Indicators" not in ioc_text:
        sections.append(f"INDICATORS OF COMPROMISE:\n{ioc_text}")

    timeline_text = format_timeline(timeline_events)
    if "No security" not in timeline_text and "No timeline" not in timeline_text:
        sections.append(f"INCIDENT TIMELINE:\n{timeline_text}")

    corr_text = format_correlation_findings(correlation_findings)
    if "No cross-source" not in corr_text:
        sections.append(f"SIEM CORRELATION FINDINGS:\n{corr_text}")

    if posture_score:
        score_val = getattr(posture_score, "score", 100)
        grade = getattr(posture_score, "grade", "?")
        sections.append(f"SECURITY POSTURE SCORE: {score_val}/100 (Grade: {grade})")

    return "\n\n".join(sections) if sections else "No additional enrichment data."


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
