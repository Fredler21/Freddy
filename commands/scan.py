"""Scan command — runs Nmap service detection against a target."""

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.platform_support import install_hint
from modules.tool_runner import ToolRunner


def run_scan(target: str, system_prompt: str) -> AnalysisResult:
    """
    Run an Nmap service version scan on the target and return AI analysis.
    
    Args:
        target: Target host or IP address
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of the scan results
    """
    if not ToolRunner.is_installed("nmap"):
        return AnalysisResult(
            report=f"[!] Nmap is not installed. {install_hint('nmap')}",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    stdout, stderr, returncode = ToolRunner.run(
        ToolRunner.build_command("nmap", "-sV", target),
        timeout=300,
    )

    output = stdout
    if returncode != 0 and stderr:
        output += f"\n[stderr]\n{stderr}"

    if not output.strip():
        return AnalysisResult(
            report="[!] Nmap produced no output. Check that the target is reachable and spelled correctly.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=output,
        system_prompt=system_prompt,
        command_name="scan",
        target=target,
        task_instruction="Analyze this scan output as a defensive cybersecurity analyst. Prioritize exposed services, likely risks, and remediation steps.",
    )
