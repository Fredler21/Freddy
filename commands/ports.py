"""Ports command — lists open ports/services and sends them for AI analysis."""

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.platform_support import is_linux_like, linux_only_message
from modules.tool_runner import ToolRunner


def run_ports(system_prompt: str) -> AnalysisResult:
    """
    List open ports/services with ss and return AI analysis.
    
    Args:
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of open ports
    """
    if not is_linux_like():
        return AnalysisResult(
            report=linux_only_message("ports"),
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    if ToolRunner.is_installed("ss"):
        stdout, stderr, returncode = ToolRunner.run(
            ["ss", "-tulpn"],
            timeout=30,
        )
    elif ToolRunner.is_installed("netstat"):
        stdout, stderr, returncode = ToolRunner.run(
            ["netstat", "-tulpn"],
            timeout=30,
        )
    else:
        return AnalysisResult(
            report="[!] Neither 'ss' nor 'netstat' found. Install iproute2 or net-tools.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    output = stdout
    if returncode != 0 and stderr:
        output += f"\n[stderr]\n{stderr}"

    if not output.strip():
        return AnalysisResult(
            report="[!] No output from port listing. You may need elevated privileges for local port enumeration.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=output,
        system_prompt=system_prompt,
        command_name="ports",
        target="local",
        task_instruction="Analyze these local listening ports for defensive risk, service exposure, and hardening priorities.",
    )
