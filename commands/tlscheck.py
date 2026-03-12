"""TLS check command — analyzes TLS/SSL certificate and configuration."""

from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis
from modules.output_formatter import OutputFormatter
from modules.platform_support import install_hint
from modules.tool_runner import ToolRunner


def run_tlscheck(target: str, system_prompt: str) -> AnalysisResult:
    """
    Check TLS/SSL certificate and configuration.
    
    Args:
        target: Target host (e.g., example.com, example.com:8443)
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of TLS/SSL configuration
    """
    if not ToolRunner.is_installed("openssl"):
        return AnalysisResult(
            report=f"[!] OpenSSL is not installed. {install_hint('openssl')}",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    formatter = OutputFormatter()

    if ":" not in target:
        target = f"{target}:443"

    host, port = target.rsplit(":", 1)
    openssl_path = ToolRunner.resolve_tool("openssl") or "openssl"

    formatter.print_info(f"Checking TLS certificate for {target}...")

    stdout, stderr, _ = ToolRunner.run(
        [openssl_path, "s_client", "-connect", f"{host}:{port}", "-servername", host],
        timeout=30,
    )

    output = stdout if stdout.strip() else ""
    if stderr:
        output = f"{output}\n{stderr}".strip()

    if not output.strip():
        return AnalysisResult(
            report="[!] No TLS certificate data obtained. Check that the target is reachable on the requested port.",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=output,
        system_prompt=system_prompt,
        command_name="tlscheck",
        target=target,
        task_instruction="Analyze this TLS evidence for transport security weaknesses, certificate issues, and hardening opportunities.",
    )
