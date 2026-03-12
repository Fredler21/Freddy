"""Analyze command — reads any file and sends it for AI analysis."""

from modules.file_loader import FileLoader
from modules.intelligence_pipeline import AnalysisResult, run_intelligence_analysis


def run_file_analysis(file_path: str, system_prompt: str) -> AnalysisResult:
    """
    Read a file and return AI analysis.
    
    Args:
        file_path: Path to the file to analyze
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of the file contents
    """
    content = FileLoader.load(file_path)

    if content is None:
        return AnalysisResult(
            report=f"[!] File not found: {file_path}",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    if content.startswith("[!]"):  # Error message from FileLoader
        return AnalysisResult(
            report=content,
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    if not content.strip():
        return AnalysisResult(
            report=f"[!] File is empty: {file_path}",
            rule_findings=[],
            knowledge_matches=[],
            memory_record_id=None,
        )

    return run_intelligence_analysis(
        raw_evidence=content,
        system_prompt=system_prompt,
        command_name="analyze",
        target=file_path,
        task_instruction="Analyze this security-relevant file, classify findings, and provide precise remediation and hardening guidance.",
    )
