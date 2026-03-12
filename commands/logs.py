"""Logs command — analyzes log files (alias for analyze, optimized for logs)."""

from commands.analyze import run_file_analysis
from modules.intelligence_pipeline import AnalysisResult


def run_logs(file_path: str, system_prompt: str) -> AnalysisResult:
    """
    Analyze a log file.
    
    This is an optimized alias for analyze specifically designed for log files.
    
    Args:
        file_path: Path to the log file
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of the log file
    """
    return run_file_analysis(file_path, system_prompt)
