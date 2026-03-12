"""Analyze command — reads any file and sends it for AI analysis."""

from modules.file_loader import FileLoader
from modules.output_formatter import OutputFormatter
from ai_engine import analyze


def run_file_analysis(file_path: str, system_prompt: str) -> str:
    """
    Read a file and return AI analysis.
    
    Args:
        file_path: Path to the file to analyze
        system_prompt: System prompt for AI analysis
        
    Returns:
        AI analysis of the file contents
    """
    formatter = OutputFormatter()

    # Load the file
    content = FileLoader.load(file_path)

    if content is None:
        return f"[!] File not found: {file_path}"

    if content.startswith("[!]"):  # Error message from FileLoader
        return content

    if not content.strip():
        return f"[!] File is empty: {file_path}"

    # Send to AI for analysis
    return analyze(content, system_prompt)

        return f"[!] Could not read file: {e}"

    if not lines:
        return f"[!] File is empty: {file_path}"

    content = "".join(lines)
    return analyze(content, prompt)
