"""Analyze command — reads a file (logs, scan output) and sends it for AI analysis."""

import os
from ai_engine import analyze


def run_file_analysis(file_path: str, prompt: str) -> str:
    """Read a file and send its contents to Claude for security analysis."""

    # Resolve the real path to prevent symlink tricks
    real_path = os.path.realpath(file_path)

    if not os.path.exists(real_path):
        return f"[!] File not found: {file_path}"

    if not os.path.isfile(real_path):
        return f"[!] Not a regular file: {file_path}"

    # Check if the file is readable
    if not os.access(real_path, os.R_OK):
        return (
            f"[!] Permission denied: {file_path}\n"
            "    Try running Freddy with sudo."
        )

    try:
        with open(real_path, "r", errors="replace") as f:
            # Read last 500 lines to stay within token limits
            lines = f.readlines()[-500:]
    except OSError as e:
        return f"[!] Could not read file: {e}"

    if not lines:
        return f"[!] File is empty: {file_path}"

    content = "".join(lines)
    return analyze(content, prompt)
