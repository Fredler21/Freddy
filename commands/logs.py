import os
from ai_engine import analyze

ALLOWED_LOG_DIRS = ["/var/log"]


def _is_safe_path(path: str) -> bool:
    """Ensure the log file is under an allowed directory."""
    real = os.path.realpath(path)
    return any(real.startswith(d) for d in ALLOWED_LOG_DIRS)


def run_log_analysis(log_path: str, prompt: str) -> str:
    """Read a log file and send it to Claude for security analysis."""
    if not _is_safe_path(log_path):
        return f"Error: log path must be under {ALLOWED_LOG_DIRS}"

    if not os.path.isfile(log_path):
        return f"Error: file not found — {log_path}"

    with open(log_path, "r", errors="replace") as f:
        # Read last 500 lines to stay within token limits
        lines = f.readlines()[-500:]

    content = "".join(lines)
    return analyze(content, prompt)
