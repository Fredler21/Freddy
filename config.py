"""Configuration Module — loads and validates Freddy configuration."""

import os
import sys
from pathlib import Path

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    ENV_PATH = Path(__file__).parent / ".env"
    if ENV_PATH.exists():
        load_dotenv(ENV_PATH)
except ImportError:
    pass  # python-dotenv not installed, use only environment variables

# --- Claude API Configuration ---
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022").strip()
MAX_TOKENS = int(os.environ.get("ANTHROPIC_MAX_TOKENS", "4096"))

# --- Paths ---
BASE_DIR = Path(__file__).parent.absolute()
SYSTEM_PROMPT_PATH = BASE_DIR / "prompts" / "system_prompt.txt"


def validate_config() -> None:
    """Validate that required configuration is present. Exit with helpful message if not."""
    if not API_KEY:
        print(
            "\n[!] ERROR: ANTHROPIC_API_KEY environment variable is not set.\n"
            "\n    To use Freddy, set your Anthropic API key:\n"
            "\n      export ANTHROPIC_API_KEY='sk-ant-yourkey...'\n"
            "\n    Or create a .env file in the Freddy directory with:\n"
            "      ANTHROPIC_API_KEY=sk-ant-yourkey...\n"
            "\n    Get a key at: https://console.anthropic.com/\n"
        )
        sys.exit(1)

    if not SYSTEM_PROMPT_PATH.exists():
        print(f"\n[!] ERROR: System prompt not found at {SYSTEM_PROMPT_PATH}\n")
        sys.exit(1)


def get_config() -> dict:
    """Return the current configuration as a dict."""
    return {
        "api_key_set": bool(API_KEY),
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system_prompt_path": str(SYSTEM_PROMPT_PATH),
    }
