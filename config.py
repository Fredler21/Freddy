import os
import sys

# --- Claude API configuration ---
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = "claude-3-7-sonnet"
MAX_TOKENS = 2000

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SYSTEM_PROMPT_PATH = os.path.join(BASE_DIR, "prompts", "system_prompt.txt")


def validate_config():
    """Check that required configuration is present. Exit with a helpful message if not."""
    if not API_KEY:
        print(
            "\n[!] ERROR: ANTHROPIC_API_KEY environment variable is not set.\n"
            "\n"
            "    Set it with:\n"
            "      export ANTHROPIC_API_KEY='sk-ant-...'\n"
            "\n"
            "    Get a key at: https://console.anthropic.com/\n"
        )
        sys.exit(1)

    if not os.path.isfile(SYSTEM_PROMPT_PATH):
        print(f"\n[!] ERROR: System prompt not found at {SYSTEM_PROMPT_PATH}\n")
        sys.exit(1)
