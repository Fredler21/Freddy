"""Freddy AI Engine — connects to the Anthropic Claude API for security analysis."""

import sys
from anthropic import Anthropic, APIError, APIConnectionError
from config import API_KEY, MODEL, MAX_TOKENS, SYSTEM_PROMPT_PATH


def get_client() -> Anthropic:
    """Create and return an authenticated Anthropic client."""
    if not API_KEY:
        print(
            "\n[!] ANTHROPIC_API_KEY not set. Export it with:\n"
            "      export ANTHROPIC_API_KEY='sk-ant-...'\n"
        )
        sys.exit(1)
    return Anthropic(api_key=API_KEY)


def load_system_prompt() -> str:
    """Load the system prompt from disk."""
    try:
        with open(SYSTEM_PROMPT_PATH, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"\n[!] System prompt not found: {SYSTEM_PROMPT_PATH}\n")
        sys.exit(1)


def analyze(data: str, system_prompt: str) -> str:
    """Send tool output to Claude for security analysis and return the response."""
    if not data or not data.strip():
        return "[!] No data to analyze — the command produced no output."

    client = get_client()

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": data}],
        )
        return response.content[0].text

    except APIConnectionError:
        return (
            "[!] Could not connect to the Anthropic API.\n"
            "    Check your internet connection and try again."
        )
    except APIError as e:
        return f"[!] Anthropic API error: {e}"
