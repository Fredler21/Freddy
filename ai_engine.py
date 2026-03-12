"""AI Engine Module — connects to Anthropic Claude API for security analysis."""

import sys
from anthropic import Anthropic, APIError, APIConnectionError
from config import API_KEY, MODEL, MAX_TOKENS, SYSTEM_PROMPT_PATH


def get_client() -> Anthropic:
    """Create and return an authenticated Anthropic client."""
    if not API_KEY:
        print(
            "\n[!] ANTHROPIC_API_KEY not set.\n"
            "    Export it with: export ANTHROPIC_API_KEY='sk-ant-...'\n"
        )
        sys.exit(1)
    return Anthropic(api_key=API_KEY)


def load_system_prompt() -> str:
    """
    Load the system prompt from disk.
    
    Returns:
        System prompt text
    """
    try:
        with open(SYSTEM_PROMPT_PATH, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"\n[!] System prompt not found: {SYSTEM_PROMPT_PATH}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error loading system prompt: {e}\n")
        sys.exit(1)


def trim_input(data: str, max_chars: int = 50000) -> tuple[str, bool]:
    """
    Trim very large inputs to fit API limits and warn user.
    
    Args:
        data: The input data
        max_chars: Maximum characters to keep
        
    Returns:
        Tuple of (trimmed_data, was_trimmed)
    """
    if len(data) > max_chars:
        return data[:max_chars] + "\n\n[...Output truncated for API limit...]", True
    return data, False


def analyze(data: str, system_prompt: str) -> str:
    """
    Send tool output to Claude for security analysis.
    
    Args:
        data: The tool output/data to analyze
        system_prompt: The system prompt defining Freddy's behavior
        
    Returns:
        The AI analysis response
    """
    if not data or not data.strip():
        return "[!] No data to analyze — the command produced no output."

    # Trim if needed
    trimmed_data, was_trimmed = trim_input(data)
    if was_trimmed:
        print("[⚠] Input was truncated to fit API limits")

    client = get_client()

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": trimmed_data}],
        )
        return response.content[0].text

    except APIConnectionError:
        return (
            "[!] Could not connect to the Anthropic API.\n"
            "    Check your internet connection and try again."
        )
    except APIError as e:
        return f"[!] API Error: {str(e)}"
    except Exception as e:
        return f"[!] Unexpected error: {str(e)}"

        return f"[!] Anthropic API error: {e}"
